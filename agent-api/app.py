import os
import re
import time
from flask import Flask, request, jsonify
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

PROMPT_VERSION = os.environ.get('PROMPT_VERSION', 'v1.0.0')

# ─── Metrics ─────────────────────────────────────────────────────────────────

# Total requests — now includes `rejected`, `reason`, and `http_status` labels
# so alert rules and dashboards can slice by outcome without a second metric join.
# Cardinality: ~2 routes × 2 rejected × 5 reasons × 3 status codes = ~60 series. Fine.
REQUEST_COUNT = Counter(
    'agent_requests_total',
    'Total requests to the agent API, labelled by outcome',
    ['prompt_version', 'route', 'rejected', 'reason', 'http_status']
)

# End-to-end latency histogram. Kept on (prompt_version, route) only — adding
# rejected/reason here would multiply the bucket series count by ~10x for little gain.
REQUEST_LATENCY = Histogram(
    'agent_request_latency_seconds',
    'Request latency in seconds',
    ['prompt_version', 'route'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)


# Input message character-length distribution. Abnormally large messages
# are a leading indicator of prompt-stuffing attacks before they show up in rejection
# rates. Also helps right-size any future LLM token budget.
MESSAGE_LENGTH = Histogram(
    'agent_message_length_chars',
    'Character length of incoming messages',
    ['prompt_version'],
    buckets=[10, 50, 100, 200, 500, 1000, 2000, 5000]
)

# Build-info gauge — always 1, exposes prompt_version as a label.
# Grafana can plot this as a step function to annotate version-change events on
# other graphs, without needing to join on a timestamp field.
BUILD_INFO = Gauge(
    'agent_build_info',
    'Running agent version metadata (value is always 1)',
    ['prompt_version']
)
BUILD_INFO.labels(prompt_version=PROMPT_VERSION).set(1)

# ─── Rejection patterns ────────────────────────────────────────────────────────

REJECTION_PATTERNS = {
    'prompt_injection': [
        r'ignore\s+(all\s+)?(previous\s+)?instructions',
        r'system\s+prompt',
        r'disregard\s+(all\s+)?(previous\s+)?',
        r'forget\s+(all\s+)?(previous\s+)?instructions',
        r'new\s+instructions',
        r'override\s+(all\s+)?rules',
        r'jailbreak',
        r'bypass\s+(safety|filter|restriction)',
    ],
    'secrets_request': [
        r'password',
        r'api[\s_-]?key',
        r'secret[\s_-]?key',
        r'access[\s_-]?token',
        r'private[\s_-]?key',
        r'credentials',
        r'auth[\s_-]?token',
        r'bearer[\s_-]?token',
    ],
    'dangerous_action': [
        r'restart\s+prod',
        r'delete\s+(the\s+)?database',
        r'drop\s+table',
        r'rm\s+-rf',
        r'shutdown\s+server',
        r'execute\s+command',
        r'run\s+as\s+root',
        r'sudo\s+',
        r'format\s+(hard\s+)?drive',
        r'wipe\s+(all\s+)?data',
    ],
}


# ─── Business logic ───────────────────────────────────────────────────────────

def classify_rejection(message: str) -> tuple[bool, str | None]:
    """
    Classify whether a message should be rejected and return the reason.
    Returns (rejected, reason) tuple.
    """
    message_lower = message.lower()

    for reason, patterns in REJECTION_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, message_lower):
                return True, reason

    return False, None


def generate_response(message: str) -> str:
    """Generate a simple response for accepted messages."""
    responses = [
        f"I understand you're asking about: {message[:50]}...",
        "That's an interesting question. Let me help you with that.",
        "I'd be happy to assist with your request.",
        "Thank you for your question. Here's what I can tell you.",
    ]
    return responses[hash(message) % len(responses)]


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/ask', methods=['POST'])
def ask():
    """
    Main endpoint for asking the agent.
    Accepts JSON with 'message' field.
    Returns rejection status, reason, prompt version, and answer.
    """
    start_time = time.time()

    # Defaults — overwritten below before the finally block records them.
    rejected_str = "false"
    reason_str = ""
    http_status = "200"

    try:
        data = request.get_json()
        if not data or 'message' not in data:
            rejected_str = "true"
            reason_str = "invalid_request"
            http_status = "400"
            return jsonify({
                'error': 'Missing required field: message',
                'rejected': True,
                'reason': 'invalid_request',
                'prompt_version': PROMPT_VERSION,
                'answer': None
            }), 400

        message = data['message']

        # Observe message length before classification. Done regardless of outcome
        # so we have the full distribution including messages that get rejected.
        MESSAGE_LENGTH.labels(prompt_version=PROMPT_VERSION).observe(len(message))
        
        rejected, reason = classify_rejection(message)

        if rejected:
            rejected_str = "true"
            reason_str = reason or ""
            response_body = {
                'rejected': True,
                'reason': reason,
                'prompt_version': PROMPT_VERSION,
                'answer': f"I cannot process this request due to: {reason}"
            }
        else:
            response_body = {
                'rejected': False,
                'reason': None,
                'prompt_version': PROMPT_VERSION,
                'answer': generate_response(message)
            }

        return jsonify(response_body), 200

    except Exception:
        # Catch-all so unhandled errors are still counted in metrics before
        # Flask's default 500 handler takes over.
        http_status = "500"
        raise

    finally:
        # Record latency and the full-outcome counter in finally so they always
        # fire regardless of which return/raise path was taken above.
        REQUEST_LATENCY.labels(prompt_version=PROMPT_VERSION, route='/ask').observe(
            time.time() - start_time
        )
        REQUEST_COUNT.labels(
            prompt_version=PROMPT_VERSION,
            route='/ask',
            rejected=rejected_str,
            reason=reason_str,
            http_status=http_status
        ).inc()


@app.route('/healthz', methods=['GET'])
def healthz():
    """Health check endpoint. Not counted as a rejection, no latency histogram."""
    REQUEST_COUNT.labels(
        prompt_version=PROMPT_VERSION,
        route='/healthz',
        rejected='false',
        reason='',
        http_status='200'
    ).inc()
    return jsonify({'status': 'healthy', 'prompt_version': PROMPT_VERSION}), 200


@app.route('/metrics', methods=['GET'])
def metrics():
    """Prometheus metrics endpoint."""
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
