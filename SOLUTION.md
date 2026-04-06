# Solution Documentation: DevOps + AIOps Take-Home Test

## Task 1

**File:** `.github/workflows/ci.yml`
### Design Decisions

#### Pipeline Structure
- **CI Stage** (runs on every PR and push to master): Builds Docker images and runs eval-runner as quality gate
- **Deploy Stage** (runs only on master after CI passes): Updates image tag in deployment manifest with commit SHA for traceability
  
### Technical Details

**CI Job Steps:**
- Build `agent-api:ci` Docker image
- Build `eval-runner:ci` Docker image
- Start agent-api container on isolated network
- Run eval-runner against the API (will fail if thresholds not met)
- Cleanup containers and network (always runs, even on failure)

**Deploy Job Steps:**
- Only runs on `refs/heads/master` with `push` event
- Stamps manifest: updates `image_tag` field to full commit SHA
- Records deployment history as comments (timestamp, short SHA, actor)
- Uses Python script for reliable multi-line history appending (sed is fragile for this)
- Commits updated manifest with `[skip ci]` tag to prevent re-triggering CI


## Task 2

**File:** `prometheus/alert-rules.yml`

### Implementation Summary
Designed 7 alert rules across three groups: availability, quality, and performance.

### Alert Rules

#### Group 1: Availability (agent-api-availability)

**1. AgentAPIDown** (Critical): API is unreachable by Prometheus scraper. 1-minute window prevents noise from rolling restarts; 1 minute is the minimum meaningful detection window.

**2. AgentAPINoTraffic** (Warning):  Dead-man's switch catching zero traffic to /ask for 3+ consecutive minutes. Normal baseline is ~2 req/s. API could be up (scrape passes) but receive zero traffic.

#### Group 2: Quality (agent-api-quality)

**3. HighRejectionRate** (Warning): Synthetic traffic baseline is ~15% rejections. 35% is 2.3× baseline headroom. 5-minute window filters out brief adversarial bursts.

**4. RejectionRateSpike** (Critical): Relative alert using rate ratio. At 15% baseline, 3× = 45%, a clear anomaly. Relative thresholds adapt to actual traffic. 2-minute for prevents false positives from a single bad minute.

**5. SafetyNetPassThroughTooHigh** (Critical): Pass-through >95% means <5% rejection rate. Safety classifier may be broken, allowing potentially harmful requests. This threshold is set very high because in normal conditions, most user requests are expected to be pass.
  
#### Group 3: Performance (agent-api-performance)

**6. HighRequestLatency** (Warning): Normal request has p95 < 50ms. >1s sustained is abnormal. Alert on p95 (not p50) to avoid noise from occasional slow requests.

**7. HighErrorRate** (Warning): >5% error rate suggests broken client or API regression. 400s are somewhat expected; >5% is abnormal.
## Task 3

**File:** `agent-api/app.py`

### Metrics Implemented

#### 1. REQUEST_COUNT (Counter)
```
agent_requests_total
  labels: prompt_version, route, rejected, reason, http_status
```
- **Purpose:** Total request count broken down by all outcome dimensions
- **Design:** Multi-label counter avoids metric explosion.
- **Why:** Enables slicing by any dimension without joins. Alert rules and dashboards use this single metric for rejection rate, and request rate.

#### 2. REQUEST_LATENCY (Histogram)
```
agent_request_latency_seconds
  labels: prompt_version, route
  buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
```
- **Purpose:** End-to-end latency distribution for /ask endpoint
- **Design:** Buckets chosen for regex-based classifier (5ms–5s range).
- **Why:** Operators need p50/p95 to distinguish median vs. tail latency. Alert on p95 > 1s to catch sustained slowness

#### 3. MESSAGE_LENGTH (Histogram)
```
agent_message_length_chars
  labels: prompt_version
  buckets: [10, 50, 100, 200, 500, 1000, 2000, 5000]
```
- **Purpose:** Incoming message length distribution
- **Design:** Character-based buckets to capture prompt-stuffing attack patterns
- **Why:** Leading indicator of attacks before they show in rejection metrics. Abnormally large messages hint at token-budget or regex-bypass attempts

####4. BUILD_INFO (Gauge)
```
agent_build_info
  labels: prompt_version
  value: 1 (always)
```
- **Purpose:** Running version metadata, value always 1(For real world usecase, need to update it with the commit-sha)
- **Design:** Grafana can plot this as a step function to annotate version-change events on dashboards
- **Why:** Correlates metric anomalies with deployments.


## Task 4

**File:** `grafana/dashboards/agent-monitoring.json`

### Panels Implemented

#### 1. Request Rate
- **Purpose:** Total traffic volume
- **Use:** Detect traffic drops (no traffic alert) or traffic spikes (possible attack)

#### 2. Rejection Rate 
- **Purpose:** Rejection rate over time
- **Use:** Spot gradual drift or sudden spikes (triggers HighRejectionRate or RejectionRateSpike alerts)

#### 3. Rejections by Reason 
- **Purpose:** Breakdown of rejections by category (prompt_injection, secrets_request, dangerous_action)
- **Use:** Incident triage (e.g., spike in prompt_injection suggests targeted attack; spike in secrets_request suggests data exfiltration attempt)

#### 4. Request Latency p50 & p95
- **Purpose:** Latency distribution percentiles
- **Use:** Operators see if slowness is widespread (p50 High) or tail-latency issue (p95 High, p50 Normal)

## Task 5
**File:** `docs/incident-response.md` 
- All detail in the file above.

---

## Future Improvements

### CI/CD Enhancements
- **Image Tagging and Registry Push**: Tag images with commit SHA and push to container registry.
- **Automated Rollbacks**: Enable rollbacks triggered by metric thresholds or health checks to reduce deployment downtime.

### Monitoring and Metrics Expansion
- **User Request Tracking**: Track user requests with sender IDs to monitor patterns and detect anomalies.
- **Sub-process Monitoring**: Add latency and token usage metrics per AI agent step for bottleneck identification.
- **Tool Usage Tracking**: Monitor tool usage per request, including frequency and success rates, for behavior analysis.
- **User Feedback Integration**: Collect user feedback metrics for satisfaction and feature improvement insights.

