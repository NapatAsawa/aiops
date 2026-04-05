# Incident Response Runbook: Spike in Agent Rejection Rate

## 1. Initial Triage and Assessment

1. **Acknowledge the Alert:** Ensure the alert is claimed in the alerting system so the team knows it's being investigated.
2. **Review the Alert Details:** Look for the specific label and metric values to define the scope.
   - `HighRejectionRate`: Rejection rate is > 35% over a sustained 5-minute period.
   - `RejectionRateSpike`: The 1-minute rejection rate is suddenly 3x the 30-minute rolling average.
3. **Check the Dashboard:** Navigate to the **"Agent API Monitoring"** Grafana Dashboard.
   - **Review "Request Rate":** Is the total traffic volume normal? A spike in rejection paired with a massive spike in overall traffic often indicates a bot/adversarial attack.
   - **Review "Rejections by Reason":** Identify which reason (e.g. `dangerous_action`, `prompt_injection`, `secrets_request`) is triggering the spike.
   - **Review Prompt Version:** Identify which prompt version is triggering the spike. Is it the recently updated version?

## 2. Investigation Steps with Specific Log Queries

**1. General search for rejected requests**
*Start by finding all requests that were rejected to observe the raw prompts.*
```logql
# Example
rate(agent_requests_total{route="/ask", rejected="true"}[5m])
```

**2. Filter logs by a specific rejection reason**
*If the dashboard shows a massive spike in `prompt_injection` or `dangerous_action`, filter logs to see exactly what triggered that reason.*
```logql
# Example
rate(agent_requests_total{
  route="/ask",
  rejected="true",
  reason="prompt_injection"
}[5m])
```

**3. Filter logs by a specific prompt version**
*If the dashboard shows a massive spike in specific prompt version, filter logs to see exactly what triggered that version.*
```logql
# Example
rate(agent_requests_total{
  route="/ask",
  rejected="true",
  prompt_version="v1.0.0"
}[5m])
```
 
## 3. Decision Framework for Mitigation vs. Escalation

| Scenario | Potential Root Cause | Action / Mitigation |
| :--- | :--- | :--- |
| **Spike tracks exactly with a new Prompt Deployment (`prompt_version` changed)** | Regressive update to the agent's prompt or ruleset making it overly sensitive. | **Mitigate:** Immediately roll back to the previously stable `prompt_version`. Notify the AI team during business hours. |
| **Spike in Rejections + Massive Overall Traffic Spike** | Adversarial attack, scraping, or bot net sending malicious prompts. | **Mitigate/Escalate:** Do not roll back. Implement rate-limiting or WAF rules for offending IPs if system stability is at risk. Escalate to Security/Platform. |
| **Rejections are heavily skewed to a single `reason` and normal traffic volume** | Upstream model change, or user behavior is legitimately shifting (e.g., a viral trend triggering a false positive safety rule). | **Escalate:** Inform the AI Team (On-call). The safety guardrail may need hotfixing. Inform customer support of potential false-positive blocks. |

## 4. Post-Incident Actions   
1. **Resolve the Incident:** Close the alert in the incident management system.
2. **Leave handover notes:** If mitigated via a rollback, document the broken `prompt_version` or failed rule in the shift-handover log so the daytime team does not inadvertently redeploy it.
3. **Conduct an Incident Review**: What Went Well, What Went Wrong, and What Can Be Improved.
