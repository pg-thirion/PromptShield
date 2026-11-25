# Threat model

User prompts, retrieved documents, tool output and generated responses are untrusted. Service identity, provenance, server policy and protected marker configuration must remain in the trusted integration boundary. The browser workbench is an educational client, not an enforcement boundary.

| Threat | Implemented control | Residual risk |
| --- | --- | --- |
| Direct or indirect injection | Deterministic rules, review and block decisions | Semantic paraphrases, encodings and multilingual text may evade detection |
| Sensitive data exposure | Pattern recognition, checksums, exact protected canaries, strict policy | Unstructured personal data, novel credentials, split or paraphrased secrets |
| Unauthorised API use | High-entropy bearer digests, endpoint scopes, server-owned policy | Compromised credentials, rotation and revocation depend on deployment |
| Configuration tampering | Reject client-supplied policy and protected markers | Trusted operators and integration code remain security-critical |
| Untrusted content rendering | DOM textContent, restrictive CSP, no external script | Browser extensions and compromised device are out of scope |
| Resource abuse | Size, connection, request, concurrency and per-key limits | Distributed abuse, upstream proxy limits, independent load tests outstanding |
| Sensitive logging | Allowlisted metadata events only | Reverse proxy, provider, infrastructure and observability configuration need review |
| Integration bypass | Guarded text-only provider helper, fail-closed decisions | Direct provider access or misconfigured clients bypass the control |

## Trust and release boundaries

The inspection service is not a model firewall capable of understanding all natural language. Never allow model output to directly authorise a privileged action. Use least-privilege tools, explicit user authorisation, typed structured output validation, separate DLP controls and human review. Configure protected canaries in trusted infrastructure only. Never publish them or use real customer records as demo fixtures.

API clients are machine identities, not end-user identities. Use separate credentials and applications for distinct trust boundaries; shared-process policies and limits do not provide full multi-tenant isolation. Store configuration and secrets using a secret manager. Test incident handling, rotation, load, availability and restoration before deployment.
