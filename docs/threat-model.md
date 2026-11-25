# Threat model

## Assets and trust boundaries
User text, retrieved documents, tool output and generated responses are untrusted. System policy, protected marker configuration, identity and permissions belong to the trusted integrating application. The inspection engine is deterministic; no untrusted content is executed. Browser input stays in memory; local API responses are not logged by the application.

## Threats and controls
| Threat | Implemented control | Residual risk |
| --- | --- | --- |
| Direct or indirect instruction manipulation | Explicit pattern rules, source classification, hold/block | Paraphrasing, multilingual text and encoded attacks can bypass patterns |
| Credential and personal information leakage | Recognised patterns, checksum validation, output markers, span redaction | Unstructured information, novel token formats, false positives |
| Privileged instruction disclosure | Extraction rules and exact output canary detection | Paraphrased or transformed content is not reliably detected |
| Untrusted content rendering | DOM textContent, restrictive CSP, no HTML interpolation | Browser extensions and compromised host remain out of scope |
| Resource abuse | Length limits and bounded local requests | No production concurrency controls or authentication |
| Policy bypass by integration | Distinct decisions and no forwardable text for block/review | Client-side checks are bypassable; server enforcement is required |

## Policy
High-severity injection findings block input. Suspicious instruction findings require review. Recognised sensitive input is redacted. High-severity sensitive output blocks, and lower-severity output is redacted. Allow means no configured actionable rule matched, not that the text is safe.

## Deployment assumptions
Local educational use. Do not submit production secrets or real customer data. Do not use as the sole defence. A production design needs authenticated service identities, per-tool authorisation, least privilege, strict structured output validation, independent DLP, human approval and auditable metadata without storing sensitive payloads.

Relevant reading: OWASP Top 10 for LLM Applications (prompt injection and sensitive information disclosure), https://genai.owasp.org/llm-top-10/ . This project does not claim certification or complete coverage.
