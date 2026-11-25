# Deployment and release gates

## Local development
Run npm start with no environment variables. The browser is available on loopback, and the service API returns 503 until credentials are configured.

## Production topology
Run the container behind a trusted TLS-terminating reverse proxy or private load balancer. Restrict network ingress to that proxy. Set PS_ALLOWED_HOSTS to the exact proxy-forwarded Host values, PS_BEHIND_TLS_PROXY=true and PS_CLIENTS_JSON to scoped SHA-256 credential digests. Use a secret manager, not a checked-in environment file. PS_POLICY defaults to strict. Rotate by deploying both old and new distinct credential IDs, migrating the consumer, then removing the old digest and restarting.

Build and run:
```sh
docker build -t promptshield:local .
# deployment.env is a protected local file, not committed
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 256m --cpus 1 --env-file deployment.env \
  -p 127.0.0.1:3000:3000 promptshield:local
```

Configure the reverse proxy for HTTPS, HSTS, request and connection limits, header/body deadlines and access logging without request bodies, query secrets or Authorization headers. No trust is placed in forwarded client-IP headers. Do not publish the API's port directly. Run vulnerability scans of the chosen base image and pin a reviewed digest in release infrastructure. Configuration is loaded at startup. Rate limits and audit events are per replica; use centrally enforced quotas and log shipping before scaling horizontally. Protect the metadata logs, apply retention and monitor 401, 403, 429 and 5xx counts. Health endpoint GET /healthz exposes only service status and API-enabled state.

## Acceptance gates
- Automated engine, HTTP API and gateway regression suite passes.
- Browser workflow and accessibility verified on supported devices and browsers.
- Container build, health, non-root runtime and vulnerability scan verified in the deployment environment.
- Independent labelled evaluation with false positives, false negatives, per-category recall and representative English/Afrikaans datasets.
- Load and soak tests against deployment-specific latency/availability targets; validated request limits, failure handling and alerting.
- Independent security review, credential rotation drill, privacy impact assessment and approval for intended data classes.
- Integration ensures every model input/output passes inspection and never falls back to uninspected content.

These gates distinguish a hardened release candidate from a production-approved service. Do not treat repository CI alone as approval.
