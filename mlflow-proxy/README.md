# MLflow proxy

This directory contains a simple FastAPI reverse proxy for MLflow.

## Behavior

- If the incoming Keycloak access token contains the `mlflow-admins` group, the proxy forwards the request to MLflow unchanged.
- If the user is not an admin, the proxy blocks:
  - MLflow UI access under `/oidc/ui`
  - experiment creation
  - experiment updates (name / description-related metadata)
  - experiment deletion
  - experiment tag updates
  - all permission-management endpoints under `/api/2.0/mlflow/permissions/*`

All other requests are forwarded to the configured MLflow upstream.

Blocked API requests return MLflow-style JSON `403` responses (`error_code` + `message`), which gives the existing frontend a chance to surface the error inside the current UI flow.

Blocked UI requests under `/oidc/ui` return the normal MLflow HTML shell with an injected full-screen "Access denied" overlay, so the user stays inside the MLflow page instead of being sent to a separate custom page.

## Token lookup

The proxy checks these headers in order and uses the first one that exists:

1. `Authorization: Bearer <token>`
2. `X-Forwarded-Access-Token`
3. `X-Auth-Request-Access-Token`

The JWT payload is decoded locally and the `groups` claim is checked for `mlflow-admins`.

## Service account passthrough

If `MLFLOW_TRACKING_USERNAME` and `MLFLOW_TRACKING_PASSWORD` are set, requests using
`Authorization: Basic ...` with matching credentials bypass the non-admin restrictions.
This is intended for MLflow service-account clients.

## Run with Docker Compose

```bash
cd /home/energyguard/mlflow-oidc/mlflow-tracking-server-docker/mlflow-proxy
docker compose up -d --build
```

The compose file attaches the proxy to the same external Docker network as `mlflow-oidc`:

- network: `nginxproxy_energyguard_net`
- internal upstream target: `http://mlflow-oidc:5001`

Point Nginx Proxy Manager at the `mlflow-proxy` container instead of the `mlflow-oidc` container.

## Environment variables

- `MLFLOW_UPSTREAM_URL` (default in code: `https://mlflow.energy-guard.eu`, default in compose: `http://mlflow-oidc:5001`)
- `ADMIN_GROUP_NAME` (default: `mlflow-admins`)
- `TOKEN_HEADER_CANDIDATES` (default: `authorization,x-forwarded-access-token,x-auth-request-access-token`)
- `REQUEST_TIMEOUT_SECONDS` (default: `60`)
- `KEYCLOAK_LOGOUT_CLIENT_ID` (optional fallback; used only when no `id_token_hint` is available)
- `KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES` (default: `x-auth-request-id-token,x-forwarded-id-token,authorization`)
- `KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME` (optional; if set, proxy can read `id_token_hint` from this cookie)
- `MLFLOW_TRACKING_USERNAME` (optional; enables service-account Basic auth passthrough when set with password)
- `MLFLOW_TRACKING_PASSWORD` (optional; used with `MLFLOW_TRACKING_USERNAME`)
