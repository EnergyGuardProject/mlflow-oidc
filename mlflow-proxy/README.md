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

## Group lookup

The proxy resolves admin access by calling:
`GET /api/2.0/mlflow/permissions/groups/{ADMIN_GROUP_NAME}/users`
on the upstream MLflow OIDC server and checking whether the current session `username` is in that list.

The proxy also allows a single machine account by matching the signed
session `username` against `MLFLOW_TRACKING_USERNAME`.

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

## Session lifetime & SSO single-logout

mlflow-oidc-auth's Starlette `SessionMiddleware` hardcodes a 14-day cookie
lifetime with no configuration knob.  The proxy works around this:

1. **Short-lived cookie** – every response rewrites the upstream `session=`
   cookie's `Max-Age` to `SESSION_COOKIE_MAX_AGE` seconds (default 300 = 5 min).
   The timer resets on every response, so active users stay logged in.  After
   5 minutes of inactivity the browser discards the cookie and the next
   request triggers a fresh OIDC login.

2. **Backchannel logout** – the proxy exposes `POST /backchannel-logout`.
   When Keycloak terminates a session (user logs out from *any* app in the
   realm), it POSTs a `logout_token` here.  The proxy adds the user to an
   in-memory revocation list; their next request gets a cookie-delete + redirect.

### Keycloak configuration for backchannel logout

1. Open **Keycloak Admin** → **Clients** → `mlflow-energyguard`
2. Go to the **Logout settings** (or **Advanced** tab, depending on Keycloak version)
3. Set **Backchannel logout URL** to the proxy's internal address reachable
   from the Keycloak server, e.g.:
   - Same Docker network: `http://mlflow-proxy:8069/backchannel-logout`
   - External (through Nginx): `https://mlflow.energy-guard.eu/backchannel-logout`
4. Enable **Backchannel logout session required** (toggle ON)
5. Save

Now logging out from JupyterHub (or any other client in the same realm) will
immediately invalidate the MLflow session.

## Environment variables

- `MLFLOW_UPSTREAM_URL` (default in code: `https://mlflow.energy-guard.eu`, default in compose: `http://mlflow-oidc:5001`)
- `ADMIN_GROUP_NAME` (default: `mlflow-admins`)
- `REQUEST_TIMEOUT_SECONDS` (default: `60`)
- `KEYCLOAK_LOGOUT_CLIENT_ID` (optional fallback; used only when no `id_token_hint` is available)
- `KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES` (default: `x-auth-request-id-token,x-forwarded-id-token,authorization`)
- `KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME` (optional; if set, proxy can read `id_token_hint` from this cookie)
- `MLFLOW_TRACKING_USERNAME` (optional; enables service-account Basic auth passthrough when set with password)
- `MLFLOW_TRACKING_PASSWORD` (optional; used with `MLFLOW_TRACKING_USERNAME`)
- `SESSION_COOKIE_MAX_AGE` (default: `300`; session cookie lifetime in seconds – controls both inactivity timeout and backchannel-logout revocation window)
