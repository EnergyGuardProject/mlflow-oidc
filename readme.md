# MLflow with OIDC for EnergyGuard

This repository runs the [MLflow Tracking Server with oidc-auth plugin](https://github.com/mlflow-oidc/mlflow-oidc-auth), so that users log in to MLflow through Keycloak. A reverse proxy (`mlflow-proxy`) sits in front of the server. It restricts some MLflow actions to admins, shortens the session cookie lifetime, handles Keycloak single logout and replaces the MLflow logo with the EnergyGuard logo.

## Components

| Service | Built from | Role |
|---|--|---|
| `mlflow-oidc` | `Dockerfile` in the repository root | MLflow 3.8.1 with mlflow-oidc-auth 6.6.3 |
| `mlflow-proxy` | `mlflow-proxy/` | FastAPI reverse proxy in front of `mlflow-oidc` |

The MLflow server stores runs and experiments in the PostgreSQL database on host `pgdb` and stores artifacts in the S3 bucket `BUCKET_NAME`. Clients upload and download artifacts through the MLflow server, which is started with `--serve-artifacts`. The database and the S3 storage (MinIO) are not part of this compose file and must be reachable on the same Docker network.

## Running

Both services are defined in `docker-compose.yaml` at the root of this repository.

```bash
cd /path/to/mlflow-tracking-server-docker
docker compose up -d --build
```

Both containers join the external Docker network `nginxproxy_energyguard_net`, which must exist before you start them. The proxy forwards requests to `http://mlflow-oidc:5001`.

## MLflow server settings

These variables in `.env` configure the `mlflow-oidc` service.

| Variable | Purpose |
|---|---|
| `OIDC_DISCOVERY_URL` | OpenID configuration URL of the Keycloak realm |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | Keycloak client that MLflow logs users in with |
| `OIDC_REDIRECT_URI` | Callback URL that Keycloak sends users back to after login |
| `OIDC_SCOPE` | Scopes requested at login |
| `OIDC_PROVIDER_DISPLAY_NAME` | Text of the login button |
| `OIDC_GROUP_NAME` | Keycloak group whose members may use MLflow |
| `OIDC_ADMIN_GROUP_NAME` | Keycloak group whose members are MLflow admins |
| `DEFAULT_MLFLOW_PERMISSION` | Permission that users get on resources they have no explicit permission for |
| `DEFAULT_LANDING_PAGE_IS_PERMISSIONS` | Whether users land on the permissions page after login |
| `OIDC_USERS_DB_URI` | Database where mlflow-oidc-auth keeps users, groups and permissions |
| `SECRET_KEY` | Key that signs the session cookie. Generated once with `openssl rand -hex 32`. |
| `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DATABASE` | MLflow backend store on `pgdb` |
| `BUCKET_NAME` | S3 bucket for artifacts |
| `MLFLOW_S3_ENDPOINT_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | S3 endpoint and credentials |
| `LOG_LEVEL` | Log level of the server |

## Proxy

### Admin checks

A request is considered as coming from an admin from the proxy when one of the following is true.

1. It sends Basic auth credentials that match `MLFLOW_TRACKING_USERNAME` and `MLFLOW_TRACKING_PASSWORD` (the service account).
2. The `username` in its MLflow session cookie matches `MLFLOW_TRACKING_USERNAME`.
3. MLflow reports the user as an admin. The proxy calls `GET /api/2.0/mlflow/users/{username}` on the MLflow server and reads the `is_admin` field. The username comes from the session cookie. When there is no session cookie, as with API clients that use a personal access token, the proxy takes the username from the Basic auth header.

The lookup in step 3 is sent with the caller's own headers and cookies. If the password or token is wrong, MLflow rejects the lookup and the user is treated as a regular user.

### Restricted endpoints

Users who are not admins get a `403` response for the requests below. Each API path is blocked under both `/api/2.0/mlflow/` and `/ajax-api/2.0/mlflow/`.

| Action | Paths |
|---|---|
| Create, update or delete an experiment | `experiments/create`, `experiments/update`, `experiments/delete` |
| Set or delete an experiment tag | `experiments/set-experiment-tag`, `experiments/delete-experiment-tag` |
| List users and service accounts | `users` (this exact path only) |
| Manage permissions | everything under `permissions/` |
| Open the Users and Service Accounts pages of the OIDC UI | `/oidc/ui/users`, `/oidc/ui/service-accounts` and everything under them |

Every user can set the `mlflow.experimentKind` tag, because the MLflow UI sets it when a user picks an experiment type. The paths `users/current` and `users/{username}` stay open to everyone.

A blocked request gets a JSON response in the MLflow error format, with `error_code` set to `PERMISSION_DENIED` and a `message` that explains the restriction. The same message is also sent in the `X-MLflow-Proxy-Error` header.

All other requests are forwarded to `MLFLOW_UPSTREAM_URL`.

### Session lifetime

mlflow-oidc-auth sets a session cookie that lasts 14 days and offers no setting to change it. The proxy rewrites the `Max-Age` of the `session` cookie to `SESSION_COOKIE_MAX_AGE` seconds (300 by default). MLflow sends the cookie again with each response, so the timer restarts and active users stay logged in. After that many seconds without activity the browser drops the cookie and the next request starts a new OIDC login. If the Keycloak session has ended in the meantime, the user sees the Keycloak login page.

### Logout

When a user logs out of MLflow, the proxy sends the browser to the Keycloak logout endpoint so that the Keycloak session ends as well. The redirect includes the client ID of the MLflow Keycloak client, taken from `KEYCLOAK_LOGOUT_CLIENT_ID`. After logout Keycloak sends the user back to the MLflow home page.

### Backchannel logout

When a user logs out of an application in the Keycloak realm, for example JupyterHub, Keycloak can notify the proxy at `POST /backchannel-logout`. The proxy reads the user's email from the `logout_token`. If the token only carries the Keycloak user ID (`sub`), the proxy looks up the email through the Keycloak admin API with `KC_ISSUER_URL`, `KC_CLIENT_ID` and `KC_CLIENT_SECRET`. That client needs a service account that is allowed to view users (the `view-users` role of `realm-management`).

The user is then added to a revocation list. On their next request the proxy deletes their session cookie and redirects them to `/`, which starts a new login. Entries expire after twice `SESSION_COOKIE_MAX_AGE` seconds. The list is kept in memory, so it is cleared when the container restarts.

### EnergyGuard branding

The proxy adds a script, served at `/eg-static/logo.js`, to every HTML page it returns. The script replaces the MLflow logo in the top bar with the EnergyGuard logo, changes the version label to `MLflow - <version>` and hides the Permissions link in the MLflow header for users who are not admins. The logo is served at `/eg-static/logo.png` from the file in `EG_LOGO_PATH`.

### Health check

`GET /healthz` returns `{"status": "ok"}`.

### Proxy settings

Compose sets these variables for the `mlflow-proxy` service. It passes `SESSION_COOKIE_LIFETIME`, `MLFLOW_TRACKING_USERNAME`, `MLFLOW_TRACKING_PASSWORD` and the `KC_` variables from `.env`.

| Variable | Default | Purpose |
|---|---|---|
| `MLFLOW_UPSTREAM_URL` | `https://mlflow.energy-guard.eu` (compose sets `http://mlflow-oidc:5001`) | MLflow server that requests are forwarded to |
| `REQUEST_TIMEOUT_SECONDS` | `60` | Timeout in seconds for requests to MLflow and Keycloak |
| `SESSION_COOKIE_MAX_AGE` | `300` | Session cookie lifetime in seconds. Revocation entries expire after twice this value. Set it with `SESSION_COOKIE_LIFETIME` in `.env`. |
| `MLFLOW_TRACKING_USERNAME` | not set | Service account username. Together with the password it lets the service account through the admin restrictions. |
| `MLFLOW_TRACKING_PASSWORD` | not set | Service account password |
| `KC_ISSUER_URL` | not set | Keycloak realm URL, for example `https://keycloak.example.com/realms/MyRealm`. Needed for logout and backchannel logout. |
| `KC_CLIENT_ID` | not set | Client used to call the Keycloak admin API |
| `KC_CLIENT_SECRET` | not set | Secret of that client |
| `KEYCLOAK_LOGOUT_CLIENT_ID` | not set (compose sets `mlflow-energyguard`) | Client ID sent to Keycloak on logout |
| `EG_LOGO_PATH` | `/app/images/logo/EnergyGuard_Site-1024x640.png` | Logo file served at `/eg-static/logo.png` |

## Upstream

This repository is a fork of [mlflow-oidc/mlflow-tracking-server-docker](https://github.com/mlflow-oidc/mlflow-tracking-server-docker). 

## License

This project is licensed under the Apache 2.0 License. See the [license](./license) file.
