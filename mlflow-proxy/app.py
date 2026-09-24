import base64
import hmac
import json
import os
import re
import time
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import logging

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response

logger = logging.getLogger("mlflow-proxy")
logging.basicConfig(level=logging.DEBUG)

MLFLOW_UPSTREAM_URL = os.getenv("MLFLOW_UPSTREAM_URL", "https://mlflow.energy-guard.eu").rstrip("/")
SESSION_COOKIE_MAX_AGE = int(os.getenv("SESSION_COOKIE_MAX_AGE", "300"))
KEYCLOAK_ISSUER_URL = os.getenv("KC_ISSUER_URL", "").rstrip("/")

# ---------------------------------------------------------------------------
# Backchannel logout: in-memory revocation list
# ---------------------------------------------------------------------------
# When Keycloak terminates a session (user logs out from *any* app in the
# realm), it POSTs a logout_token JWT to every client's backchannel-logout
# URL.  We decode the token, extract the username, and keep it in a
# revocation dict.  On subsequent requests the proxy checks this dict and,
# if the user is revoked, deletes the session cookie and forces re-auth.
#
# Entries auto-expire after 2 * SESSION_COOKIE_MAX_AGE seconds — by that
# point the browser would have discarded the cookie anyway.
# ---------------------------------------------------------------------------
_revoked_users: dict[str, float] = {}  # username -> monotonic timestamp
ADMIN_GROUP_NAME = os.getenv("ADMIN_GROUP_NAME", "mlflow-admins")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "60"))
KEYCLOAK_LOGOUT_CLIENT_ID = os.getenv("KEYCLOAK_LOGOUT_CLIENT_ID", "").strip()
KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES = tuple(
    header.strip().lower()
    for header in os.getenv(
        "KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES",
        "x-auth-request-id-token,x-forwarded-id-token,authorization",
    ).split(",")
    if header.strip()
)
KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME = os.getenv("KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME", "").strip()
MLFLOW_TRACKING_USERNAME = os.getenv("MLFLOW_TRACKING_USERNAME", "").strip()
MLFLOW_TRACKING_PASSWORD = os.getenv("MLFLOW_TRACKING_PASSWORD", "").strip()
EG_LOGO_PATH = os.getenv("EG_LOGO_PATH", "/app/images/logo/EnergyGuard_Site-1024x640.png")
EG_LOGO_URL = "/eg-static/logo.png"

ALL_METHODS = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
BLOCKED_EXACT_PATHS = {
    "/api/2.0/mlflow/experiments/create",
    "/api/2.0/mlflow/experiments/update",
    "/api/2.0/mlflow/experiments/delete",
    "/api/2.0/mlflow/experiments/set-experiment-tag",
    "/api/2.0/mlflow/experiments/delete-experiment-tag",
    "/ajax-api/2.0/mlflow/experiments/create",
    "/ajax-api/2.0/mlflow/experiments/update",
    "/ajax-api/2.0/mlflow/experiments/delete",
    "/ajax-api/2.0/mlflow/experiments/set-experiment-tag",
    "/ajax-api/2.0/mlflow/experiments/delete-experiment-tag",
    # List-of-users / list-of-service-accounts.  The OIDC UI's Users and
    # Service Accounts pages both fetch this — service accounts uses the
    # ?service=true query param.  /api/2.0/mlflow/users/current and
    # /api/2.0/mlflow/users/<email> remain accessible (they are different
    # paths under the same prefix).
    "/api/2.0/mlflow/users",
    "/ajax-api/2.0/mlflow/users",
    "/oidc/ui/users",
    "/oidc/ui/service-accounts",
}
BLOCKED_PREFIXES = (
    "/api/2.0/mlflow/permissions/",
    "/ajax-api/2.0/mlflow/permissions/",
    "/oidc/ui/users/",
    "/oidc/ui/service-accounts/",
)
# set-experiment-tag is admin-only — except for these specific tag keys, which
# are user-facing UI affordances rather than relationship metadata.
SET_EXPERIMENT_TAG_PATHS = {
    "/api/2.0/mlflow/experiments/set-experiment-tag",
    "/ajax-api/2.0/mlflow/experiments/set-experiment-tag",
}
ALLOWED_EXPERIMENT_TAG_KEYS = {
    "mlflow.experimentKind",  # MLflow 3.x experiment-type popup
}

app = FastAPI(title="MLflow Role Proxy")


# ---------------------------------------------------------------------------
# Backchannel-logout helpers
# ---------------------------------------------------------------------------

def _revoke_user(username: str) -> None:
    """Mark *username* as logged-out.  Also lazily purge stale entries."""
    _revoked_users[username.lower()] = time.monotonic()
    cutoff = time.monotonic() - (SESSION_COOKIE_MAX_AGE * 2)
    for key in [k for k, ts in _revoked_users.items() if ts < cutoff]:
        _revoked_users.pop(key, None)


def _is_user_revoked(username: str) -> bool:
    ts = _revoked_users.get(username.lower())
    if ts is None:
        return False
    if time.monotonic() - ts > SESSION_COOKIE_MAX_AGE * 2:
        _revoked_users.pop(username.lower(), None)
        return False
    return True


def _decode_jwt_payload(token: str) -> dict:
    """Return the *unverified* payload of a JWT (used for logout tokens)."""
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}


@app.get("/backchannel-logout")
async def backchannel_logout_info() -> dict:
    """Browser-friendly check — confirms the endpoint is live."""
    return {
        "endpoint": "/backchannel-logout",
        "method": "POST",
        "description": "Keycloak backchannel logout receiver. Configure this URL in Keycloak client settings.",
        "revoked_users_count": len(_revoked_users),
        "revoked_users": list(_revoked_users.keys()),
        "keycloak_admin_api_configured": bool(KEYCLOAK_ISSUER_URL and os.getenv("KC_CLIENT_ID") and os.getenv("KC_CLIENT_SECRET")),
    }


async def _resolve_keycloak_sub_to_email(sub: str) -> str | None:
    """Call the Keycloak admin API to resolve a user UUID to an email.

    Uses the service-account client-credentials grant to obtain an admin
    token, then fetches the user by ID.
    """
    if not KEYCLOAK_ISSUER_URL:
        return None

    client_id = os.getenv("KC_CLIENT_ID", "").strip()
    client_secret = os.getenv("KC_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        return None

    token_url = f"{KEYCLOAK_ISSUER_URL}/protocol/openid-connect/token"
    # The admin API base is two levels up from the realm issuer
    # e.g. https://keycloak.example.com/realms/MyRealm -> https://keycloak.example.com/admin/realms/MyRealm
    admin_base = KEYCLOAK_ISSUER_URL.replace("/realms/", "/admin/realms/")
    user_url = f"{admin_base}/users/{sub}"

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT_SECONDS)) as client:
            token_resp = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
            if token_resp.status_code != 200:
                logger.warning("Keycloak token request failed: %s %s", token_resp.status_code, token_resp.text[:200])
                return None
            access_token = token_resp.json().get("access_token")

            user_resp = await client.get(
                user_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if user_resp.status_code != 200:
                logger.warning("Keycloak user lookup failed for sub=%s: %s", sub, user_resp.status_code)
                return None
            user_data = user_resp.json()
            email = user_data.get("email", "").strip().lower()
            logger.info("Resolved Keycloak sub=%s -> email=%s", sub, email)
            return email or None
    except Exception as e:
        logger.error("Keycloak API error resolving sub=%s: %s", sub, e)
        return None


@app.post("/backchannel-logout")
async def backchannel_logout(request: Request) -> Response:
    """Receive a Keycloak backchannel logout notification.

    Keycloak POSTs ``application/x-www-form-urlencoded`` with a single
    ``logout_token`` field containing a signed JWT.  We decode the payload
    and extract the user's e-mail so we can add it to the revocation list.

    The logout_token typically only contains ``sub`` (a Keycloak UUID), not
    the email.  When ``email`` / ``preferred_username`` are absent, we call
    the Keycloak admin API to resolve sub -> email.
    """
    form = await request.form()
    logout_token = form.get("logout_token", "")
    if not logout_token:
        logger.warning("backchannel-logout: missing logout_token")
        return JSONResponse(status_code=400, content={"error": "missing logout_token"})

    payload = _decode_jwt_payload(str(logout_token))
    logger.info("backchannel-logout payload: %s", json.dumps(payload, default=str))
    if not payload:
        return JSONResponse(status_code=400, content={"error": "invalid logout_token"})

    # Try to get the email directly from the token (some Keycloak configs include it)
    username = payload.get("email") or payload.get("preferred_username")

    # Fall back: resolve the sub UUID via the Keycloak admin API
    if not username:
        sub = payload.get("sub", "")
        if sub:
            username = await _resolve_keycloak_sub_to_email(sub)

    if not username:
        logger.warning("backchannel-logout: cannot determine user from token: %s", payload)
        return JSONResponse(status_code=400, content={"error": "cannot determine user from logout_token"})

    _revoke_user(username)
    logger.info("backchannel-logout: revoked user %s, total revoked: %d", username, len(_revoked_users))
    return JSONResponse(status_code=200, content={"status": "ok"})


def _split_jwt(token: str) -> list[str]:
    parts = token.split(".")
    return parts if len(parts) == 3 else []

def _decode_basic_auth_credentials(request: Request) -> tuple[str, str] | None:
    raw_authorization = request.headers.get("authorization", "")
    scheme, _, encoded_credentials = raw_authorization.partition(" ")
    if scheme.lower() != "basic" or not encoded_credentials:
        return None
    try:
        decoded = base64.b64decode(encoded_credentials.strip()).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _is_service_account_request(request: Request) -> bool:
    if not MLFLOW_TRACKING_USERNAME or not MLFLOW_TRACKING_PASSWORD:
        return False

    credentials = _decode_basic_auth_credentials(request)
    if not credentials:
        return False

    username, password = credentials
    return hmac.compare_digest(username, MLFLOW_TRACKING_USERNAME) and hmac.compare_digest(
        password, MLFLOW_TRACKING_PASSWORD
    )


def _decode_flask_session_payload(cookie_value: str) -> dict:
    if not cookie_value:
        return {}

    payload_segment = cookie_value.split(".", 1)[0].strip()
    if not payload_segment:
        return {}

    padding = "=" * (-len(payload_segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload_segment + padding).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return {}

    return payload if isinstance(payload, dict) else {}


def _extract_session_username(request: Request) -> str:
    session_payload = _decode_flask_session_payload(request.cookies.get("session", ""))
    username = session_payload.get("username", "")
    return username.strip().lower() if isinstance(username, str) else ""


def _is_blocked_for_non_admin(path: str) -> bool:
    if path in BLOCKED_EXACT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in BLOCKED_PREFIXES)


async def _is_allowed_set_experiment_tag(request: Request, path: str) -> bool:
    """Peek at a set-experiment-tag POST body and decide whether to let it
    through despite the user not being an admin.

    The path-level block on set-experiment-tag exists so users can't rewrite
    project / ownership metadata.  But MLflow's UI also writes
    ``mlflow.experimentKind`` here when the user picks an experiment type
    from the popup — a benign UI affordance.  Allow that exact key and
    nothing else.
    """
    if path not in SET_EXPERIMENT_TAG_PATHS:
        return False
    try:
        body = await request.body()  # Starlette caches this; safe to call again later.
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    return payload.get("key") in ALLOWED_EXPERIMENT_TAG_KEYS


def _forbidden_message(path: str) -> str:
    if path.startswith("/oidc/ui/users") or path.startswith("/oidc/ui/service-accounts"):
        return "This page is restricted to MLflow administrators."
    if path.startswith("/api/2.0/mlflow/permissions/") or path.startswith("/ajax-api/2.0/mlflow/permissions/"):
        return "Permission management is restricted to MLflow admins."
    return "This MLflow action is restricted to MLflow admins."


def _forbidden_response(request: Request, path: str) -> Response:
    message = _forbidden_message(path)
    return JSONResponse(
        status_code=403,
        content={"error_code": "PERMISSION_DENIED", "message": message},
        headers={"X-MLflow-Proxy-Error": message},
    )


def _build_upstream_headers(request: Request) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() != "content-length"
    }

    original_host = request.headers.get("host", "").strip()
    if original_host:
        headers["host"] = original_host
        headers.setdefault("x-forwarded-host", original_host)

        host_name, _, host_port = original_host.partition(":")
        if host_name:
            headers.setdefault("x-forwarded-server", host_name)
        if host_port:
            headers.setdefault("x-forwarded-port", host_port)
        else:
            proto = headers.get("x-forwarded-proto", request.url.scheme).lower()
            headers.setdefault("x-forwarded-port", "443" if proto == "https" else "80")

    headers.setdefault("x-forwarded-proto", request.url.scheme)
    return headers


async def _is_admin_api_call(request: Request, username) -> set[str]:
    users_url = httpx.URL(f"{MLFLOW_UPSTREAM_URL}/api/2.0/mlflow/users/{username}")
    headers = _build_upstream_headers(request)
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
            response = await client.get(users_url, headers=headers)
    except httpx.HTTPError:
        return set()

    print("response", response)
    if response.status_code != 200:
        return set()

    try:
        payload = response.json()
        print(payload)
        is_admin = payload['is_admin']
        print(is_admin)
    except json.JSONDecodeError:
        is_admin = False
    if not isinstance(payload, dict):
        is_admin = False

    return is_admin


async def _is_admin(request: Request) -> bool:
    session_username = _extract_session_username(request)
    if session_username:
        if MLFLOW_TRACKING_USERNAME and session_username == MLFLOW_TRACKING_USERNAME.lower():
            return True
        return await _is_admin_api_call(request, session_username)

    # No Flask session cookie (typical for API clients using a PAT). Fall back
    # to the username carried in the Basic-auth header so admin-only endpoints
    # work for admins authenticating via PAT, not just the browser UI.
    creds = _decode_basic_auth_credentials(request)
    if creds:
        username, _ = creds
        return await _is_admin_api_call(request, username.strip().lower())

    return False


def _extract_logout_id_token(request: Request) -> str | None:
    for header_name in KEYCLOAK_LOGOUT_ID_TOKEN_HEADER_CANDIDATES:
        raw_value = request.headers.get(header_name)
        if not raw_value:
            continue
        if header_name == "authorization":
            scheme, _, token = raw_value.partition(" ")
            if scheme.lower() != "bearer" or not token:
                continue
            candidate = token.strip()
        else:
            candidate = raw_value.strip()

        if _split_jwt(candidate):
            return candidate

    if KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME:
        cookie_value = request.cookies.get(KEYCLOAK_LOGOUT_ID_TOKEN_COOKIE_NAME, "").strip()
        if cookie_value and _split_jwt(cookie_value):
            return cookie_value

    return None


def _username_from_set_cookie(set_cookie_value: str) -> str:
    """Decode the Flask session payload out of a ``Set-Cookie: session=…`` header."""
    cookie_part = set_cookie_value.split(";", 1)[0]
    _, _, raw_value = cookie_part.partition("=")
    raw_value = raw_value.strip()
    if not raw_value:
        return ""
    payload = _decode_flask_session_payload(raw_value)
    username = payload.get("username", "")
    return username.strip().lower() if isinstance(username, str) else ""


def _rewrite_session_cookie_max_age(cookie_value: str) -> str:
    """Rewrite the session cookie's Max-Age so it expires sooner.

    Starlette's SessionMiddleware defaults to 14-day Max-Age with no knob
    exposed by mlflow-oidc-auth.  By shortening it at the proxy layer the
    browser will discard the cookie after SESSION_COOKIE_MAX_AGE seconds of
    inactivity, forcing a new OIDC login flow.  If the Keycloak session was
    killed (e.g. the user logged out via another app) that re-auth will
    redirect to the Keycloak login page — effectively providing single-logout.
    """
    if re.search(r"(?i)\bmax-age\s*=\s*\d+", cookie_value):
        cookie_value = re.sub(
            r"(?i)\bmax-age\s*=\s*\d+",
            f"Max-Age={SESSION_COOKIE_MAX_AGE}",
            cookie_value,
        )
    else:
        cookie_value += f"; Max-Age={SESSION_COOKIE_MAX_AGE}"
    return cookie_value


def _build_keycloak_logout_url(request: Request) -> str | None:
    """Construct Keycloak's RP-initiated logout URL.

    Returns None when the issuer URL or the client identifier are missing —
    in that case there is nothing safe to redirect to, so callers should fall
    back to leaving the upstream redirect alone.
    """
    if not KEYCLOAK_ISSUER_URL:
        return None

    id_token_hint = _extract_logout_id_token(request)
    if not id_token_hint and not KEYCLOAK_LOGOUT_CLIENT_ID:
        return None

    original_host = request.headers.get("host", "").strip()
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    post_logout_redirect = f"{proto}://{original_host}/" if original_host else None

    query_items: list[tuple[str, str]] = []
    if id_token_hint:
        query_items.append(("id_token_hint", id_token_hint))
    if KEYCLOAK_LOGOUT_CLIENT_ID:
        query_items.append(("client_id", KEYCLOAK_LOGOUT_CLIENT_ID))
    if post_logout_redirect:
        query_items.append(("post_logout_redirect_uri", post_logout_redirect))

    return (
        f"{KEYCLOAK_ISSUER_URL}/protocol/openid-connect/logout?"
        + urlencode(query_items, doseq=True)
    )


def _rewrite_logout_location(path: str, request: Request, headers: dict[str, str]) -> dict[str, str]:
    if path != "/logout":
        return headers

    location_key = next((key for key in headers if key.lower() == "location"), None)
    if not location_key:
        return headers

    location = headers[location_key]
    parsed = urlsplit(location)

    if "/protocol/openid-connect/logout" in parsed.path:
        # Upstream already points at Keycloak; just enrich the query with
        # id_token_hint or client_id so the IdP can identify the session.
        query_items = parse_qsl(parsed.query, keep_blank_values=True)
        query_keys = {key for key, _ in query_items}
        if "id_token_hint" in query_keys:
            return headers
        if "post_logout_redirect_uri" not in query_keys:
            return headers

        id_token_hint = _extract_logout_id_token(request)
        if id_token_hint:
            query_items.append(("id_token_hint", id_token_hint))
        elif "client_id" not in query_keys and KEYCLOAK_LOGOUT_CLIENT_ID:
            query_items.append(("client_id", KEYCLOAK_LOGOUT_CLIENT_ID))
        else:
            return headers

        headers[location_key] = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(query_items, doseq=True),
                parsed.fragment,
            )
        )
        return headers

    # Upstream cleared the local Flask session but redirected to a local
    # page (e.g. /oidc/ui/auth).  Keycloak's SSO session is still alive, so
    # the next /login would silently re-authenticate — meaning "logout"
    # didn't really log the user out.  Force a redirect to Keycloak's
    # end_session_endpoint instead.
    keycloak_url = _build_keycloak_logout_url(request)
    if keycloak_url:
        headers[location_key] = keycloak_url
    return headers


async def _forward_request(request: Request, path: str) -> Response:
    upstream_url = httpx.URL(f"{MLFLOW_UPSTREAM_URL}/{path.lstrip('/')}")
    query_string = request.url.query.encode("utf-8")
    if query_string:
        upstream_url = upstream_url.copy_with(query=query_string)

    body = await request.body()
    headers = _build_upstream_headers(request)

    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=headers,
        )

    skip_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
    response_headers: dict[str, str] = {}
    set_cookie_headers: list[str] = []

    for key, value in upstream_response.headers.items():
        if key.lower() in skip_headers:
            continue
        if key.lower() == "set-cookie":
            # Collect Set-Cookie headers separately so duplicates are preserved.
            if value.startswith("session="):
                value = _rewrite_session_cookie_max_age(value)
            set_cookie_headers.append(value)
        else:
            response_headers[key] = value

    response_headers = _rewrite_logout_location(path, request, response_headers)

    # A successful /callback mints a fresh session for the user.  Clear any
    # leftover revocation from a prior logout so the very next request isn't
    # bounced back to the login screen.  (Without this, the user has to
    # "log in" twice after each logout — Keycloak SSO is still active, but
    # the proxy's revocation list isn't.)
    if path == "/callback":
        for cookie_header in set_cookie_headers:
            if not cookie_header.startswith("session="):
                continue
            fresh_user = _username_from_set_cookie(cookie_header)
            if fresh_user and _revoked_users.pop(fresh_user, None) is not None:
                logger.info("Cleared stale revocation after /callback for %s", fresh_user)

    content = upstream_response.content
    if "text/html" in upstream_response.headers.get("content-type", "").lower():
        content = _inject_logo_replacement(content)

    response = Response(
        content=content,
        status_code=upstream_response.status_code,
        headers=response_headers,
        media_type=upstream_response.headers.get("content-type"),
    )
    for cookie_header in set_cookie_headers:
        response.headers.append("set-cookie", cookie_header)
    return response


@app.get("/healthz")
async def healthcheck() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/eg-static/logo.png")
async def eg_logo() -> Response:
    if not os.path.exists(EG_LOGO_PATH):
        return Response(status_code=404)
    return FileResponse(
        EG_LOGO_PATH,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/eg-static/logo.js")
async def eg_logo_js() -> Response:
    return Response(
        content=_LOGO_JS,
        media_type="application/javascript",
        headers={"Cache-Control": "public, max-age=60"},
    )


# Replaces MLflow's top-left logo with the EnergyGuard wordmark.
#
# MLflow's top bar IS a <header> element (class css-ehv30l) but the home
# anchor uses href="#/" — same as the sidebar "Home" link.  To pick out only
# the header logo we filter on viewport position: the header anchor is at
# rect.top < 100, the sidebar Home link is much further down.
#
# The script is served as an external resource (not inlined) so MLflow's CSP
# doesn't block it.  Reload check: GET /eg-static/logo.js should return 200.
_LOGO_JS = """(function(){
  console.log('[eg-proxy] logo replacement loaded');
  var L='/eg-static/logo.png';
  var H='42px';
  // Cached promise resolving to true iff the current user is_admin.
  // We only call the API once per page; subsequent passes reuse the result.
  var _adminPromise=null;
  function isAdmin(){
    if(_adminPromise)return _adminPromise;
    _adminPromise=fetch('/api/2.0/mlflow/users/current',{
      credentials:'include',
      headers:{'Accept':'application/json'}
    }).then(function(r){return r.ok?r.json():null;})
      .then(function(d){return !!(d&&d.is_admin===true);})
      .catch(function(){return false;});
    return _adminPromise;
  }
  function applyLogo(im){
    im.src=L;
    im.alt='EnergyGuard';
    im.setAttribute('data-eg-logo','1');
    im.style.setProperty('height',H,'important');
    im.style.setProperty('width','auto','important');
    im.style.setProperty('max-width','none','important');
    im.style.setProperty('max-height','none','important');
    im.style.verticalAlign='middle';
    im.style.objectFit='contain';
  }
  function hidePermissionsLink(){
    // Don't touch the OIDC plugin's own UI (it lives at /oidc/*) — only
    // hide the "Permissions" entry that mlflow-oidc-auth injects into
    // MLflow's own top-right nav, and only for non-admins.
    if(window.location.pathname.indexOf('/oidc/')===0)return;
    isAdmin().then(function(admin){
      if(admin)return;
      var anchors=document.querySelectorAll('header a');
      for(var i=0;i<anchors.length;i++){
        var a=anchors[i];
        if((a.textContent||'').trim()!=='Permissions')continue;
        if(a.getAttribute('data-eg-hidden')==='1')continue;
        a.style.setProperty('display','none','important');
        a.setAttribute('data-eg-hidden','1');
      }
    });
  }
  function r(){
    // Brand anchor selectors:
    //  - MLflow main UI : <a href="#/"> (hash routing)
    //  - mlflow-oidc UI : <a class="text-logo" href="…dynamic…">
    // Deliberately NOT matching a[href="/"] — that is a nav-menu link on
    // the OIDC pages ("MLFlow"), not the brand.
    var ls=document.querySelectorAll('a[href="#/"],a[href="/#/"],a.text-logo');
    for(var i=0;i<ls.length;i++){
      var a=ls[i];
      var rc=a.getBoundingClientRect();
      if(rc.width===0&&rc.height===0)continue;
      if(rc.top>100)continue;
      var kids=a.querySelectorAll('svg,img:not([data-eg-logo])');
      for(var j=0;j<kids.length;j++){
        if(kids[j].style.display!=='none')kids[j].style.display='none';
      }
      if(!a.querySelector('img[data-eg-logo]')){
        var im=document.createElement('img');
        applyLogo(im);
        a.insertBefore(im,a.firstChild);
      }
      // Rewrite the version sibling to "MLflow - <version>" (MLflow main UI).
      var sib=a.nextElementSibling;
      while(sib){
        var text=(sib.textContent||'').trim();
        var m=text.match(/(\\d+(?:\\.\\d+)+)\\s*$/);
        if(m){
          var desired='MLflow - '+m[1];
          if(text!==desired)sib.textContent=desired;
          break;
        }
        sib=sib.nextElementSibling;
      }
    }
    // Clean up any stale EG-logo imgs left by older versions of this script
    // (it used to inject into a[href="/"] on the OIDC nav menu).
    var stale=document.querySelectorAll('a[href="/"] img[data-eg-logo]');
    for(var s=0;s<stale.length;s++){
      var sa=stale[s].parentElement;
      stale[s].remove();
      if(sa){
        var hidden=sa.querySelectorAll('svg[style*="display: none"],img[style*="display: none"]');
        for(var h=0;h<hidden.length;h++)hidden[h].style.display='';
      }
    }
    hidePermissionsLink();
  }
  function start(){
    r();
    new MutationObserver(r).observe(document.documentElement,{childList:true,subtree:true});
  }
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',start);}
  else{start();}
})();"""

_LOGO_INJECTION = '<script src="/eg-static/logo.js" defer></script>'


def _inject_logo_replacement(content: bytes) -> bytes:
    try:
        html = content.decode("utf-8")
    except UnicodeDecodeError:
        return content
    if "</body>" in html:
        html = html.replace("</body>", f"{_LOGO_INJECTION}</body>", 1)
    elif "</head>" in html:
        html = html.replace("</head>", f"{_LOGO_INJECTION}</head>", 1)
    else:
        html = html + _LOGO_INJECTION
    return html.encode("utf-8")


@app.api_route("/{path:path}", methods=ALL_METHODS)
async def proxy(path: str, request: Request) -> Response:
    normalized_path = "/" + path.lstrip("/")

    # Backchannel logout: if Keycloak revoked this user's session, delete the
    # cookie immediately and force a fresh OIDC login.  Remove the user from
    # the revocation list afterwards so the fresh login (which just went
    # through Keycloak) is not blocked again.
    session_username = _extract_session_username(request)
    if session_username and _is_user_revoked(session_username):
        _revoked_users.pop(session_username.lower(), None)
        logger.info("Revocation consumed for %s — deleting cookie and redirecting", session_username)
        response = Response(status_code=302, headers={"location": "/"})
        response.delete_cookie("session", path="/")
        return response

    if _is_blocked_for_non_admin(normalized_path) and not _is_service_account_request(request) and not await _is_admin(
        request
    ):
        if not await _is_allowed_set_experiment_tag(request, normalized_path):
            return _forbidden_response(request, normalized_path)

    return await _forward_request(request, normalized_path)
