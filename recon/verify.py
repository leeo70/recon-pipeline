"""
Verificação de credenciais.

CONTRATO (não negociável): cada verificador faz UMA chamada read-only do tipo
"whoami" que só confirma se a credencial autentica. Nunca enumera recurso, nunca
lê dado de cliente, nunca modifica nada. É a diferença entre "confirmei que está
viva" (disclosure responsável) e "usei a chave" (acesso não-autorizado).

Casos que recusamos verificar de propósito:
  - slack_webhook  -> verificar = POSTar no canal de alguém (intrusivo)
  - aws_access_key -> precisa do secret pareado; AKIA sozinho não verifica
  - google_api_key -> chave é por-API, sem endpoint whoami genérico
Esses viram status 'unsupported' e seguem como triagem manual.

Status possíveis: valid | invalid | limited | expired | active | decoded |
                  unsupported | error
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.error
import urllib.request

TIMEOUT = 12
DEFAULT_UA = "bug-bounty-recon/0.1"
# Para falar com providers QUEREMOS TLS válido (canal de confiança real).
_CTX = ssl.create_default_context()


def _http(method: str, url: str, headers: dict, data: bytes | None = None):
    req = urllib.request.Request(url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_CTX) as r:
            return getattr(r, "status", 200), r.read(8192).decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(2048).decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return None, str(e)


def _classify(code: int | None, body: str, ok=(200,)) -> tuple[str, str]:
    if code in ok:
        return "valid", ""
    if code in (401, 403):
        return "invalid", f"http {code}"
    return "error", f"http {code}" if code else f"net: {body[:60]}"


# ---- verificadores por provider (1 chamada read-only cada) -----------------

def _v_github(v: str, ua: str) -> tuple[str, str]:
    code, body = _http("GET", "https://api.github.com/user", {
        "Authorization": f"Bearer {v}",
        "Accept": "application/vnd.github+json",
        "User-Agent": ua,
    })
    status, detail = _classify(code, body)
    if status == "valid":
        try:
            j = json.loads(body)
            detail = f"user={j.get('login')}"
        except Exception:  # noqa: BLE001
            pass
    return status, detail


def _v_gitlab(v: str, ua: str) -> tuple[str, str]:
    # assume gitlab.com; instâncias self-hosted exigem ajuste de host
    code, body = _http("GET", "https://gitlab.com/api/v4/user",
                       {"PRIVATE-TOKEN": v, "User-Agent": ua})
    status, detail = _classify(code, body)
    if status == "valid":
        try:
            detail = f"user={json.loads(body).get('username')}"
        except Exception:  # noqa: BLE001
            pass
    return status, detail


def _v_stripe(v: str, ua: str) -> tuple[str, str]:
    # /v1/balance: leve, não toca em dado de cliente
    code, body = _http("GET", "https://api.stripe.com/v1/balance",
                       {"Authorization": f"Bearer {v}", "User-Agent": ua})
    return _classify(code, body)


def _v_sendgrid(v: str, ua: str) -> tuple[str, str]:
    # /v3/scopes só revela o que a chave PODE fazer — útil e não-destrutivo
    code, body = _http("GET", "https://api.sendgrid.com/v3/scopes",
                       {"Authorization": f"Bearer {v}", "User-Agent": ua})
    status, detail = _classify(code, body)
    if status == "valid":
        try:
            scopes = json.loads(body).get("scopes", [])
            detail = f"{len(scopes)} scopes"
            if "mail.send" in scopes:
                detail += " (inclui mail.send!)"
        except Exception:  # noqa: BLE001
            pass
    return status, detail


def _v_slack(v: str, ua: str) -> tuple[str, str]:
    code, body = _http("POST", "https://slack.com/api/auth.test",
                       {"Authorization": f"Bearer {v}", "User-Agent": ua,
                        "Content-Type": "application/x-www-form-urlencoded"},
                       data=b"")
    if code != 200:
        return "error", f"http {code}"
    try:
        j = json.loads(body)
    except Exception:  # noqa: BLE001
        return "error", "resposta não-JSON"
    if j.get("ok"):
        return "valid", f"team={j.get('team')} user={j.get('user')}"
    return "invalid", j.get("error", "ok=false")


def _v_npm(v: str, ua: str) -> tuple[str, str]:
    code, body = _http("GET", "https://registry.npmjs.org/-/whoami",
                       {"Authorization": f"Bearer {v}", "User-Agent": ua})
    status, detail = _classify(code, body)
    if status == "valid":
        try:
            detail = f"user={json.loads(body).get('username')}"
        except Exception:  # noqa: BLE001
            pass
    return status, detail


def _v_jwt(v: str, ua: str) -> tuple[str, str]:
    """Offline: decodifica o payload e checa expiração. NÃO valida assinatura
    (isso exigiria o segredo), então um JWT 'active' ainda precisa de olho."""
    parts = v.split(".")
    if len(parts) != 3:
        return "error", "malformado"
    try:
        seg = parts[1]
        seg += "=" * (-len(seg) % 4)
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except Exception as e:  # noqa: BLE001
        return "error", f"decode: {e}"

    iss = payload.get("iss", "?")
    exp = payload.get("exp")
    if exp:
        if exp < time.time():
            return "expired", f"exp em {time.strftime('%Y-%m-%d', time.gmtime(exp))}; iss={iss}"
        return "active", f"não expirado; iss={iss} (assinatura não checada)"
    return "decoded", f"sem exp; iss={iss} sub={payload.get('sub')}"


VERIFIERS = {
    "github_token": _v_github,
    "gitlab_pat": _v_gitlab,
    "stripe_secret": _v_stripe,
    "sendgrid_key": _v_sendgrid,
    "slack_token": _v_slack,
    "npm_token": _v_npm,
    "jwt": _v_jwt,
}


def verify_one(rule: str, value: str, user_agent: str = DEFAULT_UA) -> tuple[str, str]:
    fn = VERIFIERS.get(rule)
    if not fn:
        return "unsupported", "sem probe read-only seguro p/ este tipo"
    try:
        return fn(value, user_agent)
    except Exception as e:  # noqa: BLE001
        return "error", str(e)[:80]
