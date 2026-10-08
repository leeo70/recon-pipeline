"""
Triagem — rankeia os hosts mais "interessantes" pra olhar à mão.

Não é mágica: replica o que um humano faz batendo o olho no inventário —
cruza (1) reachabilidade (status), (2) tokens do hostname que gritam ambiente
de staging/QA/dev/test ou função sensível (login/admin/api/orquestrador...) e
(3) tech conhecida (WordPress, GitLab...). Cada sinal soma pontos; o profile
define o corte (1=só joias ... 4=tudo reachable).

Uso standalone (lê o banco que já existe, sem re-scan):
    python -m recon.triage raia.yaml --profile 1
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# profile -> intensidade do scan + corte da triagem. Aplicado no pipeline.
PROFILES = {
    1: dict(name="surface",    nuclei=False, automatic_scan=True,  severity="low,medium,high,critical",       triage_min=7),
    2: dict(name="balanced",   nuclei=True,  automatic_scan=True,  severity="low,medium,high,critical",       triage_min=4),
    3: dict(name="aggressive", nuclei=True,  automatic_scan=True,  severity="info,low,medium,high,critical",  triage_min=2),
    4: dict(name="deep",       nuclei=True,  automatic_scan=False, severity="info,low,medium,high,critical",  triage_min=0),
}


def apply_profile(config: dict, profile: int) -> None:
    """Sobrepõe os dials que o profile controla (severity/automatic_scan/nuclei
    on-off) e grava o corte da triagem. Profile é escolha de runtime: ganha do YAML."""
    p = PROFILES.get(profile)
    if not p:
        return
    nuc = config.setdefault("nuclei", {})
    nuc["severity"] = p["severity"]
    nuc["automatic_scan"] = p["automatic_scan"]
    nuc["_enabled"] = p["nuclei"]
    config["_profile"] = profile
    config["_triage_min"] = p["triage_min"]


# tokens de AMBIENTE (staging/qa/dev/test...) — o maior sinal de bug bounty
_ENV_RE = re.compile(
    r"^(staging|stg|stage|qa|dev[a-z]*|test|tst|uat|hml|homolog\w*|sandbox|sbx|"
    r"preview|demo|beta|preprod|pre-?prod|ppd|sit|int|internal|lab|stage\w*)\d*$"
)
# tokens de FUNÇÃO sensível
_FUNC = {
    "login", "signin", "sso", "auth", "oauth", "admin", "adm", "api", "gateway",
    "gw", "portal", "dashboard", "painel", "console", "vpn", "git", "gitlab",
    "jenkins", "grafana", "kibana", "jira", "confluence", "orquestrador",
    "orchestrator", "backoffice", "bo", "manage", "manager", "deploy", "ci",
    "cd", "registry", "vault", "keycloak", "phpmyadmin", "pma", "webmail",
    "status", "metrics", "monitor", "internal", "intranet", "wallet", "pay", "payment", "pix", "checkout", "account", "conta", "bank", "banco", "transfer", "debug", "app", "mobile", "pagamento", "carteira",
}
# tech que por si só já é superfície
_TECH = (
    "wordpress", "joomla", "drupal", "gitlab", "jenkins", "jira", "confluence",
    "phpmyadmin", "tomcat", "weblogic", "jboss", "spring", "grafana", "kibana",
    "kong", "swagger", "graphql", "keycloak", "salesforce",
)
_TITLE = ("login", "admin", "dashboard", "painel", "index of", "phpmyadmin",
          "jenkins", "grafana", "kibana", "sign in")


def _tokens(host: str) -> list[str]:
    return [t for t in re.split(r"[.\-_]", host.lower()) if t]


def score(url: str, status, tech, title) -> tuple[int, list[str]]:
    """Devolve (pontuação, motivos) de um host."""
    host = urlparse(url).hostname or url
    toks = _tokens(host)
    sc = 0
    why: list[str] = []

    # 1) reachabilidade
    if status in (200, 201, 202, 204):
        sc += 3; why.append(str(status))
    elif status == 401:
        sc += 3; why.append("401-auth")
    elif status and 300 <= status < 400:
        sc += 2; why.append(str(status))
    elif status == 404:
        sc += 1
    elif status:
        why.append(str(status))

    # 2) ambiente (staging/qa/dev/test) — peso máximo
    envs = sorted({t for t in toks if _ENV_RE.match(t)})
    if envs:
        sc += 4; why.append("env:" + ",".join(envs))

    # 3) função sensível
    funcs = sorted({t for t in toks if t in _FUNC})
    if funcs:
        sc += 3; why.append("fn:" + ",".join(funcs))

    # 4) tech conhecida
    techl = (tech or "").lower()
    hits = [k for k in _TECH if k in techl]
    if hits:
        sc += 2; why.append("tech:" + ",".join(hits))

    # 5) título suspeito
    if any(k in (title or "").lower() for k in _TITLE):
        sc += 1; why.append("title")

    return sc, why


def leads(db, program: str, min_score: int = 0) -> list[tuple]:
    rows = db.conn.execute(
        "SELECT url, status_code, tech, title FROM http_services WHERE program = ?",
        (program,),
    )
    out = []
    for r in rows:
        sc, why = score(r["url"], r["status_code"], r["tech"], r["title"])
        if sc >= min_score:
            out.append((sc, r["url"], r["status_code"], why))
    out.sort(key=lambda x: (-x[0], x[1]))
    return out


def report(db, program: str, profile=None, min_score=None, limit: int = 40) -> None:
    if min_score is None:
        min_score = PROFILES.get(profile or 2, {}).get("triage_min", 0)
    pname = PROFILES.get(profile, {}).get("name", "custom")
    items = leads(db, program, min_score)
    print(f"\n=== triagem [{program}] — profile {profile} ({pname}): "
          f"{len(items)} leads (score >= {min_score}) ===")
    if not items:
        print("  (nenhum host atingiu o corte — afrouxe o profile)")
        return
    for sc, url, status, why in items[:limit]:
        print(f"  {sc:>3}  {url:<50} [{status}]  {' · '.join(why)}")
    if len(items) > limit:
        print(f"  … +{len(items) - limit} (suba o corte ou use --limit)")


def main(argv=None) -> int:
    import argparse
    import yaml
    from .db import DB

    ap = argparse.ArgumentParser(
        prog="recon.triage",
        description="Rankeia os hosts mais interessantes do banco (sem re-scan).",
    )
    ap.add_argument("config")
    ap.add_argument("--profile", type=int, default=2, choices=[1, 2, 3, 4])
    ap.add_argument("--min", type=int, help="score mínimo (sobrepõe o do profile)")
    ap.add_argument("--limit", type=int, default=40)
    a = ap.parse_args(argv)

    cfg = yaml.safe_load(open(a.config))
    db = DB(cfg.get("database", "recon.db"))
    report(db, cfg["program"], profile=a.profile, min_score=a.min, limit=a.limit)
    db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
