"""
Gerador de config.

    python -m recon.init --program exemplo --in app.exemplo.com.br --handle leeo

Aplica os defaults sensatos automaticamente: sem wildcard quando é host único,
rate conservador, exclusão de ssl/dos no nuclei e o header de identificação.
Detecta wildcard vs host único e avisa o que isso implica.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

TEMPLATE = """program: {program}

# Escopo. Hosts SEM wildcard são varridos diretamente (seed); com '*.' a
# enumeração passiva expande. Tudo fora destas regras é descartado antes de
# qualquer tráfego ao alvo.
scope:
  in:
{in_block}
  out:{out_block}

database: {program}.db

# Identificação do pesquisador — programas pedem p/ allowlist de IP e atribuição.
http:
  user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  extra_headers: {{"X-Bug-Bounty": "{handle}"}}   # alguns exigem header próprio, ex.: {{"X-Bug-Bounty": "{handle}"}}

tools:
  subfinder: subfinder
  dnsx: dnsx
  httpx: /root/go/bin/httpx
  gau: gau
  nuclei: nuclei

# Defaults defensivos: 'info' fora (quase sempre OOS: headers, versão, códigos
# HTTP), exclui ssl/dos (categorias tipicamente proibidas), rate conservador.
nuclei:
  severity: "{severity}"
  rate_limit: {rate}
  exclude_tags: "{exclude_tags}"
  # templates: "/caminho/seus-templates-custom"   # seu edge

js_secrets:
  binary: {binary}
  workdir: .recon-js
  fetch_concurrency: {fetch_conc}
  entropy: false

verify:
  concurrency: 4

notify:
  discord_webhook: "{discord}"
"""

DEF_SEVERITY = "low,medium,high,critical"
DEF_EXCLUDE = "ssl,dos,fuzz"
DEF_RATE = 50
DEF_FETCH = 10
DEF_BINARY = "./engine/js-secrets/target/release/js-secrets"


def _list_block(items: list[str]) -> str:
    return "\n".join(f'    - "{i}"' for i in items)


def _out_block(items: list[str]) -> str:
    if not items:
        return " []   # nada além do que o filtro já dropa"
    return "\n" + _list_block(items)


def build(args) -> str:
    return TEMPLATE.format(
        program=args.program,
        in_block=_list_block(args.in_scope),
        out_block=_out_block(args.out_scope or []),
        handle=args.handle,
        severity=args.severity,
        rate=args.rate,
        exclude_tags=args.exclude_tags,
        binary=args.binary,
        fetch_conc=args.fetch_concurrency,
        discord=args.discord or "",
    )


def advise(args) -> None:
    """Avisos conforme o formato do escopo — onde a galera erra."""
    wild = [s for s in args.in_scope if s.startswith("*.")]
    exact = [s for s in args.in_scope if not s.startswith("*.")]
    print("── análise do escopo ──", file=sys.stderr)
    if wild and not exact:
        print(f"  wildcard: {wild} — enum de subdomínio ATIVA.", file=sys.stderr)
        print("  confirme que TODOS os sub-hosts encontrados estão em escopo.",
              file=sys.stderr)
    elif exact and not wild:
        if len(exact) == 1:
            print(f"  host único: {exact[0]} — sem wildcard de propósito.",
                  file=sys.stderr)
            print("  enum de subdomínio não agrega; o seed garante a varredura.",
                  file=sys.stderr)
        else:
            print(f"  {len(exact)} hosts fixos — só estes recebem tráfego.",
                  file=sys.stderr)
    else:
        print(f"  misto: {len(exact)} fixos + {len(wild)} wildcard.", file=sys.stderr)
    for s in args.in_scope:
        if s.startswith("http://") or s.startswith("https://") or "/" in s:
            print(f"  ⚠ '{s}' parece URL/caminho — use só o HOST (ex.: app.x.com).",
                  file=sys.stderr)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="recon.init", description="Gera um config.yaml de recon."
    )
    p.add_argument("--program", required=True, help="nome curto do programa")
    p.add_argument("--in", dest="in_scope", nargs="+", required=True,
                   metavar="HOST", help="hosts in-scope (use '*.dom' p/ wildcard)")
    p.add_argument("--out", dest="out_scope", nargs="*", metavar="HOST",
                   help="hosts/padrões fora de escopo")
    p.add_argument("--handle", default="SEU_HANDLE", help="seu handle na plataforma")
    p.add_argument("--rate", type=int, default=DEF_RATE, help="nuclei rate-limit")
    p.add_argument("--severity", default=DEF_SEVERITY)
    p.add_argument("--exclude-tags", default=DEF_EXCLUDE, dest="exclude_tags")
    p.add_argument("--fetch-concurrency", type=int, default=DEF_FETCH,
                   dest="fetch_concurrency")
    p.add_argument("--binary", default=DEF_BINARY, help="caminho do motor js-secrets")
    p.add_argument("--discord", default="", help="webhook do Discord (opcional)")
    p.add_argument("--output", help="arquivo de saída (default: <program>.yaml)")
    p.add_argument("--force", action="store_true", help="sobrescreve se existir")
    args = p.parse_args(argv)

    out = Path(args.output or f"{args.program}.yaml")
    if out.exists() and not args.force:
        print(f"erro: {out} já existe (use --force p/ sobrescrever)", file=sys.stderr)
        return 1

    out.write_text(build(args))
    advise(args)
    print(f"\n✓ {out} gerado. Revise e rode: python main.py {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
