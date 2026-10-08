#!/usr/bin/env python3
"""
Entrypoint do pipeline de recon contínuo.

    python main.py <config.yaml> [--profile 1-4]

A cada execução só notifica o delta (subdomínio/serviço/finding novo) em relação
ao banco — feito pra rodar no cron. No fim, rankeia os hosts mais interessantes.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import yaml

from recon.pipeline import run_pipeline

_EPILOG = """\
profiles (--profile N) — intensidade do scan + corte da triagem:
  1  surface     só enumera e mapeia; NÃO roda nuclei; triagem só das joias (score>=7)
  2  balanced    nuclei -as, severidade low-crit  [DEFAULT];  triagem score>=4
  3  aggressive  nuclei -as + info;  triagem ampla (score>=2)
  4  deep        nuclei full (sem -as) nos hosts reachable + info; triagem tudo (score>=0)

exemplos:
  python main.py raia.yaml --profile 1      # recon leve + leads de staging/QA
  python main.py raia.yaml                  # profile 2 (default)
  python main.py raia.yaml --profile 4      # varredura profunda

ferramentas companheiras:
  python -m recon.init   --program X --in "*.x.com" --handle voce   # gera um config
  python -m recon.doctor X.yaml                                     # valida os binários
  python -m recon.triage X.yaml --profile 1                         # rankeia o banco (sem re-scan)

a triagem pontua cada host por: status reachable + token de ambiente
(stg/qa/dev/test) + função (login/admin/api/...) + tech (wordpress/...). Cada
lead vem com o motivo do score (ex.: 'env:stg · fn:login').
"""


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="recon",
        description="Pipeline de recon contínuo: enumera, escaneia e rankeia "
                    "os alvos mais interessantes de um programa de bug bounty.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("config", nargs="?", default="config.yaml",
                    help="YAML do programa (gere com 'python -m recon.init')")
    ap.add_argument("--profile", type=int, default=2, choices=[1, 2, 3, 4],
                    metavar="N",
                    help="1=surface  2=balanced(default)  3=aggressive  4=deep")
    args = ap.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)
    try:
        asyncio.run(run_pipeline(config, profile=args.profile))
    except KeyboardInterrupt:
        print("\n[!] interrompido pelo usuário (Ctrl-C). "
              "O progresso parcial já foi salvo no banco.", file=sys.stderr)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
