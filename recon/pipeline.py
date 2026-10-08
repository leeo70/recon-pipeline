"""
Orquestrador.

Roda os estágios em ordem. Cada um lê do banco o que o anterior produziu, então
não precisa de um DAG complexo: uma lista ordenada resolve. Falha em um estágio
é logada mas não derruba os demais (recon é best-effort).

Visibilidade: enquanto um estágio roda (gau e nuclei levam minutos), um heartbeat
pinga reticências com o tempo decorrido e o contador [i/n]. Ctrl-C encerra limpo,
sem despejar traceback, e o que já foi descoberto fica salvo no banco.

Profile (1-4): ajusta a intensidade do scan e o corte da triagem final.
"""

from __future__ import annotations

import asyncio
import sys
import time

from . import stages as S
from .db import DB
from .notify import notify_new
from .scope import Scope
from .triage import apply_profile, report
from .stages.base import Context, Stage

DEFAULT_PIPELINE: list[Stage] = [
    S.SubdomainStage(),
    S.ResolveStage(),
    S.HttpxStage(),
    S.UrlsStage(),
    S.JsSecretsStage(),
    S.VerifyStage(),
    S.NucleiStage(),
]


async def _heartbeat(prefix: str, t0: float, ctx) -> None:
    """Pinga '...' com o tempo decorrido enquanto o estágio roda. Só anima em
    terminal (TTY); em log/pipe fica quieto pra não sujar a saída redirecionada."""
    if not sys.stdout.isatty():
        return
    n = 0
    try:
        while True:
            n = (n % 3) + 1
            elapsed = time.monotonic() - t0
            dots = "." * n + " " * (3 - n)
            sub = f" {ctx.status}" if ctx.status else ""
            visible = f"    {prefix} ▶ em execução{dots}{sub}  {elapsed:5.1f}s"
            sys.stdout.write("\r" + visible.ljust(100))
            sys.stdout.flush()
            await asyncio.sleep(0.5)
    except asyncio.CancelledError:
        pass


def _clear_line() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()


async def run_pipeline(config: dict, pipeline: list[Stage] | None = None,
                       profile: int = 2) -> None:
    apply_profile(config, profile)
    program = config["program"]
    db = DB(config.get("database", "recon.db"))
    scope = Scope(config["scope"]["in"], config["scope"].get("out", []))
    ctx = Context(program=program, db=db, scope=scope, config=config)
    pipeline = pipeline or DEFAULT_PIPELINE
    n = len(pipeline)

    run_id = db.start_run(program)
    pname = {1: "surface", 2: "balanced", 3: "aggressive", 4: "deep"}.get(profile, "?")
    print(f"[*] run #{run_id} — '{program}' — profile {profile} ({pname}) — {n} estágios\n")

    completed = False
    try:
        for i, stage in enumerate(pipeline, 1):
            t0 = time.monotonic()
            prefix = f"[{i}/{n}] {stage.name:<12}"
            ctx.status = ""
            hb = asyncio.create_task(_heartbeat(prefix, t0, ctx))
            interrupted = False
            err: Exception | None = None
            result = None
            try:
                result = await stage.run(ctx)
            except (KeyboardInterrupt, asyncio.CancelledError):
                interrupted = True
                raise
            except Exception as e:  # noqa: BLE001
                err = e
            finally:
                hb.cancel()
                try:
                    await hb
                except asyncio.CancelledError:
                    pass
                _clear_line()
                dt = time.monotonic() - t0
                if interrupted:
                    print(f"[x] {prefix} INTERROMPIDO após {dt:.1f}s")
                elif err is not None:
                    print(f"[!] {prefix} ERRO: {type(err).__name__}: {err}  ({dt:.1f}s)")
                else:
                    print(f"[+] {prefix} {result}  ({dt:.1f}s)")
        else:
            completed = True

        try:
            report(db, program, profile=profile)
        except Exception as e:  # noqa: BLE001
            print(f"[!] triagem falhou: {type(e).__name__}: {e}")
    finally:
        db.finish_run(run_id)
        if completed:
            notify_new(config, program, ctx.new_items)
        db.close()

    novos = sum(len(v) for v in ctx.new_items.values())
    print(f"\n[*] fim. {novos} itens novos desde a última run.")
