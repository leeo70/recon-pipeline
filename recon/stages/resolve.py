"""Resolução DNS + filtragem de wildcards (dnsx)."""

from __future__ import annotations

from ..runner import ensure_tool, run_jsonl
from .base import Context, Stage, StageResult


class ResolveStage(Stage):
    name = "resolve"

    async def run(self, ctx: Context) -> StageResult:
        binary = ensure_tool(ctx.tool("dnsx"))
        hosts = ctx.db.hostnames(ctx.program)
        if not hosts:
            return StageResult()

        # -wd faz wildcard detection no domínio raiz; ajuste por programa
        cmd = [binary, "-silent", "-json", "-a", "-resp"]

        total = 0
        with ctx.db.tx():
            async for obj in run_jsonl(cmd, stdin_lines=hosts, timeout=900, label="dnsx"):
                host = obj.get("host")
                a = obj.get("a") or []
                if not host or not a:
                    continue
                total += 1
                ctx.db.mark_resolved(ctx.program, host, a[0])

        # nada "novo" pra notificar aqui — resolve só enriquece assets
        return StageResult(total=total, new=0)
