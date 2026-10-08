"""Enumeração passiva de subdomínios (subfinder)."""

from __future__ import annotations

from ..runner import ToolNotFound, ensure_tool, run_jsonl
from .base import Context, Stage, StageResult


class SubdomainStage(Stage):
    name = "subdomains"

    async def run(self, ctx: Context) -> StageResult:
        total = new = 0
        added: list[str] = []

        # 1) semeia os hosts explícitos PRIMEIRO — assim alvos de host único
        # entram no banco mesmo que o subfinder não esteja instalado
        with ctx.db.tx():
            for host in ctx.scope.explicit_hosts():
                total += 1
                if ctx.db.add_asset(ctx.program, host, source="seed"):
                    new += 1
                    added.append(host)

        # 2) enumeração passiva (best-effort: se subfinder faltar, segue só c/ seed)
        seeds = ctx.scope.seeds()
        try:
            binary = ensure_tool(ctx.tool("subfinder"))
        except ToolNotFound:
            ctx.record_new(self.name, added)
            return StageResult(total=total, new=new)

        if seeds:
            cmd = [binary, "-silent", "-all", "-json"]
            for d in seeds:
                cmd += ["-d", d]
            with ctx.db.tx():
                async for obj in run_jsonl(cmd, timeout=900, label="subfinder"):
                    host = obj.get("host") or obj.get("input")
                    if not host or not ctx.scope.allows(host):
                        continue
                    total += 1
                    if ctx.db.add_asset(ctx.program, host, source="subfinder"):
                        new += 1
                        added.append(host)

        ctx.record_new(self.name, added)
        return StageResult(total=total, new=new)
