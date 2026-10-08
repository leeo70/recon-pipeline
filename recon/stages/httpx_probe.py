"""Probing HTTP — quais hosts respondem web e com o quê (httpx)."""

from __future__ import annotations

import json

from ..runner import ensure_tool, run_jsonl
from .base import Context, Stage, StageResult


class HttpxStage(Stage):
    name = "httpx"

    async def run(self, ctx: Context) -> StageResult:
        binary = ensure_tool(ctx.tool("httpx"))
        hosts = ctx.db.hostnames(ctx.program, resolved_only=True)
        if not hosts:
            # fallback: sem resolve rodado ainda, tenta todos
            hosts = ctx.db.hostnames(ctx.program)
        if not hosts:
            return StageResult()

        # flags ajustáveis por versão — alguns builds renomeiam/aposentam opções.
        # rode `httpx -h` na sua versão se precisar adequar.
        cfg = ctx.config.get("httpx", {})
        flags = cfg.get("flags", [
            "-silent", "-json",
            "-status-code", "-title", "-tech-detect", "-cdn",
            "-content-length", "-follow-redirects",
        ])
        cmd = [binary, *flags, *ctx.header_args()]

        total = new = 0
        added: list[str] = []
        with ctx.db.tx():
            async for obj in run_jsonl(
                cmd, stdin_lines=hosts, timeout=900, label="httpx"
            ):
                url = obj.get("url")
                if not url:
                    continue
                total += 1
                is_new = ctx.db.add_http(
                    ctx.program,
                    url=url,
                    host=obj.get("host"),
                    port=obj.get("port"),
                    status_code=obj.get("status_code"),
                    title=obj.get("title"),
                    tech=json.dumps(obj.get("tech", [])),
                    cdn=obj.get("cdn_name"),
                    content_length=obj.get("content_length"),
                )
                if is_new:
                    new += 1
                    sc = obj.get("status_code")
                    added.append(f"{url} [{sc}] {obj.get('title') or ''}".strip())

        ctx.record_new(self.name, added)
        return StageResult(total=total, new=new)
