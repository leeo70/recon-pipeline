"""
Coleta de URLs (gau).

Aqui aparece endpoint velho, parâmetro esquecido, API morta que ninguém tirou
do ar. Fonte riquíssima e subexplorada por quem começa.

Harvest de hostnames: o gau frequentemente revela SUBDOMÍNIOS que a enumeração
passiva (subfinder) não traz — ex.: api.development., docs., sandbox. Os hostnames
in-scope das URLs viram assets novos (source='gau'), então na próxima run o
resolve/httpx/nuclei os pegam automaticamente. Sem isso, host vivo descoberto
pelo gau ficava invisível pro resto do recon.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..runner import ensure_tool, run
from .base import Context, Stage, StageResult


class UrlsStage(Stage):
    name = "urls"

    async def run(self, ctx: Context) -> StageResult:
        binary = ensure_tool(ctx.tool("gau"))
        seeds = ctx.scope.seeds()
        if not seeds:
            return StageResult()

        cfg = ctx.config.get("urls", {})
        cmd = [binary, "--subs",
               "--threads", str(cfg.get("threads", 5)),
               "--timeout", str(cfg.get("timeout", 20)),
               "--retries", str(cfg.get("retries", 2))]
        if cfg.get("providers"):
            cmd += ["--providers", cfg["providers"]]
        rc, out, _ = await run(cmd, stdin_lines=seeds, timeout=cfg.get("max_seconds", 900))

        total = new = 0
        added: list[str] = []
        hosts: set[str] = set()
        with ctx.db.tx():
            for line in out.splitlines():
                url = line.strip()
                if not url:
                    continue
                host = urlparse(url).hostname or ""
                if not ctx.scope.allows(host):
                    continue
                hosts.add(host)
                total += 1
                if ctx.db.add_url(ctx.program, url, source="gau"):
                    new += 1
                    added.append(url)

            # harvest: hostnames in-scope do gau viram assets — o resolve/httpx da
            # PRÓXIMA run os promove a alvos. Fecha a lacuna "gau achou, ninguém probou".
            new_hosts = [h for h in sorted(hosts)
                         if ctx.db.add_asset(ctx.program, h, source="gau")]

        ctx.record_new(self.name, added[:25])
        if new_hosts:
            ctx.record_new(self.name, [f"[host novo via gau] {h}" for h in new_hosts])

        note = f"+{len(new_hosts)} hosts via gau" if new_hosts else ""
        return StageResult(total=total, new=new, note=note)
