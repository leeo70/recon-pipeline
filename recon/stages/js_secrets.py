"""
Estágio JS secrets — a ponte Python <-> motor Rust.

Junta os JS candidatos (urls .js do inventário + raízes vivas + <script src>
crawleados das páginas vivas), baixa cada um + seu .map, gera o manifest e
dispara o binário Rust. O Rust devolve JSONL de findings que gravamos em
`secrets`. Só os NOVOS entram em ctx.new_items pra notificação.

O crawl é o que faz funcionar em SPA/Next.js: o gau não conhece os bundles em
/_next/static/chunks/, mas eles estão referenciados no HTML da página viva.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from ..fetch import crawl_script_srcs, fetch_js
from ..runner import run_jsonl
from .base import Context, Stage, StageResult


class JsSecretsStage(Stage):
    name = "js_secrets"

    async def run(self, ctx: Context) -> StageResult:
        cfg = ctx.config.get("js_secrets", {})
        binary = cfg.get("binary", "js-secrets")
        if not shutil.which(binary) and not Path(binary).exists():
            raise RuntimeError(
                f"motor '{binary}' não encontrado. Compile: "
                f"cargo build --release em engine/js-secrets/ e aponte o "
                f"caminho em config.yaml -> js_secrets.binary"
            )

        headers = {"User-Agent": ctx.user_agent(), **ctx.extra_headers()}
        conc = cfg.get("fetch_concurrency", 20)

        # candidatos: tudo que termina em .js no inventário + serviços vivos
        candidates = set(ctx.db.urls_like(ctx.program, ".js"))
        live = ctx.db.live_urls(ctx.program)
        candidates.update(live)

        # crawl: <script src> das páginas vivas -> bundles reais de SPA/Next.js
        # (que o gau não conhece). Resolve pós-redirect, filtra in-scope.
        crawled: list[str] = []
        try:
            crawled = await crawl_script_srcs(live, headers, conc, ctx.scope.allows)
            candidates.update(crawled)
        except Exception:  # noqa: BLE001 — crawl é best-effort, nunca derruba a etapa
            pass

        urls = sorted(candidates)
        if not urls:
            return StageResult()

        # 1) baixa JS + .map (Python, I/O-bound) com identificação do pesquisador
        workdir = Path(cfg.get("workdir", ".recon-js")) / ctx.program
        manifest = await fetch_js(urls, workdir, conc, headers)
        if not manifest:
            return StageResult()

        manifest_path = workdir / "manifest.jsonl"
        manifest_path.write_text("\n".join(json.dumps(e) for e in manifest) + "\n")

        # 2) varredura (Rust, CPU-bound)
        cmd = [binary, "--manifest", str(manifest_path)]
        if cfg.get("entropy"):
            cmd.append("--entropy")

        total = new = 0
        novos: list[str] = []
        with ctx.db.tx():
            async for f in run_jsonl(cmd, timeout=1800, label="js-secrets"):
                total += 1
                is_new = ctx.db.add_secret(
                    ctx.program,
                    kind=f.get("kind"),
                    rule=f.get("rule"),
                    severity=f.get("severity"),
                    value=f.get("value"),
                    source_url=f.get("source_url"),
                    from_sourcemap=1 if f.get("from_sourcemap") else 0,
                    sourcemap_file=f.get("sourcemap_file"),
                    line=f.get("line"),
                )
                if is_new and f.get("kind") != "endpoint":
                    new += 1
                    tag = " [sourcemap]" if f.get("from_sourcemap") else ""
                    novos.append(
                        f"[{f.get('severity','?').upper()}] {f.get('rule')}: "
                        f"{f.get('value','')[:40]} @ {f.get('source_url')}{tag}"
                    )

        ctx.record_new(self.name, novos)
        note = f"+{len(crawled)} bundles via crawl" if crawled else ""
        return StageResult(total=total, new=new, note=note)
