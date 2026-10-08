"""Detecção de vulnerabilidades (nuclei) sobre os alvos HTTP vivos.

Progresso ao vivo: o nuclei roda como UM processo sobre todos os alvos (não um
por URL — seria caro e perderia o agendamento/dedup interno dele). Ligamos
-stats-json, lemos as stats do stderr a cada 3s e empurramos pro heartbeat via
ctx.set_status(), então o painel mostra percentual/requests/ETA enquanto varre.
"""

from __future__ import annotations

import json

from ..runner import ensure_tool, run_streaming
from .base import Context, Stage, StageResult


def _progress_cb(ctx: Context):
    """Traduz cada linha de stats-json do nuclei num substatus pro heartbeat.
    Em -as o nuclei não pré-calcula total (vem total=0, percent=overflow), então
    caímos pra contadores vivos (req feitos · rps · hosts)."""
    def on_stderr(line: str) -> None:
        line = line.strip()
        if not (line.startswith("{") and "percent" in line):
            return
        try:
            st = json.loads(line)
        except Exception:  # noqa: BLE001
            return

        def num(k):
            try:
                return int(st.get(k))
            except (TypeError, ValueError):
                return None

        pct, req, tot, rps = num("percent"), num("requests"), num("total"), num("rps")
        matched, errs, hosts = num("matched"), num("errors"), num("hosts")
        parts: list[str] = []
        if pct is not None and 0 <= pct <= 100 and tot:
            parts.append(f"{pct}%")
            if req is not None:
                parts.append(f"req {req}/{tot}")
            if rps and req is not None:
                eta = max(0, tot - req) // rps
                parts.append(f"ETA {eta // 60}m{eta % 60:02d}s")
        else:
            if req is not None:
                parts.append(f"req {req}")
            if rps:
                parts.append(f"{rps}/s")
            if hosts is not None:
                parts.append(f"{hosts} hosts")
        if matched:
            parts.append(f"matched {matched}")
        if errs:
            parts.append(f"err {errs}")
        if parts:
            ctx.set_status(" · ".join(parts))

    return on_stderr


class NucleiStage(Stage):
    name = "nuclei"

    async def run(self, ctx: Context) -> StageResult:
        cfg = ctx.config.get("nuclei", {})
        if not cfg.get("_enabled", True):
            return StageResult()  # profile 1 (surface): nuclei desligado pelo perfil
        binary = ensure_tool(ctx.tool("nuclei"))

        # filtra os alvos: pula parede de WAF (403) e host morto (502/503/504),
        # que só geram erro/ruído. Configurável via nuclei.skip_status.
        skip_raw = cfg.get("skip_status", "403,502,503,504")
        if isinstance(skip_raw, (list, set, tuple)):
            skip = set(skip_raw)
        else:
            skip = {int(x) for x in str(skip_raw).split(",") if str(x).strip()}
        targets = ctx.db.scannable_urls(ctx.program, skip)
        if not targets:
            return StageResult()

        cmd = [
            binary, "-silent", "-jsonl", "-duc",
            "-stats", "-sj", "-stats-interval", "3",
            "-severity", cfg.get("severity", "low,medium,high,critical"),
            "-rate-limit", str(cfg.get("rate_limit", 150)),
            *ctx.header_args(),
        ]
        # -as: nuclei detecta a tech (wappalyzer) e roda só o relevante (10-50x menos)
        if cfg.get("automatic_scan", True):
            cmd.append("-as")
        if cfg.get("exclude_tags"):
            cmd += ["-etags", cfg["exclude_tags"]]
        if cfg.get("templates"):
            cmd += ["-t", cfg["templates"]]

        findings = await run_streaming(
            cmd, stdin_lines=targets, timeout=1800, label="nuclei",
            on_stderr=_progress_cb(ctx),
        )
        ctx.set_status("")

        total = new = 0
        added: list[str] = []
        with ctx.db.tx():
            for obj in findings:
                tid = obj.get("template-id")
                if not tid:  # defensivo: ignora linha que não seja finding
                    continue
                info = obj.get("info", {})
                matched = obj.get("matched-at") or obj.get("host")
                sev = info.get("severity", "unknown")
                total += 1
                is_new = ctx.db.add_finding(
                    ctx.program,
                    template_id=tid,
                    severity=sev,
                    name=info.get("name"),
                    matched_at=matched,
                    raw=json.dumps(obj),
                )
                if is_new:
                    new += 1
                    added.append(f"[{sev.upper()}] {info.get('name')} -> {matched}")

        ctx.record_new(self.name, added)
        return StageResult(total=total, new=new)
