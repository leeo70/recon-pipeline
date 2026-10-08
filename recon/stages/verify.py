"""
Estágio de verificação.

Pega os secrets ainda não verificados e dispara o probe read-only de cada um.
O sinal que importa: os que voltam 'valid' (ou 'active'/'limited') são os
relatáveis — esses entram em ctx.new_items pra te avisar na hora.
"""

from __future__ import annotations

import asyncio

from ..verify import verify_one
from .base import Context, Stage, StageResult

# o que conta como "confirmado vivo" para fins de alerta
LIVE = {"valid", "active", "limited"}


class VerifyStage(Stage):
    name = "verify"

    async def run(self, ctx: Context) -> StageResult:
        rows = ctx.db.unverified_secrets(ctx.program)
        if not rows:
            return StageResult()

        cfg = ctx.config.get("verify", {})
        sem = asyncio.Semaphore(cfg.get("concurrency", 8))
        ua = ctx.user_agent()

        async def check(row):
            async with sem:
                status, detail = await asyncio.to_thread(
                    verify_one, row["rule"], row["value"], ua
                )
            return row, status, detail

        results = await asyncio.gather(*(check(r) for r in rows))

        live: list[str] = []
        counts: dict[str, int] = {}
        with ctx.db.tx():
            for row, status, detail in results:
                ctx.db.set_verify(row["id"], status, detail)
                counts[status] = counts.get(status, 0) + 1
                if status in LIVE:
                    live.append(
                        f"✅ VÁLIDO [{row['rule']}] {row['value'][:28]} "
                        f"({detail}) @ {row['source_url']}"
                    )

        # resumo legível no log: valid=2 invalid=5 unsupported=3 ...
        summary = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"      └─ {summary}")

        ctx.record_new(self.name, live)
        return StageResult(total=len(rows), new=len(live))
