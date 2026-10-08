"""
Contrato dos estágios.

Cada etapa do recon (subdomínios, resolve, http, urls, nuclei...) é uma
subclasse de Stage. Ela lê o que precisa do banco, roda sua ferramenta,
grava de volta e devolve a contagem do que é NOVO. Adicionar uma etapa nova
é só criar mais uma subclasse e plugar na lista da pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..db import DB
from ..scope import Scope


@dataclass
class Context:
    program: str
    db: DB
    scope: Scope
    config: dict
    # itens novos descobertos nesta run, agrupados por estágio (p/ notificação)
    new_items: dict[str, list[str]] = field(default_factory=dict)
    # substatus ao vivo (ex.: progresso do nuclei) lido pelo heartbeat
    status: str = ""

    def tool(self, name: str) -> str:
        """Resolve o binário de uma ferramenta a partir do config."""
        return self.config.get("tools", {}).get(name, name)

    def user_agent(self) -> str:
        """UA de identificação. Programas pedem isso p/ allowlist de IP."""
        return self.config.get("http", {}).get(
            "user_agent", "bug-bounty-recon/0.1 (+defina-seu-handle)"
        )

    def extra_headers(self) -> dict:
        """Headers extras de identificação (ex.: X-Bug-Bounty: <handle>)."""
        return dict(self.config.get("http", {}).get("extra_headers", {}) or {})

    def header_args(self, flag: str = "-H") -> list[str]:
        """Args de header p/ ferramentas CLI (httpx, nuclei usam '-H K: V')."""
        args: list[str] = [flag, f"User-Agent: {self.user_agent()}"]
        for k, v in self.extra_headers().items():
            args += [flag, f"{k}: {v}"]
        return args

    def set_status(self, text: str) -> None:
        """Substatus ao vivo exibido pelo heartbeat enquanto o estágio roda."""
        self.status = text

    def record_new(self, stage: str, items: list[str]) -> None:
        if items:
            self.new_items.setdefault(stage, []).extend(items)


@dataclass
class StageResult:
    total: int = 0
    new: int = 0
    note: str = ""   # nota extra opcional (ex.: "+4 hosts via gau")

    def __str__(self) -> str:
        s = f"{self.total} total / {self.new} novos"
        return f"{s} · {self.note}" if self.note else s


class Stage(ABC):
    name: str = "stage"

    @abstractmethod
    async def run(self, ctx: Context) -> StageResult: ...
