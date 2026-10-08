"""
Controle de escopo.

Em bug bounty isso não é detalhe — testar fora do escopo te queima no programa
e pode ter implicação legal. Todo hostname descoberto passa por aqui antes de
entrar no banco. Suporta wildcard ('*.acme.com') e exclusões explícitas.
"""

from __future__ import annotations


def _matches(pattern: str, host: str) -> bool:
    pattern = pattern.lower().strip().lstrip(".")
    host = host.lower().strip()

    if pattern.startswith("*."):
        root = pattern[2:]
        # *.acme.com cobre sub.acme.com e o apex acme.com
        return host == root or host.endswith("." + root)
    return host == pattern


class Scope:
    def __init__(self, in_scope: list[str], out_scope: list[str] | None = None):
        self.in_scope = [p.lower().strip() for p in in_scope]
        self.out_scope = [p.lower().strip() for p in (out_scope or [])]

    def allows(self, host: str) -> bool:
        if any(_matches(p, host) for p in self.out_scope):
            return False
        return any(_matches(p, host) for p in self.in_scope)

    def filter(self, hosts) -> list[str]:
        return [h for h in hosts if self.allows(h)]

    def seeds(self) -> list[str]:
        """Domínios-raiz para alimentar a enumeração passiva."""
        roots = []
        for p in self.in_scope:
            roots.append(p[2:] if p.startswith("*.") else p)
        return sorted(set(roots))

    def explicit_hosts(self) -> list[str]:
        """Hosts in-scope SEM wildcard — devem ser varridos diretamente,
        mesmo que a enumeração passiva não os retorne (caso host único)."""
        return sorted({p for p in self.in_scope if not p.startswith("*.")})
