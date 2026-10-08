"""
Notificação de novidades.

Recon contínuo só vale se você fica sabendo quando algo NOVO aparece. Aqui é
Discord webhook (padrão na cena de bug bounty), mas o mesmo molde serve para
Telegram/Slack. Sem webhook configurado, vira no-op silencioso.
"""

from __future__ import annotations

import json
import urllib.request


def _post(webhook: str, content: str) -> None:
    data = json.dumps({"content": content[:1900]}).encode()
    req = urllib.request.Request(
        webhook, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=15)
    except Exception:
        pass  # notificação nunca deve derrubar a pipeline


def notify_new(config: dict, program: str, new_items: dict[str, list[str]]) -> None:
    webhook = config.get("notify", {}).get("discord_webhook")
    if not webhook or not any(new_items.values()):
        return

    lines = [f"**[{program}] novidades no recon**"]
    for stage, items in new_items.items():
        if not items:
            continue
        lines.append(f"\n__{stage}__ (+{len(items)}):")
        lines.extend(f"• {i}" for i in items[:15])
        if len(items) > 15:
            lines.append(f"… +{len(items) - 15}")

    _post(webhook, "\n".join(lines))
