"""
Execução de ferramentas externas.

A maioria das ferramentas de recon (subfinder, httpx, nuclei, dnsx...) lê de
stdin e escreve em stdout, idealmente em JSONL. Este runner padroniza isso:
alimenta stdin, captura stdout, faz parse opcional de JSONL e respeita timeout.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from typing import AsyncIterator


class ToolNotFound(RuntimeError):
    pass


def ensure_tool(binary: str) -> str:
    path = shutil.which(binary)
    if not path:
        raise ToolNotFound(
            f"'{binary}' não encontrado no PATH. Instala a ferramenta ou "
            f"ajusta o nome em config.yaml -> tools."
        )
    return path


async def run(
    cmd: list[str],
    stdin_lines: list[str] | None = None,
    timeout: float | None = 600,
) -> tuple[int, str, str]:
    """Roda um comando, opcionalmente alimentando stdin. Retorna (rc, out, err)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_lines is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    payload = ("\n".join(stdin_lines) + "\n").encode() if stdin_lines else None
    try:
        out, err = await asyncio.wait_for(proc.communicate(payload), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"timeout após {timeout:.0f}s sem terminar") from None

    return (
        proc.returncode,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )


def _pick_error_line(err: str, rc: int | None) -> str:
    """Extrai a linha de stderr que importa, ignorando banner ASCII e ruído.
    httpx & cia imprimem arte ASCII antes do erro real — não é o que queremos."""
    lines = [l.strip() for l in err.splitlines() if l.strip()]
    keywords = ("flag provided", "not defined", "unknown flag", "unsupported",
                "invalid", "no such", "error", "failed", "panic", "usage:")
    for kw in keywords:
        for l in lines:
            if kw in l.lower():
                return l
    # descarta linhas que são só arte ASCII (poucos chars alfanuméricos)
    for l in reversed(lines):
        alnum = sum(c.isalnum() for c in l)
        if alnum >= max(4, len(l) // 3):
            return l
    return f"exit code {rc}"


async def run_jsonl(
    cmd: list[str],
    stdin_lines: list[str] | None = None,
    timeout: float | None = 600,
    label: str | None = None,
) -> AsyncIterator[dict]:
    """Igual ao run(), mas faz yield de cada linha JSON do stdout.
    Se a ferramenta falhar ou não produzir JSON, expõe o stderr (em vez de
    fingir que 'não achou nada' — falha silenciosa esconde bug de config)."""
    rc, out, err = await run(cmd, stdin_lines, timeout)
    yielded = 0
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        yielded += 1
        yield obj

    if yielded == 0 and (rc not in (0, None) or err.strip()):
        tool = label or (cmd[0] if cmd else "?")
        msg = _pick_error_line(err, rc)
        print(f"      ⚠ {tool}: 0 resultados — {msg[:200]}", file=sys.stderr)


async def run_streaming(
    cmd: list[str],
    stdin_lines: list[str] | None = None,
    timeout: float | None = 600,
    label: str | None = None,
    on_stderr=None,
) -> list[dict]:
    """Como run_jsonl, mas lê o stderr AO VIVO (linha a linha) e repassa cada uma
    para `on_stderr` — usado p/ surfar o progresso do nuclei (-stats-json) no
    heartbeat enquanto varre. O stdout (findings JSONL) é coletado e devolvido no
    fim. Mantém o aviso de '0 resultados' e o tratamento de timeout do run_jsonl."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin_lines is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    objs: list[dict] = []
    err_tail: list[str] = []

    async def feed_stdin() -> None:
        if stdin_lines is None:
            return
        try:
            proc.stdin.write(("\n".join(stdin_lines) + "\n").encode())
            await proc.stdin.drain()
        finally:
            proc.stdin.close()

    async def read_stdout() -> None:
        async for raw in proc.stdout:
            line = raw.decode(errors="replace").strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    async def read_stderr() -> None:
        async for raw in proc.stderr:
            line = raw.decode(errors="replace").rstrip()
            if not line:
                continue
            # stats-json (-sj) NÃO é erro — não polui o err_tail (senão o
            # aviso de '0 resultados' dispara falso quando a tool acha 0).
            if not line.lstrip().startswith("{") and len(err_tail) < 50:
                err_tail.append(line)
            if on_stderr is not None:
                try:
                    on_stderr(line)
                except Exception:  # noqa: BLE001 — callback nunca derruba a run
                    pass

    try:
        await asyncio.wait_for(
            asyncio.gather(feed_stdin(), read_stdout(), read_stderr()), timeout
        )
        rc = await proc.wait()
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"timeout após {timeout:.0f}s sem terminar") from None

    if not objs and (rc not in (0, None) or err_tail):
        tool = label or (cmd[0] if cmd else "?")
        msg = _pick_error_line("\n".join(err_tail), rc)
        print(f"      ⚠ {tool}: 0 resultados — {msg[:200]}", file=sys.stderr)

    return objs
