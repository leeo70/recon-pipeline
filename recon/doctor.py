"""
recon.doctor — valida que cada ferramenta configurada é a binária CERTA.

    python -m recon.doctor exemplo.yaml

Pega o footgun clássico do Kali: o `httpx` do ProjectDiscovery vs a lib Python
`httpx` (mesmo nome, CLI incompatível). Rode antes do primeiro recon num
ambiente novo — falha de binário some silenciosa e custa horas.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import yaml

DEFAULT_TOOLS = ["subfinder", "dnsx", "httpx", "gau", "nuclei"]


def _resolve(binary: str) -> str | None:
    if "/" in binary:
        return binary if Path(binary).exists() else None
    return shutil.which(binary)


def _run(cmd, stdin=None, timeout=10):
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001
        return None, "", str(e)


def _check_httpx(path: str) -> tuple[bool, str]:
    """PD httpx lê de stdin e ecoa a URL com esquema. A lib python imprime
    'Usage: httpx [OPTIONS] URL'."""
    _, out, err = _run([path, "-silent"], stdin="example.com\n")
    blob = out + err
    if "Usage: httpx [OPTIONS] URL" in blob or "Missing argument" in blob:
        return False, "✗ é a LIB PYTHON httpx — instale o ProjectDiscovery httpx"
    if "example.com" in out:
        return True, "ProjectDiscovery httpx"
    _, out, err = _run([path, "-version"])
    if "Usage:" in (out + err):
        return False, "✗ parece a lib python httpx"
    return True, "ok (heurística)"


def main(argv=None) -> int:
    cfg_path = (argv or sys.argv[1:])[0] if (argv or sys.argv[1:]) else "config.yaml"
    cfg = yaml.safe_load(open(cfg_path))
    tools = dict(cfg.get("tools", {}))
    for t in DEFAULT_TOOLS:
        tools.setdefault(t, t)

    print(f"── doctor: {cfg_path} ──")
    ok_all = True
    for name, binary in tools.items():
        path = _resolve(binary)
        if not path:
            print(f"  ✗ {name:11} não encontrado: {binary}")
            ok_all = False
            continue
        note = ""
        if name == "httpx":
            good, note = _check_httpx(path)
            ok_all &= good
            mark = "✓" if good else "✗"
        else:
            mark = "✓"
        print(f"  {mark} {name:11} {path}  {note}")

    eng = cfg.get("js_secrets", {}).get("binary")
    if eng:
        path = _resolve(eng)
        print(f"  {'✓' if path else '✗'} {'js-secrets':11} {path or eng}"
              f"{'' if path else '  (compile: cargo build --release)'}")
        ok_all &= bool(path)

    print("\n" + ("✓ tudo certo — pode rodar" if ok_all
                  else "✗ corrija os itens acima antes de rodar"))
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
