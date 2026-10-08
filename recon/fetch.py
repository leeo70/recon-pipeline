"""
Fetch HTTP para o estágio de JS.

Fica no Python de propósito: o escopo já foi aplicado upstream e o inventário de
URLs vive aqui. Fetch é I/O-bound; concorrência via threads (stdlib) resolve.
Alvos de recon costumam ter TLS quebrado, então não verificamos cert.

Crawl de <script src>: SPAs (Next.js etc.) carregam o código em bundles que o gau
não conhece (ex.: /_next/static/chunks/). crawl_script_srcs baixa as páginas vivas,
extrai os <script src>/<link href=*.js> e resolve contra a URL FINAL (pós-redirect),
expondo o JS real do app ao motor.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import ssl
import urllib.parse
import urllib.request
from pathlib import Path

MAX_BYTES = 12 * 1024 * 1024  # corta JS-bomba
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# regexes construídas via chr() p/ não embutir sequência de aspas mistas literal
_DQ, _SQ = chr(34), chr(39)
_Q = "[" + _DQ + _SQ + "]"        # classe: aspa dupla ou simples
_NQ = "[^" + _DQ + _SQ + "]"      # classe: qualquer coisa menos aspa
_SOURCEMAP_RE = re.compile(("[#@]\\s*sourceMappingURL=([^\\s" + _SQ + _DQ + "]+)").encode())
_SCRIPT_SRC_RE = re.compile(("<script[^>]+\\bsrc=" + _Q + "(" + _NQ + "+)" + _Q).encode(), re.I)
_LINK_JS_RE = re.compile(("<link[^>]+\\bhref=" + _Q + "(" + _NQ + "+\\.js" + _NQ + "*)" + _Q).encode(), re.I)


def _get(url: str, headers: dict, timeout: int = 15) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
        return getattr(r, "status", 200), r.read(MAX_BYTES)


def _get_final(url: str, headers: dict, timeout: int = 15) -> tuple[str, bytes]:
    """Como _get, mas devolve a URL FINAL (pós-redirect) p/ resolver relativos."""
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
        return r.geturl(), r.read(MAX_BYTES)


def _name_for(url: str, suffix: str = ".js") -> str:
    return hashlib.sha1(url.encode()).hexdigest()[:16] + suffix


def find_sourcemap_url(js_url: str, body: bytes) -> str | None:
    m = _SOURCEMAP_RE.search(body[-2048:])
    if not m:
        return None
    ref = m.group(1).decode(errors="replace")
    if ref.startswith("data:"):
        return None
    return urllib.parse.urljoin(js_url, ref)


async def crawl_script_srcs(
    page_urls: list[str],
    headers: dict | None = None,
    concurrency: int = 10,
    allows=None,
) -> list[str]:
    """Baixa cada página HTML viva, extrai <script src> e <link href=*.js>,
    resolve contra a URL FINAL (pós-redirect) e devolve as URLs de JS in-scope.
    `allows` é o Scope.allows do programa: JS de host fora de escopo é ignorado."""
    headers = headers or {"User-Agent": "bug-bounty-recon/0.1"}
    sem = asyncio.Semaphore(concurrency)
    found: set[str] = set()

    async def one(page: str) -> None:
        async with sem:
            try:
                final_url, body = await asyncio.to_thread(_get_final, page, headers)
            except Exception:
                return
            for raw in _SCRIPT_SRC_RE.findall(body) + _LINK_JS_RE.findall(body):
                ref = raw.decode(errors="replace")
                ju = urllib.parse.urljoin(final_url, ref)
                path = ju.split("?", 1)[0].split("#", 1)[0]
                if not path.lower().endswith(".js"):
                    continue
                host = urllib.parse.urlparse(ju).hostname or ""
                if allows and not allows(host):
                    continue
                found.add(ju)

    await asyncio.gather(*(one(u) for u in page_urls))
    return sorted(found)


async def fetch_js(
    urls: list[str],
    dest: Path,
    concurrency: int = 20,
    headers: dict | None = None,
) -> list[dict]:
    """Baixa cada JS + seu .map (quando referenciado). Retorna entradas de
    manifest {path, url} prontas para o motor Rust."""
    dest.mkdir(parents=True, exist_ok=True)
    headers = headers or {"User-Agent": "bug-bounty-recon/0.1"}
    sem = asyncio.Semaphore(concurrency)
    manifest: list[dict] = []

    async def one(url: str) -> None:
        async with sem:
            try:
                _, body = await asyncio.to_thread(_get, url, headers)
            except Exception:
                return
            js_path = dest / _name_for(url, ".js")
            js_path.write_bytes(body)
            manifest.append({"path": str(js_path), "url": url})

            sm_url = find_sourcemap_url(url, body)
            if sm_url:
                try:
                    _, sm_body = await asyncio.to_thread(_get, sm_url, headers)
                    sm_path = dest / _name_for(url, ".js.map")
                    sm_path.write_bytes(sm_body)
                    manifest.append({"path": str(sm_path), "url": url})
                except Exception:
                    pass

    await asyncio.gather(*(one(u) for u in urls))
    return manifest
