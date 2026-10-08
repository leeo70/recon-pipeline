"""
Camada de persistência (SQLite).

Toda a graça do recon contínuo está aqui: cada upsert devolve se a linha é
NOVA ou apenas foi vista de novo. Assim a pipeline notifica só o que mudou
desde a última execução, em vez de te spammar com o escopo inteiro.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY,
    program     TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY,
    program    TEXT NOT NULL,
    hostname   TEXT NOT NULL,
    source     TEXT,
    resolved   INTEGER DEFAULT 0,
    ip         TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(program, hostname)
);

CREATE TABLE IF NOT EXISTS http_services (
    id             INTEGER PRIMARY KEY,
    program        TEXT NOT NULL,
    url            TEXT NOT NULL,
    host           TEXT,
    port           INTEGER,
    status_code    INTEGER,
    title          TEXT,
    tech           TEXT,
    cdn            TEXT,
    content_length INTEGER,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS urls (
    id         INTEGER PRIMARY KEY,
    program    TEXT NOT NULL,
    url        TEXT NOT NULL,
    source     TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE(program, url)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    program     TEXT NOT NULL,
    template_id TEXT,
    severity    TEXT,
    name        TEXT,
    matched_at  TEXT,
    raw         TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE(program, template_id, matched_at)
);

CREATE TABLE IF NOT EXISTS secrets (
    id             INTEGER PRIMARY KEY,
    program        TEXT NOT NULL,
    kind           TEXT,
    rule           TEXT,
    severity       TEXT,
    value          TEXT,
    source_url     TEXT,
    from_sourcemap INTEGER DEFAULT 0,
    sourcemap_file TEXT,
    line           INTEGER,
    verify_status  TEXT,
    verify_detail  TEXT,
    verified_at    TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE(program, rule, value, source_url)
);
"""


class DB:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Adiciona colunas novas em bancos criados por versões anteriores."""
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(secrets)")}
        for col in ("verify_status", "verify_detail", "verified_at"):
            if col not in cols:
                self.conn.execute(f"ALTER TABLE secrets ADD COLUMN {col} TEXT")

    # ---- ciclo de vida da run -------------------------------------------
    def start_run(self, program: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs (program, started_at) VALUES (?, ?)",
            (program, _now()),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at = ? WHERE id = ?", (_now(), run_id)
        )
        self.conn.commit()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Transação única — use para inserir lotes grandes de uma vez."""
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ---- upsert genérico -------------------------------------------------
    def _upsert(self, table: str, key_cols: list[str], values: dict) -> bool:
        """
        Insere ou atualiza. Retorna True se a linha é NOVA (não existia).
        Em update, só mexe em last_seen + nas colunas não-chave.
        """
        now = _now()
        where = " AND ".join(f"{c} = ?" for c in key_cols)
        key_vals = [values[c] for c in key_cols]

        row = self.conn.execute(
            f"SELECT id FROM {table} WHERE {where}", key_vals
        ).fetchone()

        if row is None:
            cols = list(values.keys()) + ["first_seen", "last_seen"]
            placeholders = ", ".join("?" for _ in cols)
            self.conn.execute(
                f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})",
                list(values.values()) + [now, now],
            )
            return True

        # já existe: atualiza last_seen e campos voláteis (status, title, etc.)
        update_cols = [c for c in values if c not in key_cols]
        set_clause = ", ".join(f"{c} = ?" for c in update_cols + ["last_seen"])
        self.conn.execute(
            f"UPDATE {table} SET {set_clause} WHERE id = ?",
            [values[c] for c in update_cols] + [now, row["id"]],
        )
        return False

    # ---- helpers por tipo (devolvem só os NOVOS) ------------------------
    def add_asset(self, program: str, hostname: str, source: str = "") -> bool:
        return self._upsert(
            "assets", ["program", "hostname"],
            {"program": program, "hostname": hostname, "source": source},
        )

    def mark_resolved(self, program: str, hostname: str, ip: str) -> None:
        self.conn.execute(
            "UPDATE assets SET resolved = 1, ip = ?, last_seen = ? "
            "WHERE program = ? AND hostname = ?",
            (ip, _now(), program, hostname),
        )

    def add_http(self, program: str, **kw) -> bool:
        kw["program"] = program
        return self._upsert("http_services", ["program", "url"], kw)

    def add_url(self, program: str, url: str, source: str = "") -> bool:
        return self._upsert(
            "urls", ["program", "url"],
            {"program": program, "url": url, "source": source},
        )

    def add_finding(self, program: str, **kw) -> bool:
        kw["program"] = program
        return self._upsert(
            "findings", ["program", "template_id", "matched_at"], kw
        )

    def add_secret(self, program: str, **kw) -> bool:
        kw["program"] = program
        return self._upsert(
            "secrets", ["program", "rule", "value", "source_url"], kw
        )

    def urls_like(self, program: str, suffix: str) -> list[str]:
        return [
            r["url"]
            for r in self.conn.execute(
                "SELECT url FROM urls WHERE program = ? AND url LIKE ?",
                (program, f"%{suffix}"),
            )
        ]

    def unverified_secrets(self, program: str) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT id, rule, value, source_url, severity FROM secrets "
            "WHERE program = ? AND kind = 'secret' AND verify_status IS NULL",
            (program,),
        ))

    def set_verify(self, secret_id: int, status: str, detail: str) -> None:
        self.conn.execute(
            "UPDATE secrets SET verify_status = ?, verify_detail = ?, "
            "verified_at = ? WHERE id = ?",
            (status, detail, _now(), secret_id),
        )

    # ---- leituras que os estágios consomem ------------------------------
    def hostnames(self, program: str, resolved_only: bool = False) -> list[str]:
        q = "SELECT hostname FROM assets WHERE program = ?"
        if resolved_only:
            q += " AND resolved = 1"
        return [r["hostname"] for r in self.conn.execute(q, (program,))]

    def live_urls(self, program: str) -> list[str]:
        return [
            r["url"]
            for r in self.conn.execute(
                "SELECT url FROM http_services WHERE program = ?", (program,)
            )
        ]

    def scannable_urls(self, program: str, skip_status=None) -> list[str]:
        """URLs vivas que VALEM scan: pula paredes de WAF (403) e hosts mortos
        (502/503/504), que só geram erro e ruído no nuclei. status NULL é mantido
        (host respondeu de algum jeito; melhor errar pro lado de escanear)."""
        skip = set(skip_status or (403, 502, 503, 504))
        return [
            r["url"]
            for r in self.conn.execute(
                "SELECT url, status_code FROM http_services WHERE program = ?",
                (program,),
            )
            if r["status_code"] not in skip
        ]

    def close(self) -> None:
        self.conn.close()
