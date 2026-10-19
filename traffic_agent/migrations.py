"""Transactional schema upgrades. Original databases are backed up before any DDL."""
from datetime import datetime, timezone
from contextlib import closing
from pathlib import Path
import os
import re
import sqlite3
import time
import uuid

from .connection_instances import stable_id

SCHEMA_VERSION = 4


def prepare_backup(db, path):
    version = db.execute('PRAGMA user_version').fetchone()[0]
    if version > SCHEMA_VERSION:
        raise RuntimeError('数据库版本高于当前程序，禁止降级打开')
    populated = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone()
    if version == SCHEMA_VERSION or not populated or str(path) == ':memory:':
        return None
    directory = Path(path).resolve().parent / 'backups'
    directory.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = directory / f'{Path(path).name}.v{version}.{stamp}.{uuid.uuid4().hex[:8]}.sqlite'
    deadline = time.monotonic() + 30
    def progress(*_):
        if time.monotonic() > deadline:
            raise RuntimeError('数据库备份超时，未开始迁移；请停止其他写入程序后重试')
    try:
        with closing(sqlite3.connect(backup)) as target:
            db.backup(target, pages=256, progress=progress, sleep=.05)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('备份完整性校验失败，未开始迁移')
        with backup.open('r+b') as stream:
            os.fsync(stream.fileno())
    except Exception:
        backup.unlink(missing_ok=True)
        raise
    return str(backup)


def restore_copy(backup, destination):
    """Restore to a NEW path only, avoiding overwrite and stale WAL sidecars.

    Close the application before selecting the restored database. Keep the
    failed/current DB and its WAL together until newer data has been recovered.
    """
    backup, destination = Path(backup).resolve(), Path(destination).resolve()
    if any(Path(str(destination) + suffix).exists() for suffix in ('', '-wal', '-shm')):
        raise ValueError('恢复目标必须是不存在的新路径；禁止覆盖现有数据库或WAL')
    with closing(sqlite3.connect(backup.as_uri() + '?mode=ro', uri=True)) as source:
        if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('备份数据库损坏')
        # Exclusive filesystem creation protects against accidental overwrite.
        with destination.open('xb'):
            pass
        with closing(sqlite3.connect(destination)) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('恢复副本校验失败，请保留原备份')
    return str(destination)


def migrate(db):
    """Caller owns BEGIN IMMEDIATE/COMMIT, including the legacy schema bootstrap."""
    def legacy_id(sid, a, ap, b, bp, protocol):
        left, right = sorted(((a, ap), (b, bp)))
        return stable_id(sid, (*left, *right, protocol), 'legacy')
    db.create_function('legacy_connection_id', 6, legacy_id)
    for table in ('session_flows', 'session_connection_metrics', 'session_applications'):
        columns = [r['name'] for r in db.execute(f'PRAGMA table_info({table})')]
        if 'connection_id' in columns:
            continue
        sql = db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?', ('table', table)).fetchone()[0]
        index_sql = [r[0] for r in db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (table,))]
        new_name = table + '_migration'
        sql = re.sub(r'\b' + table + r'\b', new_name, sql, count=1)
        # The final table constraint is the tuple identity constraint in all
        # three old tables; add the generation to it, retaining all old columns.
        sql = re.sub(r'((?:PRIMARY KEY|UNIQUE)\([^)]*)(\)\s*\)\s*)$', r'\1,connection_id\2', sql)
        closing = sql.rfind(')')
        extra = ", connection_id TEXT NOT NULL DEFAULT ''"
        if table == 'session_connection_metrics':
            extra += (", instance_kind TEXT NOT NULL DEFAULT 'untracked_aggregate'"
                      ", boundary_reason TEXT NOT NULL DEFAULT 'metadata_without_tracker'"
                      ", uncertainty_flags INTEGER NOT NULL DEFAULT 512"
                      ", handshake_basis TEXT NOT NULL DEFAULT 'not_observed'")
        # Column declarations must precede table constraints in SQLite.
        constraint = re.search(r',\s*(?:PRIMARY KEY|UNIQUE)\(', sql)
        pos = constraint.start() if constraint else closing
        sql = sql[:pos] + extra + sql[pos:]
        before = db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
        db.execute(sql)
        endpoints = 'src,sport,dst,dport,protocol' if table == 'session_flows' else 'a,ap,b,bp,protocol'
        additions = ',connection_id'
        values = f',legacy_connection_id(session_id,{endpoints})'
        if table == 'session_connection_metrics':
            additions += ',instance_kind,boundary_reason,uncertainty_flags,handshake_basis'
            values += ", 'legacy_aggregate', 'pre_instance_schema', 256, 'legacy_flags_only'"
        names = ','.join(columns)
        db.execute(f'INSERT INTO {new_name}({names}{additions}) SELECT {names}{values} FROM {table}')
        if db.execute(f'SELECT count(*) FROM {new_name}').fetchone()[0] != before:
            raise RuntimeError('迁移行数校验失败')
        db.execute(f'DROP TABLE {table}')
        db.execute(f'ALTER TABLE {new_name} RENAME TO {table}')
        for statement in index_sql:
            db.execute(statement)
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS metric_instance_id ON session_connection_metrics(session_id,connection_id)')
    db.execute('CREATE INDEX IF NOT EXISTS flow_instance ON session_flows(session_id,connection_id,bucket)')
    db.execute('CREATE INDEX IF NOT EXISTS application_instance ON session_applications(session_id,connection_id,bucket)')
    from .incident_store import create_schema
    create_schema(db)
    from .jobs import create_schema as create_job_schema
    create_job_schema(db)
    if db.execute('PRAGMA foreign_key_check').fetchone() is not None:
        raise RuntimeError('事件迁移外键校验失败')
    db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
        raise RuntimeError('迁移完整性校验失败')
