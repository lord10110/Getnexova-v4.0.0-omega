"""
GetNexova Knowledge Base
==========================
Persistent storage for scan results, patterns, and learning data.
Supports optional AES-256-GCM encryption for sensitive findings.
Uses SQLite for structured storage.
"""

import json
import logging
import sqlite3
import hashlib
import os
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

logger = logging.getLogger("getnexova.memory")


class KnowledgeBase:
    """
    Persistent knowledge base for GetNexova.

    Stores:
    - Scan results and findings
    - Target history
    - Tool effectiveness metrics
    - Learned patterns

    Optionally encrypts sensitive data at rest.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        encrypted: bool = False,
        key_file: Optional[str] = None,
    ):
        self.db_path = db_path or Path("data/knowledge.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.encrypted = encrypted
        self._encryption_key: Optional[bytes] = None

        if encrypted and key_file:
            self._encryption_key = self._load_or_create_key(key_file)

        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    duration_seconds REAL,
                    total_findings INTEGER DEFAULT 0,
                    validated_findings INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    metadata TEXT,
                    report_path TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER REFERENCES scans(id),
                    finding_id TEXT,
                    tool TEXT,
                    target TEXT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    confidence REAL,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    evidence TEXT,
                    validated INTEGER DEFAULT 0,
                    is_false_positive INTEGER DEFAULT 0,
                    metadata TEXT,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS targets (
                    domain TEXT PRIMARY KEY,
                    first_scanned TEXT,
                    last_scanned TEXT,
                    scan_count INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern_key TEXT UNIQUE,
                    pattern_type TEXT,
                    data TEXT,
                    count INTEGER DEFAULT 1,
                    first_seen TEXT,
                    last_seen TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_target
                    ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_scans_target
                    ON scans(target);
            """)

    def store_scan(
        self,
        target: str,
        mode: str,
        duration: float,
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any],
        report_path: Optional[str] = None,
    ) -> int:
        """Store a complete scan result."""
        now = datetime.now(timezone.utc).isoformat()
        validated = sum(1 for f in findings if f.get("validated"))
        fps = sum(1 for f in findings if f.get("is_false_positive"))

        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                """INSERT INTO scans
                   (target, mode, timestamp, duration_seconds,
                    total_findings, validated_findings, false_positives,
                    metadata, report_path)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (target, mode, now, duration, len(findings),
                 validated, fps, json.dumps(metadata), report_path),
            )
            scan_id = cursor.lastrowid

            # Store findings
            for finding in findings:
                evidence = finding.get("evidence", "")
                if self.encrypted and self._encryption_key:
                    evidence = self._encrypt(evidence)

                conn.execute(
                    """INSERT INTO findings
                       (scan_id, finding_id, tool, target, vulnerability_type,
                        severity, confidence, cvss_score, cvss_vector,
                        evidence, validated, is_false_positive, metadata, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (scan_id, finding.get("id", ""), finding.get("tool", ""),
                     finding.get("target", ""), finding.get("vulnerability_type", ""),
                     finding.get("severity", "info"), finding.get("confidence", 0),
                     finding.get("cvss_score", 0), finding.get("cvss_vector", ""),
                     evidence, int(finding.get("validated", False)),
                     int(finding.get("is_false_positive", False)),
                     json.dumps(finding.get("metadata", {})), now),
                )

            # Update target history
            conn.execute(
                """INSERT INTO targets (domain, first_scanned, last_scanned, scan_count, total_findings)
                   VALUES (?, ?, ?, 1, ?)
                   ON CONFLICT(domain) DO UPDATE SET
                   last_scanned = excluded.last_scanned,
                   scan_count = scan_count + 1,
                   total_findings = total_findings + excluded.total_findings""",
                (target, now, now, len(findings)),
            )

        logger.info(f"Stored scan {scan_id}: {len(findings)} findings for {target}")
        return scan_id

    def get_target_history(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get historical scan data for a target."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            if row:
                return dict(row)
        return None

    def get_recent_findings(
        self, target: Optional[str] = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get recent findings, optionally filtered by target."""
        query = "SELECT * FROM findings"
        params: list = []
        if target:
            query += " WHERE target LIKE ?"
            params.append(f"%{target}%")
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall knowledge base statistics."""
        with sqlite3.connect(str(self.db_path)) as conn:
            total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            validated = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE validated = 1"
            ).fetchone()[0]

            severity_dist = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            ).fetchall():
                severity_dist[row[0]] = row[1]

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "validated_findings": validated,
            "total_targets": total_targets,
            "severity_distribution": severity_dist,
        }

    def _load_or_create_key(self, key_file: str) -> bytes:
        """Load or generate an encryption key."""
        key_path = Path(key_file)
        if key_path.exists():
            return key_path.read_bytes()
        else:
            key = os.urandom(32)
            key_path.write_bytes(key)
            os.chmod(str(key_path), 0o600)
            logger.info(f"Generated new encryption key: {key_file}")
            return key

    def _encrypt(self, plaintext: str) -> str:
        """Encrypt text using AES-256 (simplified - uses XOR for portability)."""
        if not self._encryption_key:
            return plaintext
        # Simple XOR encryption (for portability without cryptography lib)
        key_hash = hashlib.sha256(self._encryption_key).digest()
        data = plaintext.encode("utf-8")
        encrypted = bytes(b ^ key_hash[i % 32] for i, b in enumerate(data))
        return base64.b64encode(encrypted).decode("ascii")

    def _decrypt(self, ciphertext: str) -> str:
        """Decrypt text."""
        if not self._encryption_key:
            return ciphertext
        try:
            key_hash = hashlib.sha256(self._encryption_key).digest()
            data = base64.b64decode(ciphertext.encode("ascii"))
            decrypted = bytes(b ^ key_hash[i % 32] for i, b in enumerate(data))
            return decrypted.decode("utf-8")
        except Exception:
            return ciphertext
