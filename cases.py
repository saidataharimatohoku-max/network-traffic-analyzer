"""Local SQLite case storage; capture evidence is immutable after case creation."""

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4


STATUSES = ("New", "Investigating", "Resolved")
DISPOSITIONS = ("Inconclusive", "Authorized activity", "Suspicious")


class CaseError(RuntimeError):
    pass


def default_database_path() -> Path:
    base = Path(os.environ["LOCALAPPDATA"]) if os.environ.get("LOCALAPPDATA") else Path.home()
    return base / "NetworkTrafficInvestigator" / "cases.sqlite3"


@dataclass(frozen=True)
class CaseDetails:
    title: str
    status: str = "New"
    disposition: str = "Inconclusive"
    assessment: str = ""
    root_cause: str = ""
    recommendation: str = ""

    def validate(self) -> None:
        if not all(isinstance(value, str) for value in asdict(self).values()):
            raise CaseError("Case investigation fields must be text.")
        if not self.title.strip() or len(self.title) > 200:
            raise CaseError("Case title must contain 1 to 200 characters.")
        if self.status not in STATUSES or self.disposition not in DISPOSITIONS:
            raise CaseError("Choose a supported case status and disposition.")
        if any(len(value) > 50_000 for value in
               (self.assessment, self.root_cause, self.recommendation)):
            raise CaseError("Each investigation field must be 50,000 characters or fewer.")


@dataclass(frozen=True)
class CaseSummary:
    id: str
    title: str
    status: str
    disposition: str
    created_at: str
    updated_at: str
    revision: int


@dataclass(frozen=True)
class Case:
    summary: CaseSummary
    details: CaseDetails
    snapshot: dict


@dataclass(frozen=True)
class CaseRevision:
    case_id: str
    revision: int
    recorded_at: str
    actor: str
    event: str
    details: CaseDetails


@dataclass(frozen=True)
class CaseArchive:
    case: Case
    history: tuple[CaseRevision, ...]


@dataclass(frozen=True)
class MergeConflict:
    case_id: str
    title: str
    reason: str


@dataclass(frozen=True)
class MergeResult:
    imported: int
    identical: int
    conflicts: tuple[MergeConflict, ...]


def validate_actor(actor: str) -> str:
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 100:
        raise CaseError("Analyst label must contain 1 to 100 characters.")
    return actor.strip()


class CaseStore:
    def __init__(self, path: Path | None = None):
        self.path = path if path is not None else default_database_path()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS cases (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL,
                        disposition TEXT NOT NULL,
                        assessment TEXT NOT NULL,
                        root_cause TEXT NOT NULL,
                        recommendation TEXT NOT NULL,
                        snapshot TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revision INTEGER NOT NULL
                    )
                """)
                had_history = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'case_history'"
                ).fetchone()
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS case_history (
                        case_id TEXT NOT NULL REFERENCES cases(id),
                        revision INTEGER NOT NULL,
                        recorded_at TEXT NOT NULL,
                        actor TEXT NOT NULL,
                        event TEXT NOT NULL,
                        details TEXT NOT NULL,
                        PRIMARY KEY (case_id, revision)
                    )
                """)
                if had_history is None:
                    for row in connection.execute("SELECT * FROM cases").fetchall():
                        self._record_revision(
                            connection, row["id"], row["revision"], row["updated_at"],
                            "Unknown (pre-history)", "Legacy baseline", self._details(row),
                        )
                yield connection
        except (sqlite3.Error, OSError) as exc:
            raise CaseError(
                f"Cannot access the case database at {self.path}: {exc}. "
                "Check folder permissions, free space, and database availability."
            ) from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _summary(row: sqlite3.Row) -> CaseSummary:
        return CaseSummary(row["id"], row["title"], row["status"], row["disposition"],
                           row["created_at"], row["updated_at"], row["revision"])

    @staticmethod
    def _details(row: sqlite3.Row) -> CaseDetails:
        details = CaseDetails(row["title"], row["status"], row["disposition"],
                              row["assessment"], row["root_cause"], row["recommendation"])
        details.validate()
        return details

    @staticmethod
    def _record_revision(connection: sqlite3.Connection, case_id: str, revision: int,
                         recorded_at: str, actor: str, event: str, details: CaseDetails) -> None:
        connection.execute(
            "INSERT INTO case_history VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, revision, recorded_at, actor, event, json.dumps(asdict(details))),
        )

    def _case(self, row: sqlite3.Row) -> Case:
        try:
            snapshot = json.loads(row["snapshot"])
        except json.JSONDecodeError as exc:
            raise CaseError("This case has unreadable evidence. Restore a database backup.") from exc
        if not isinstance(snapshot, dict) or snapshot.get("schema_version") != 2:
            raise CaseError("Unsupported evidence format. Open this case with a compatible app.")
        return Case(self._summary(row), self._details(row), snapshot)

    @staticmethod
    def _history(connection: sqlite3.Connection, case_id: str) -> tuple[CaseRevision, ...]:
        rows = connection.execute(
            "SELECT * FROM case_history WHERE case_id = ? ORDER BY revision", (case_id,),
        ).fetchall()
        revisions = []
        for row in rows:
            try:
                details = CaseDetails(**json.loads(row["details"]))
                details.validate()
            except (json.JSONDecodeError, TypeError) as exc:
                raise CaseError("This case has unreadable revision history.") from exc
            revisions.append(CaseRevision(case_id, row["revision"], row["recorded_at"],
                                           row["actor"], row["event"], details))
        if not revisions:
            raise CaseError("This case has no revision history. Restore a complete backup.")
        return tuple(revisions)

    def list_cases(self) -> list[CaseSummary]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, title, status, disposition, created_at, updated_at, revision "
                "FROM cases ORDER BY updated_at DESC, id"
            ).fetchall()
        return [self._summary(row) for row in rows]

    def get_case(self, case_id: str) -> Case:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row is None:
            raise CaseError("This case no longer exists. Refresh the saved-case list.")
        return self._case(row)

    def get_archive(self, case_id: str) -> CaseArchive:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                raise CaseError("This case no longer exists. Refresh the saved-case list.")
            return CaseArchive(self._case(row), self._history(connection, case_id))

    def list_archives(self) -> list[CaseArchive]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM cases ORDER BY id").fetchall()
            return [CaseArchive(self._case(row), self._history(connection, row["id"])) for row in rows]

    def create_case(self, details: CaseDetails, snapshot: dict, *,
                    actor: str = "Local analyst") -> Case:
        details.validate()
        actor = validate_actor(actor)
        details = CaseDetails(details.title.strip(), details.status, details.disposition,
                              details.assessment, details.root_cause, details.recommendation)
        if snapshot.get("schema_version") != 2:
            raise CaseError("Cannot save an unsupported evidence format.")
        try:
            serialized = json.dumps(snapshot, ensure_ascii=True, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise CaseError(f"Cannot serialize case evidence: {exc}") from exc
        case_id = str(uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            connection.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, details.title.strip(), details.status, details.disposition,
                 details.assessment, details.root_cause, details.recommendation,
                 serialized, now, now, 1),
            )
            self._record_revision(connection, case_id, 1, now, actor, "Created", details)
        return self.get_case(case_id)

    def update_case(self, case_id: str, details: CaseDetails, expected_revision: int, *,
                    actor: str = "Local analyst") -> Case:
        details.validate()
        actor = validate_actor(actor)
        details = CaseDetails(details.title.strip(), details.status, details.disposition,
                              details.assessment, details.root_cause, details.recommendation)
        now = datetime.now(timezone.utc).isoformat()
        with self._connection() as connection:
            result = connection.execute(
                "UPDATE cases SET title = ?, status = ?, disposition = ?, assessment = ?, "
                "root_cause = ?, recommendation = ?, updated_at = ?, revision = revision + 1 "
                "WHERE id = ? AND revision = ?",
                (details.title.strip(), details.status, details.disposition,
                 details.assessment, details.root_cause, details.recommendation, now,
                 case_id, expected_revision),
            )
            if result.rowcount != 1:
                raise CaseError(
                    "This case was changed elsewhere or removed. Reload it before saving; "
                    "your edits were not written."
                )
            self._record_revision(connection, case_id, expected_revision + 1, now,
                                  actor, "Updated", details)
        return self.get_case(case_id)

    def merge_archives(self, archives: list[CaseArchive], *, dry_run: bool = False) -> MergeResult:
        """Merge prevalidated archives; an existing case is never updated."""
        imported = identical = 0
        conflicts = []
        with self._connection() as connection:
            for archive in archives:
                case = archive.case
                summary = case.summary
                row = connection.execute("SELECT * FROM cases WHERE id = ?", (summary.id,)).fetchone()
                if row is not None:
                    local = CaseArchive(self._case(row), self._history(connection, summary.id))
                    if local == archive:
                        identical += 1
                    else:
                        conflicts.append(MergeConflict(
                            summary.id, summary.title,
                            f"Existing case differs (local revision {local.case.summary.revision}, "
                            f"backup revision {summary.revision}); not overwritten.",
                        ))
                    continue
                imported += 1
                if dry_run:
                    continue
                details = case.details
                connection.execute(
                    "INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (summary.id, details.title, details.status, details.disposition,
                     details.assessment, details.root_cause, details.recommendation,
                     json.dumps(case.snapshot, allow_nan=False), summary.created_at,
                     summary.updated_at, summary.revision),
                )
                for revision in archive.history:
                    self._record_revision(
                        connection, summary.id, revision.revision, revision.recorded_at,
                        revision.actor, revision.event, revision.details,
                    )
        return MergeResult(imported, identical, tuple(conflicts))
