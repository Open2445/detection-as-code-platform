"""Unit tests for the ingestion service."""
import json
import pytest

from app.services.ingestion import parse_log_file, ingest_logs


SAMPLE_ARRAY_JSON = json.dumps([
    {
        "EventID": 1,
        "Computer": "WORKSTATION-01",
        "UserName": "alice",
        "UtcTime": "2024-01-15T10:00:00Z",
        "EventData": {
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        },
    },
    {
        "EventID": 4688,
        "Computer": "SERVER-02",
        "SubjectUserName": "bob",
        "UtcTime": "2024-01-15T10:01:00Z",
        "CommandLine": "net user administrator",
    },
]).encode()

SAMPLE_NDJSON = b'\n'.join([
    json.dumps({"EventID": 3, "Computer": "HOST-01", "UtcTime": "2024-01-15T11:00:00Z"}).encode(),
    json.dumps({"EventID": 1, "Computer": "HOST-02", "UtcTime": "2024-01-15T11:01:00Z"}).encode(),
])

INVALID_JSON = b"not valid json {"


class TestParseLogFile:
    def test_parse_json_array(self):
        batch, records = parse_log_file(SAMPLE_ARRAY_JSON, "test.json")
        assert batch.filename == "test.json"
        assert batch.log_count == 2
        assert len(records) == 2

    def test_parse_ndjson(self):
        batch, records = parse_log_file(SAMPLE_NDJSON, "ndjson_test.json")
        assert batch.log_count == 2
        assert len(records) == 2

    def test_parse_single_object(self):
        single = json.dumps({"EventID": 1, "Computer": "HOST"}).encode()
        batch, records = parse_log_file(single, "single.json")
        assert batch.log_count == 1
        assert len(records) == 1

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_log_file(INVALID_JSON, "bad.json")


class TestIngestLogs:
    def test_ingest_creates_batch_and_entries(self, db):
        batch = ingest_logs(db, SAMPLE_ARRAY_JSON, "test.json")
        assert batch.id is not None
        assert batch.log_count == 2
        assert batch.status == "processed"

    def test_ingest_extracts_hostname(self, db):
        batch = ingest_logs(db, SAMPLE_ARRAY_JSON, "test2.json")
        from app.models.log import LogEntry
        entries = db.query(LogEntry).filter(LogEntry.batch_id == batch.id).all()
        hostnames = {e.hostname for e in entries}
        assert "WORKSTATION-01" in hostnames
        assert "SERVER-02" in hostnames

    def test_ingest_extracts_username(self, db):
        batch = ingest_logs(db, SAMPLE_ARRAY_JSON, "test3.json")
        from app.models.log import LogEntry
        entries = db.query(LogEntry).filter(LogEntry.batch_id == batch.id).all()
        usernames = {e.username for e in entries if e.username}
        assert "alice" in usernames

    def test_ingest_extracts_event_id(self, db):
        batch = ingest_logs(db, SAMPLE_ARRAY_JSON, "test4.json")
        from app.models.log import LogEntry
        entries = db.query(LogEntry).filter(LogEntry.batch_id == batch.id).all()
        event_ids = {e.event_id for e in entries}
        assert 1 in event_ids
        assert 4688 in event_ids

    def test_ingest_ndjson(self, db):
        batch = ingest_logs(db, SAMPLE_NDJSON, "ndjson.json")
        assert batch.log_count == 2

    def test_ingest_invalid_raises(self, db):
        with pytest.raises(ValueError):
            ingest_logs(db, INVALID_JSON, "bad.json")
