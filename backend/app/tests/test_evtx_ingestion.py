"""Unit tests for EVTX parsing and ingestion."""
import json
import pytest
from app.services.ingestion import _xml_to_dict, parse_log_file, ingest_logs
from app.models.log import UploadBatch, LogEntry


SAMPLE_EVTX_XML = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{57707959-9547-4F78-A63E-877810F5D3D8}"/>
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-06-21T18:00:00.123456Z"/>
    <EventRecordID>1050</EventRecordID>
    <Execution ProcessID="2048" ThreadID="4096"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WORKSTATION-01</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-06-21 18:00:00.123</Data>
    <Data Name="ProcessGuid">{12345678-1234-1234-1234-123456789012}</Data>
    <Data Name="ProcessId">2048</Data>
    <Data Name="Image">C:\\Windows\\System32\\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -Enc ABC123DEF</Data>
    <Data Name="CurrentDirectory">C:\\Users\\Administrator\\</Data>
    <Data Name="User">CORP\\Administrator</Data>
    <Data Name="LogonId">0x3e7</Data>
  </EventData>
</Event>"""


class TestEvtxParsing:
    def test_xml_to_dict_conversion(self):
        result = _xml_to_dict(SAMPLE_EVTX_XML)

        # System fields
        assert result["System"]["EventID"] == 1
        assert result["System"]["Computer"] == "WORKSTATION-01"
        assert result["System"]["Channel"] == "Microsoft-Windows-Sysmon/Operational"
        assert result["System"]["Provider"]["Name"] == "Microsoft-Windows-Sysmon"

        # EventData fields
        assert result["EventData"]["Image"] == "C:\\Windows\\System32\\powershell.exe"
        assert result["EventData"]["User"] == "CORP\\Administrator"

        # Promoted top-level fields for PySigma
        assert result["EventID"] == 1
        assert result["Computer"] == "WORKSTATION-01"
        assert result["Image"] == "C:\\Windows\\System32\\powershell.exe"
        assert result["CommandLine"] == "powershell.exe -ExecutionPolicy Bypass -Enc ABC123DEF"
        assert result["User"] == "CORP\\Administrator"

    def test_invalid_xml_returns_empty_dict(self):
        assert _xml_to_dict("<invalid xml") == {}


def test_ingest_evtx_parsed_records(db):
    """Test persisting EVTX parsed records to database."""
    parsed_record = _xml_to_dict(SAMPLE_EVTX_XML)

    batch = UploadBatch(filename="test_sample.evtx", log_count=1, status="processed")
    db.add(batch)
    db.flush()

    entry = LogEntry(
        batch_id=batch.id,
        event_id=parsed_record.get("EventID"),
        hostname=parsed_record.get("Computer"),
        username=parsed_record.get("User"),
        raw_json=json.dumps(parsed_record),
    )
    db.add(entry)
    db.commit()

    saved_batch = db.get(UploadBatch, batch.id)
    assert saved_batch is not None
    assert saved_batch.filename == "test_sample.evtx"

    saved_entries = db.query(LogEntry).filter(LogEntry.batch_id == batch.id).all()
    assert len(saved_entries) == 1
    assert saved_entries[0].event_id == 1
    assert saved_entries[0].hostname == "WORKSTATION-01"
    assert saved_entries[0].username == "CORP\\Administrator"

    raw_data = json.loads(saved_entries[0].raw_json)
    assert raw_data["CommandLine"] == "powershell.exe -ExecutionPolicy Bypass -Enc ABC123DEF"

