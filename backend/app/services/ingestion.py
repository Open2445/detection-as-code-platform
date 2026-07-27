"""Log ingestion service — parse uploaded JSON and EVTX logs and persist to DB."""
import io
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import Evtx.Evtx as evtx
from sqlalchemy.orm import Session

from app.models.log import UploadBatch, LogEntry

logger = logging.getLogger(__name__)

# Field aliases for extracting common metadata from different log formats
_HOSTNAME_KEYS = ["Computer", "computer", "hostname", "Hostname", "host", "ComputerName"]
_USERNAME_KEYS = [
    "User", "user", "username", "Username", "UserName",
    "SubjectUserName", "TargetUserName",
]
_TIMESTAMP_KEYS = [
    "UtcTime", "TimeCreated", "timestamp", "Timestamp", "EventTime",
    "SystemTime", "time", "Time",
]
_EVENT_ID_KEYS = ["EventID", "eventId", "event_id", "Id"]


def _xml_to_dict(xml_str: str) -> Dict[str, Any]:
    """Convert Windows Event XML string into a structured dictionary."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return {}

    def strip_ns(tag: str) -> str:
        return tag.split('}')[-1] if '}' in tag else tag

    result: Dict[str, Any] = {}
    system_dict: Dict[str, Any] = {}
    event_data_dict: Dict[str, Any] = {}

    for child in root:
        ctag = strip_ns(child.tag)
        if ctag == "System":
            for elem in child:
                etag = strip_ns(elem.tag)
                if etag == "Provider":
                    name = elem.attrib.get("Name")
                    guid = elem.attrib.get("Guid")
                    prov_dict = {}
                    if name:
                        prov_dict["Name"] = name
                    if guid:
                        prov_dict["Guid"] = guid
                    system_dict["Provider"] = prov_dict if prov_dict else (name or "")
                elif etag == "TimeCreated":
                    system_dict["TimeCreated"] = elem.attrib.get("SystemTime", "")
                elif etag == "Execution":
                    system_dict["Execution"] = dict(elem.attrib)
                elif etag == "Security":
                    system_dict["Security"] = dict(elem.attrib)
                else:
                    text = elem.text or ""
                    if etag == "EventID":
                        try:
                            system_dict[etag] = int(text)
                        except ValueError:
                            system_dict[etag] = text
                    else:
                        system_dict[etag] = text
        elif ctag in ("EventData", "UserData"):
            for elem in child:
                etag = strip_ns(elem.tag)
                name = elem.attrib.get("Name")
                text = elem.text or ""
                if name:
                    event_data_dict[name] = text
                elif text:
                    event_data_dict[etag] = text
                else:
                    sub_dict = {}
                    for sub in elem:
                        stag = strip_ns(sub.tag)
                        sname = sub.attrib.get("Name") or stag
                        sub_dict[sname] = sub.text or ""
                    if sub_dict:
                        event_data_dict[etag] = sub_dict

    result["System"] = system_dict
    result["EventData"] = event_data_dict

    # Promote EventData and System fields to top level for PySigma rule evaluation
    for k, v in event_data_dict.items():
        result[k] = v
    for k, v in system_dict.items():
        if k not in result:
            result[k] = v

    return result


def parse_evtx_bytes(content: bytes) -> List[Dict[str, Any]]:
    """Parse EVTX binary log content into a list of log dictionaries."""
    records = []
    try:
        buf = io.BytesIO(content)
        with evtx.Evtx(buf) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    d = _xml_to_dict(xml_str)
                    if d:
                        records.append(d)
                except Exception as exc:
                    logger.warning("Error parsing EVTX record: %s", exc)
                    continue
    except Exception as exc:
        raise ValueError(f"Failed to parse EVTX file: {exc}") from exc

    return records


def _extract_field(data: Dict[str, Any], keys: List[str]) -> Optional[Any]:
    """Try multiple key names to extract a field from the log dict."""
    for key in keys:
        if key in data:
            return data[key]
        # Check nested EventData / System
        for nested_key in ("EventData", "System", "UserData"):
            nested = data.get(nested_key, {})
            if isinstance(nested, dict) and key in nested:
                return nested[key]
    return None


def _parse_timestamp(raw: Any) -> Optional[datetime]:
    """Attempt to parse a timestamp string into datetime."""
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    ts_str = str(raw).strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def _parse_event_id(raw: Any) -> Optional[int]:
    """Parse event ID to int."""
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


def parse_log_file(content: bytes, filename: str) -> Tuple[UploadBatch, List[Dict]]:
    """
    Parse uploaded JSON or EVTX log file content.

    Accepts:
      - Native binary Windows Event Log (.evtx) files
      - A JSON array of event objects: [{ ... }, { ... }]
      - A newline-delimited JSON (NDJSON) file

    Returns:
      (UploadBatch stub, list of parsed dicts)
    """
    is_evtx = filename.lower().endswith(".evtx") or content.startswith(b"ElfFile\x00")

    if is_evtx:
        data = parse_evtx_bytes(content)
    else:
        text = content.decode("utf-8", errors="replace").strip()
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                data = [data]
            elif not isinstance(data, list):
                raise ValueError("Expected JSON array or object")
        except json.JSONDecodeError:
            # Try NDJSON
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            try:
                data = [json.loads(ln) for ln in lines]
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON format: {exc}") from exc

    batch = UploadBatch(filename=filename, log_count=len(data), status="processed")
    return batch, data


def ingest_logs(db: Session, content: bytes, filename: str) -> UploadBatch:
    """
    Parse a JSON log file and persist all entries to the database.

    Args:
        db:       SQLAlchemy session.
        content:  Raw bytes of the uploaded file.
        filename: Original filename.

    Returns:
        The created UploadBatch with log_count populated.
    """
    batch, records = parse_log_file(content, filename)
    db.add(batch)
    db.flush()  # get batch.id before inserting children

    entries = []
    for record in records:
        if not isinstance(record, dict):
            continue

        hostname = _extract_field(record, _HOSTNAME_KEYS)
        username = _extract_field(record, _USERNAME_KEYS)
        raw_ts = _extract_field(record, _TIMESTAMP_KEYS)
        raw_eid = _extract_field(record, _EVENT_ID_KEYS)

        entry = LogEntry(
            batch_id=batch.id,
            event_id=_parse_event_id(raw_eid),
            hostname=str(hostname)[:255] if hostname else None,
            username=str(username)[:255] if username else None,
            timestamp=_parse_timestamp(raw_ts),
            raw_json=json.dumps(record),
        )
        entries.append(entry)

    db.bulk_save_objects(entries)
    db.commit()
    db.refresh(batch)
    return batch
