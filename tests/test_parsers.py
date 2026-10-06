from pathlib import Path

from src.parsers.auth_parser import parse_auth_log
from src.timeline.events import Event


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SAMPLE_AUTH_LOG = (
    PROJECT_ROOT
    / "data"
    / "sample"
    / "auth.log"
)


def test_auth_log_parser_returns_events():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    assert events
    assert all(isinstance(event, Event) for event in events)


def test_auth_log_parser_event_count():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    assert len(events) == 8


def test_failed_ssh_logins():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    failed = [
        event
        for event in events
        if event.event_type == "SSH_AUTH_FAILURE"
    ]

    assert len(failed) == 4

    for event in failed:
        assert event.user == "admin"
        assert event.source_ip == "192.0.2.50"
        assert event.severity == "MEDIUM"


def test_successful_ssh_login():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    successful = [
        event
        for event in events
        if event.event_type == "SSH_AUTH_SUCCESS"
    ]

    assert len(successful) == 1

    event = successful[0]

    assert event.user == "admin"
    assert event.source_ip == "192.0.2.50"


def test_session_events():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    opened = [
        event
        for event in events
        if event.event_type == "SSH_SESSION_OPEN"
    ]

    closed = [
        event
        for event in events
        if event.event_type == "SSH_SESSION_CLOSE"
    ]

    assert len(opened) == 1
    assert len(closed) == 1

    assert opened[0].user == "admin"
    assert closed[0].user == "admin"


def test_sudo_event():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    sudo_events = [
        event
        for event in events
        if event.event_type == "SUDO_COMMAND"
    ]

    assert len(sudo_events) == 1

    event = sudo_events[0]

    assert event.user == "admin"
    assert event.command == "/bin/bash"
    assert event.metadata["target_user"] == "root"
    assert event.metadata["privilege_change"] is True


def test_events_are_chronological():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    timestamps = [
        event.timestamp
        for event in events
    ]

    assert timestamps == sorted(timestamps)


def test_event_ids_are_unique():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    event_ids = [
        event.event_id
        for event in events
    ]

    assert len(event_ids) == len(set(event_ids))


def test_event_serialization():
    events = parse_auth_log(
        str(SAMPLE_AUTH_LOG),
        year=2026,
    )

    event = events[0]

    data = event.to_dict()

    assert data["event_id"] == event.event_id
    assert data["source"] == "auth.log"
    assert data["event_type"] == "SSH_AUTH_FAILURE"
    assert data["source_ip"] == "192.0.2.50"
