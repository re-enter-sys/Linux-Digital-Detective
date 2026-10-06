from pathlib import Path

from src.parsers.auth_parser import parse_auth_log
from src.timeline.builder import (
    Timeline,
    build_timeline,
)


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


def test_build_timeline():
    events = get_sample_events()

    timeline = build_timeline(events)

    assert isinstance(timeline, Timeline)
    assert timeline.event_count() == 8


def test_timeline_is_chronological():
    events = get_sample_events()

    timeline = build_timeline(events)

    timestamps = [
        event.timestamp
        for event in timeline.events
    ]

    assert timestamps == sorted(timestamps)


def test_timeline_start_time():
    events = get_sample_events()

    timeline = build_timeline(events)

    assert (
        timeline.start_time.strftime("%H:%M:%S")
        == "22:14:03"
    )


def test_timeline_end_time():
    events = get_sample_events()

    timeline = build_timeline(events)

    assert (
        timeline.end_time.strftime("%H:%M:%S")
        == "22:17:32"
    )


def test_timeline_duration():
    events = get_sample_events()

    timeline = build_timeline(events)

    assert timeline.duration_seconds == 209.0


def test_timeline_event_sequence():
    events = get_sample_events()

    timeline = build_timeline(events)

    data = timeline.to_dict()

    sequences = [
        event["sequence"]
        for event in data["events"]
    ]

    assert sequences == list(range(1, 9))


def test_timeline_gap_calculation():
    events = get_sample_events()

    timeline = build_timeline(events)

    data = timeline.to_dict()

    gaps = [
        event["gap_from_previous_seconds"]
        for event in data["events"]
    ]

    assert gaps[0] == 0.0
    assert gaps[1] == 4.0
    assert gaps[2] == 4.0
    assert gaps[3] == 4.0
    assert gaps[4] == 46.0
    assert gaps[5] == 1.0
    assert gaps[6] == 72.0
    assert gaps[7] == 78.0


def test_timeline_serialization():
    events = get_sample_events()

    timeline = build_timeline(events)

    data = timeline.to_dict()

    assert data["event_count"] == 8
    assert data["start_time"] is not None
    assert data["end_time"] is not None
    assert data["duration_seconds"] == 209.0
    assert len(data["events"]) == 8


def test_timeline_save_json(tmp_path):
    events = get_sample_events()

    timeline = build_timeline(events)

    output_file = (
        tmp_path
        / "timeline.json"
    )

    timeline.save_json(
        str(output_file)
    )

    assert output_file.exists()

    content = output_file.read_text(
        encoding="utf-8"
    )

    assert '"event_count": 8' in content
    assert '"SSH_AUTH_FAILURE"' in content
    assert '"SUDO_COMMAND"' in content


def test_timeline_add_event():
    events = get_sample_events()

    timeline = Timeline()

    # Add events deliberately out of chronological order.
    timeline.add_event(events[7])
    timeline.add_event(events[0])
    timeline.add_event(events[4])

    assert timeline.event_count() == 3

    timestamps = [
        event.timestamp
        for event in timeline.events
    ]

    assert timestamps == sorted(timestamps)


def test_timeline_string_output():
    events = get_sample_events()

    timeline = build_timeline(events)

    output = str(timeline)

    assert "LINUX DIGITAL DETECTIVE TIMELINE" in output
    assert "Events: 8" in output
    assert "SSH_AUTH_FAILURE" in output
    assert "SSH_AUTH_SUCCESS" in output
    assert "SUDO_COMMAND" in output
