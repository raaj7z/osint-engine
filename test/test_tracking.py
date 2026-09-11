from src.models import Finding
from src.tracking.change_detector import detect_changes


def finding(
    value: str,
) -> Finding:

    return Finding(
        investigation_id="test",
        finding_type="username",
        value=value,
        source="test",
    )


def test_change_detector():

    result = detect_changes(
        [finding("old")],
        [finding("new")],
    )

    assert [
        item.value
        for item in result["added"]
    ] == ["new"]

    assert [
        item.value
        for item in result["removed"]
    ] == ["old"]
