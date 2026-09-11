from src.engine import OSINTEngine
from src.input import make_investigation


def test_engine_runs_seed_identifiers():

    investigation = make_investigation(
        username="ExampleUser",
        domain="example.com",
        ip="192.0.2.10",
    )

    result = OSINTEngine().run(
        investigation
    )

    assert result.investigation_id

    assert len(
        result.findings
    ) >= 3

    assert not result.errors
