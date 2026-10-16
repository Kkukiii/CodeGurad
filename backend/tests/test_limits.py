import pytest
from fastapi import HTTPException

from app.limits import enforce_instance_request_limit


def test_instance_rate_limit_is_bounded(monkeypatch):
    monkeypatch.setenv("REQUESTS_PER_MINUTE_PER_INSTANCE", "1")
    enforce_instance_request_limit("isolated-test-client")
    with pytest.raises(HTTPException) as error:
        enforce_instance_request_limit("isolated-test-client")
    assert error.value.status_code == 429