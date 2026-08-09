import pytest
from pydantic import ValidationError

from igris.core.config import Settings


def test_settings_load_explicit_values() -> None:
    settings = Settings(
        app_name="Igris Local",
        environment="test",
        log_level="DEBUG",
        max_upload_bytes=1024,
    )

    assert settings.app_name == "Igris Local"
    assert settings.environment == "test"
    assert settings.log_level == "DEBUG"
    assert settings.max_upload_bytes == 1024


def test_invalid_upload_limit_fails_validation() -> None:
    with pytest.raises(ValidationError):
        Settings(max_upload_bytes=0)


def test_empty_request_id_header_fails_validation() -> None:
    with pytest.raises(ValidationError):
        Settings(request_id_header=" ")

