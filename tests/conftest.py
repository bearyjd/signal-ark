from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from signal_ark.validate import ValidationResult, validate_plaintext, validator_available

REQUIRE_VALIDATOR_ENV = "SIGNAL_ARK_REQUIRE_VALIDATOR"
UNAVAILABLE_MESSAGE = "libsignal validator unavailable: run `npm ci --prefix tools/validator`"


def _fail_unavailable(*_args: object, **_kwargs: object) -> ValidationResult:
    pytest.fail(UNAVAILABLE_MESSAGE)


@pytest.fixture
def validator() -> Callable[..., ValidationResult]:
    if validator_available():
        return validate_plaintext
    if os.environ.get(REQUIRE_VALIDATOR_ENV) == "1":
        return _fail_unavailable
    pytest.skip(UNAVAILABLE_MESSAGE)
