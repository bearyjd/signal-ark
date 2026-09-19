from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from signal_ark.validate import ValidationResult, validate_plaintext, validator_available

REQUIRE_VALIDATOR_ENV = "SIGNAL_ARK_REQUIRE_VALIDATOR"
UNAVAILABLE_MESSAGE = "libsignal validator unavailable: run `npm ci --prefix tools/validator`"


@pytest.fixture
def validator() -> Callable[..., ValidationResult]:
    if not validator_available():
        if os.environ.get(REQUIRE_VALIDATOR_ENV) == "1":
            pytest.fail(UNAVAILABLE_MESSAGE)
        pytest.skip(UNAVAILABLE_MESSAGE)
    return validate_plaintext
