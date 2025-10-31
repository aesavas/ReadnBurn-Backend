class SecretNotAvailableError(Exception):
    """Raised when an operation is attempted on an unavailable secret."""

    pass


class SecretAlreadyViewedError(SecretNotAvailableError):
    """Raised when an operation is attempted on an already viewed secret."""

    pass


class SecretAlreadyDeletedError(SecretNotAvailableError):
    """Raised when an operation is attempted on an already deleted secret."""

    pass


class SecretDoesNotExistError(SecretNotAvailableError):
    """Raised when an operation is attempted on a non-existent secret."""

    pass


class SecretExpiredError(SecretNotAvailableError):
    """Raised when an operation is attempted on an expired secret."""

    pass
