class JobShieldException(Exception):
    """Base exception for expected application errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "APPLICATION_ERROR",
    ) -> None:
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class InvalidInputException(JobShieldException):
    """Raised when user-provided input is invalid."""

    def __init__(self, message: str = "Invalid input.") -> None:
        super().__init__(
            message=message,
            error_code="INVALID_INPUT",
        )