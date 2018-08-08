"""Custom exceptions in the BinaryAlert CLI."""


class ManagerError(Exception):
    """Top-level exception for Manager errors."""
    pass


class InvalidConfigError(ManagerError):
    """BinaryAlert config is not valid."""
    pass


class TestFailureError(ManagerError):
    """Exception raised when a BinaryAlert test fails."""
    pass
