"""Custom exceptions in the BinaryAlert CLI."""


class ManagerError(Exception):
    """Top-level exception for Manager errors."""


class InvalidConfigError(ManagerError):
    """BinaryAlert config is not valid."""


class TestFailureError(ManagerError):
    """Exception raised when a BinaryAlert test fails."""
