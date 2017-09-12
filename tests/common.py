"""Utilities common to several different unit tests."""


class MockLambdaContext(object):
    """http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html"""
    def __init__(self, function_version: int = 1, time_limit_ms: int = 30000,
                 decrement_ms: int = 0) -> None:
        self.function_version = function_version
        self.time_limit_ms = time_limit_ms
        self.decrement_ms = decrement_ms

    def get_remaining_time_in_millis(self) -> int:
        """Decrements remaining time before returning."""
        self.time_limit_ms -= self.decrement_ms
        return self.time_limit_ms
