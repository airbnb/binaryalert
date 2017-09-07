"""Mock Lambda context."""


class MockLambdaContext(object):
    """http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html"""
    def __init__(self, function_version=1, time_limit_ms=30000):
        self.function_version = function_version
        self.time_limit_ms = time_limit_ms

    def get_remaining_time_in_millis(self):
        """Returns the original time limit (self.time_limit_ms)."""
        return self.time_limit_ms
