"""In-memory boto3 client mocks to be used for testing."""
# This is similar to the moto library. Unfortunately, moto does not support complex Dynamo updates,
# has a limited feature set, and has some Python3 bugs. To keep it simple, we instead build only
# the simplest mocks we need.
from botocore.vendored.requests.adapters import HTTPAdapter


def restore_http_adapter(func):
    """Decorator to manually restore the botocore adapter in cases where moto does not."""
    # Due to https://github.com/spulec/moto/issues/1026, mocks are not always properly stopped.
    # This manually restores the mocked out HTTPAdapter library.

    def func_wrapper():
        """Remember HTTPAdapter.send before invoking the wrapped function."""
        real_adapter_send = HTTPAdapter.send
        func()
        HTTPAdapter.send = real_adapter_send
    func_wrapper.__doc__ = func.__doc__  # Replace docstring of inner function with the original.
    return func_wrapper


class MockLambdaContext(object):
    """http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html"""
    def __init__(self, function_version=1, time_limit_ms=30000):
        self.function_version = function_version
        self.time_limit_ms = time_limit_ms

    def get_remaining_time_in_millis(self):
        """Returns the original time limit (self.time_limit_ms)."""
        return self.time_limit_ms
