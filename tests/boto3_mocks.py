"""In-memory boto3 client mocks to be used for testing."""
# This is similar to the moto library. Unfortunately, moto does not support complex Dynamo updates,
# has a limited feature set, and has some Python3 bugs. To keep it simple, we instead build only
# the simplest mocks we need.
import collections
import io


class MockLambdaContext(object):
    """http://docs.aws.amazon.com/lambda/latest/dg/python-context-object.html"""
    def __init__(self, function_version=1, time_limit_ms=30000):
        self.function_version = function_version
        self.time_limit_ms = time_limit_ms

    def get_remaining_time_in_millis(self):
        """Returns the original time limit (self.time_limit_ms)."""
        return self.time_limit_ms


class MockCloudwatchCient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/cloudwatch.html#client"""
    def __init__(self):
        # Maps namespace to list of published metric data.
        self.metric_data = collections.defaultdict(list)

    def put_metric_data(self, **kwargs):
        """Published metric data is added to an in-memory list."""
        self.metric_data[kwargs['Namespace']].extend(kwargs['MetricData'])


class MockDynamoItem(object):
    """Stores original item values and a list of update strings."""
    def __init__(self, key_value_dict):
        self.key_value_dict = key_value_dict
        self.updates = []

    def update(self, update_expression):
        """Append a new update to the item."""
        self.updates.append(update_expression)


class MockDynamoTable(object):
    """Supports only String, StringSet, Map, and List."""
    def __init__(self, table_name, hash_key, range_key):
        """Creates mock dynamo table with numeric range key."""
        self.table_name = table_name
        self.hash_key = hash_key
        self.range_key = range_key
        self.items = {}  # Maps composite key to MockDynamoItem.

    def _composite_key(self, item):
        """Create a tuple composite key out of an item's attributes."""
        return item[self.hash_key]['S'], item[self.range_key]['N']

    def put_item(self, item):
        """Add a new Dynamo item (dict of key-value pairs)."""
        self.items[self._composite_key(item)] = MockDynamoItem(item)

    def query(self, hash_key_value):
        """Return all original item values for the given SHA (updates are NOT applied)."""
        return {'Items': [item.key_value_dict for item in self.items.values() if
                          item.key_value_dict[self.hash_key]['S'] == hash_key_value]}

    def update_item(self, key_expr, update_expression):
        """Append a new update to the item with the given hash/range key."""
        self.items[self._composite_key(key_expr)].update(update_expression)


class MockDynamoDBClient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/dynamodb.html#client"""
    def __init__(self, table_name, hash_key, range_key):
        """Create boto3.client('dynamodb') with a single pre-existing table."""
        self.tables = {table_name: MockDynamoTable(table_name, hash_key, range_key)}

    def put_item(self, **kwargs):
        """Put a new item in the table."""
        table = self.tables[kwargs['TableName']]
        table.put_item(kwargs['Item'])

    def query(self, **kwargs):
        """Get item details by SHA256."""
        return self.tables[kwargs['TableName']].query(
            kwargs['ExpressionAttributeValues'][':sha']['S'])

    def update_item(self, **kwargs):
        """Update an existing item in the table (appends rather than replaces)."""
        table = self.tables[kwargs['TableName']]
        # Replace attribute values in update expression.
        update_expr = kwargs['UpdateExpression']
        for attr_key, attr_value in kwargs.get('ExpressionAttributeValues', {}).items():
            update_expr = update_expr.replace(attr_key, str(attr_value))
        table.update_item(kwargs['Key'], update_expr)


class MockS3Client(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/s3.html#S3.Client"""
    def __init__(self, bucket_name, object_key, file_contents, file_metadata):
        """Create boto3.client('s3'), pre-populated with test data."""
        self.buckets = {bucket_name: {object_key: (file_contents, file_metadata)}}

    def get_object(self, **kwargs):
        """Return object contents as bytesIO."""
        file_contents, file_metadata = self.buckets[kwargs['Bucket']][kwargs['Key']]
        return {
            'Body': io.BytesIO(file_contents.encode('utf-8')),
            'Metadata': file_metadata
        }


class MockSNSClient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/sns.html#client"""
    def __init__(self):
        self.topics = collections.defaultdict(list)  # Maps topic arn to list of publications.

    def publish(self, **kwargs):
        """Record an SNS publication in the history."""
        self.topics[kwargs['TopicArn']].append(kwargs)


class MockSQSClient(object):
    """http://boto3.readthedocs.io/en/latest/reference/services/sqs.html#client"""
    def __init__(self, queue_url, receipts):
        self.queues = {queue_url: receipts}

    def delete_message_batch(self, **kwargs):
        """Delete a batch of SQS message receipts."""
        for entry in kwargs['Entries']:
            self.queues[kwargs['QueueUrl']].remove(entry['ReceiptHandle'])
