"""Worker task for adding things to a queue."""
from multiprocessing import JoinableQueue, Process
import time
from typing import List

import boto3


class EnqueueTask:
    """A Task to send a batch of records to SQS."""

    def __init__(self, messages: List[str]) -> None:
        """Initialize a Task with up to 10 SQS message entries."""
        self.messages = messages

    def run(self, sqs_queue: boto3.resource) -> None:
        """Send messages to SQS."""
        while self.messages:
            response = sqs_queue.send_messages(Entries=[
                {'Id': str(i), 'MessageBody': message}
                for i, message in enumerate(self.messages)
            ])

            if not response.get('Failed'):
                return

            # There were some failed messages, put them back and retry in a few seconds
            self.messages = [
                self.messages[int(failure['Id'])]
                for failure in response['Failed']
            ]
            time.sleep(2)


class Worker(Process):
    """Worker processes consumes S3 versions from the task queue and processes them."""

    def __init__(self, sqs_queue_name: str, task_queue: JoinableQueue) -> None:
        """Create a new worker process.

        Args:
            sqs_queue_name: Name of the target SQS queue
            task_queue: Thread-safe queue of EnqueueTasks to complete
        """
        super().__init__()
        self._task_queue = task_queue
        self._queue = boto3.resource('sqs').get_queue_by_name(QueueName=sqs_queue_name)

    def run(self) -> None:
        """Consume tasks from the task queue until an empty task is found."""
        while True:
            task = self._task_queue.get()

            if task is None:
                self._task_queue.task_done()
                return

            task.run(self._queue)
            self._task_queue.task_done()
