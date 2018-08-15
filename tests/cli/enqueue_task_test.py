"""Unit tests for cli/enqueue_task.py"""
# pylint: disable=no-self-use,protected-access
from multiprocessing import JoinableQueue
import time
from typing import Any, Dict
import unittest
from unittest import mock

import boto3

from cli import enqueue_task


class MockQueue:
    """Mock SQS queue which fails half of the messages it sends."""

    def __init__(self):
        self._calls = []

    def send_messages(self, **kwargs) -> Dict[str, Any]:
        """Even messages send successfully, odd are failures"""
        entries = kwargs['Entries']
        self._calls.append(entries)
        result = {
            'Successful': [],
            'Failed': []
        }

        for i, entry in enumerate(entries):
            if i % 2 == 0:
                result['Successful'].append({'Id': entry['Id']})
            else:
                result['Failed'].append({'Id': entry['Id']})
        return result


class MockTask:
    """Mock executable task for worker process"""

    @staticmethod
    def run(queue: Any) -> None:
        pass


class EnqueueTaskTest(unittest.TestCase):
    """Unit tests for EnqueueTask class."""

    @mock.patch.object(time, 'sleep')
    def test_task_run(self, mock_sleep: mock.MagicMock) -> None:
        """Execute the task - messages send to queue, retrying on failure"""
        queue = MockQueue()
        task = enqueue_task.EnqueueTask(['A', 'B', 'C', 'D', 'E'])
        task.run(queue)

        # Failed messages should be retried
        expected = [
            [
                {'Id': '0', 'MessageBody': 'A'},
                {'Id': '1', 'MessageBody': 'B'},
                {'Id': '2', 'MessageBody': 'C'},
                {'Id': '3', 'MessageBody': 'D'},
                {'Id': '4', 'MessageBody': 'E'},
            ],
            [
                {'Id': '0', 'MessageBody': 'B'},
                {'Id': '1', 'MessageBody': 'D'},
            ],
            [
                {'Id': '0', 'MessageBody': 'D'},
            ]
        ]
        self.assertEqual(expected, queue._calls)
        mock_sleep.assert_called()


class WorkerTest(unittest.TestCase):
    """Unit tests for Worker class."""

    @mock.patch.object(boto3, 'resource')
    def test_worker_run(self, mock_resource: mock.MagicMock) -> None:
        """A worker process should iterate over the task queue"""
        task_queue = JoinableQueue()
        worker = enqueue_task.Worker('queue_name', task_queue)
        mock_resource.assert_called()

        # Add mock task to queue, followed by None
        task_queue.put(MockTask())
        task_queue.put(None)

        # Worker process should terminate and the task queue should be empty
        worker.run()
        task_queue.join()
