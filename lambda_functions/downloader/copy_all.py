"""Copy *all* binaries from CarbonBlack into S3, using multiprocess producer-consumer queue."""
# This is a one-off script which backfills BinaryAlert with all CarbonBlack binaries.
# Using dozens of processes, this will copy about 1000 binaries / minute.
#
# Usage: export CARBON_BLACK_URL='...' && \
#        export ENCRYPTED_CARBON_BLACK_API_TOKEN='...' && \
#        export TARGET_S3_BUCKET='...' && \
#        python3 copy_all.py 2>&1 | tee copy.log
import logging
import multiprocessing
import queue

import cbapi

if __package__:
    from lambda_functions.downloader import main
else:
    import main

LOG_FORMAT = '%(asctime)s %(levelname)-6s %(message)s'
LOG_LEVEL = logging.DEBUG

NUM_CONSUMERS = 32  # Number of consumer threads executing copy tasks (optimized by experiment).
MAX_TASK_QUEUE_SIZE = NUM_CONSUMERS * 20  # Maximum number of tasks in the queue at any time.


class CopyTask(object):
    """A Task to copy a single binary from CarbonBlack into the BinaryAlert S3 bucket."""

    def __init__(self, index: int, md5: str):
        """Initialize a Task with the binary's information.

        Args:
            index: Binary's index in the CarbonBlack enumeration.
                Helps give the user a sense of progress.
            md5: Binary MD5, used as the key to retrieve from CarbonBlack.
        """
        self.index = index
        self.md5 = md5

    def __call__(self):
        """Execute the copy task."""
        main.download_lambda_handler({'md5': self.md5}, None)

    def __str__(self):
        """Use the index and MD5 in the string representation."""
        return 'CopyTask [#{}] MD5:{}'.format(self.index, self.md5)


class Consumer(multiprocessing.Process):
    """A Consumer grabs Tasks from the shared queue and executes them asynchronously."""

    def __init__(self, task_queue: multiprocessing.JoinableQueue,
                 failed_queue: multiprocessing.Queue):
        """Create a Consumer with shared communication queues.

        Args:
            task_queue: Shared queue of Tasks to perform.
                The Consumer will process tasks until it sees a None task.
            failed_queue: Shared queue containing the MD5 hashes of every binary which
                failed to upload.
        """
        super(Consumer, self).__init__()
        self.task_queue = task_queue
        self.failed_queue = failed_queue

        # Each process needs its own logger to avoid race conditions.
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(LOG_LEVEL)

    def run(self):
        """Grab Tasks and execute them until an empty task signals a shutdown."""
        while True:
            # Grab the next task from the queue.
            copy_task = self.task_queue.get()

            # Exit if we encounter an empty task.
            if copy_task is None:
                self.logger.info('[%s] Exiting', self.name)
                self.task_queue.task_done()
                return

            # Execute the copy task, logging any failure.
            self.logger.info('[%s] Executing %s', self.name, copy_task)
            try:
                copy_task()
            except Exception:  # pylint: disable=broad-except
                # This is a long-running job: catch any Exception, mark as failure, and continue.
                self.logger.exception('[%s] %s', self.name, copy_task)
                self.failed_queue.put(copy_task.md5)
            finally:
                # Mark the task as complete and move on to the next one.
                self.task_queue.task_done()


def copy_all_binaries():
    """Copy every binary in CarbonBlack into the BinaryAlert input S3 bucket."""
    # Create the logger.
    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger('carbon_black_copy')
    logger.setLevel(LOG_LEVEL)

    # Create process communication queues.
    tasks = multiprocessing.JoinableQueue(MAX_TASK_QUEUE_SIZE)  # CopyTasks to execute.
    failures = multiprocessing.Queue()  # A list of MD5s which failed to copy.

    # Start the consumer processes.
    logger.info('Start %d consumers', NUM_CONSUMERS)
    consumers = [Consumer(tasks, failures) for _ in range(NUM_CONSUMERS)]
    for worker in consumers:
        worker.start()

    # Enumerate all CarbonBlack binaries and enqueue a CopyTask for each one.
    # This main thread is the producer, enqueuing CopyTasks as fast as it can enumerate the
    # binaries (which actually takes a relatively long time).
    # As soon as a CopyTask is enqueued, any worker process (Consumer) can immediately execute it.
    for index, binary in enumerate(main.CARBON_BLACK.select(cbapi.response.models.Binary).all()):
        copy_task = CopyTask(index, binary.md5)
        logger.debug('Enqueuing %s', copy_task)
        tasks.put(copy_task)  # Block if necessary until the task queue has space.

    # Add a "poison pill" for each Consumer, marking the end of the task queue.
    for _ in range(NUM_CONSUMERS):
        tasks.put(None)

    # Wait for all of the tasks to finish.
    tasks.join()
    logger.info('All CopyTasks Finished!')

    # Grab the MD5s which failed to copy, if any.
    failed_md5s = []
    while True:
        try:
            failed_md5s.append(failures.get_nowait())
        except queue.Empty:
            break

    # Log all offending MD5s, one per line.
    if failed_md5s:
        logger.error(
            '%d %s failed to copy: \n%s', len(failed_md5s),
            'binary' if len(failed_md5s) == 1 else 'binaries', '\n'.join(sorted(failed_md5s)))


if __name__ == '__main__':
    copy_all_binaries()
