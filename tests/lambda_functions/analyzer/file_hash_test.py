"""Unit tests for file_hash.py (uses fake filesystem)."""
import hashlib
import math

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import file_hash


class FileUtilsTest(fake_filesystem_unittest.TestCase):
    """Unit tests for file utilities."""
    # pylint: disable=no-member,protected-access

    def setUp(self):
        """Enable the fake filesystem and write some test files."""
        self.setUpPyfakefs()

        self.fs.create_file('/empty_file', contents='')

        self._test_contents = 'Hello, World! This is a test file.'
        self._file_size = len(self._test_contents)
        self.fs.create_file('/hello_world', contents=self._test_contents)

    def test_read_in_chunks(self):
        """File chunking works with different size chunks."""
        for chunk_size in [1, 2, 3, self._file_size - 1, self._file_size, self._file_size + 1]:
            chunks = list(file_hash._read_in_chunks(open('/hello_world'), chunk_size=chunk_size))
            # Check the number of chunks, size of each chunk, and their reconstructed content.
            self.assertEqual(int(math.ceil(self._file_size / chunk_size)), len(chunks))
            self.assertTrue(all(1 <= len(chunk) <= chunk_size for chunk in chunks))
            self.assertEqual(self._test_contents, ''.join(chunks))

    def test_read_in_chunks_empty_file(self):
        """File chunking returns an empty list if no file contents."""
        chunks = list(file_hash._read_in_chunks(open('/empty_file')))
        self.assertEqual([], chunks)

    def test_compute_hashes(self):
        """Test hash functions for basic file."""
        sha, md5 = file_hash.compute_hashes('/hello_world')
        self.assertEqual(hashlib.sha256(self._test_contents.encode('utf-8')).hexdigest(), sha)
        self.assertEqual(hashlib.md5(self._test_contents.encode('utf-8')).hexdigest(), md5)

    def test_compute_hashes_empty_file(self):
        """Test hash functions for an empty file."""
        sha, md5 = file_hash.compute_hashes('/empty_file')
        self.assertEqual(hashlib.sha256().hexdigest(), sha)
        self.assertEqual(hashlib.md5().hexdigest(), md5)
