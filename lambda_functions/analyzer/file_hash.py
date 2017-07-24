"""Memory-efficient file hashing."""
import hashlib

MB = 2 ** 20  # ~ 1 million bytes


def _read_in_chunks(file_object, chunk_size=2*MB):
    """Read a file in fixed-size chunks (to minimize memory usage for large files).

    Args:
        file_object: An opened file-like object supporting read().
        chunk_size: [int] Max size (in bytes) of each file chunk.

    Yields:
        [string] file chunks, each of size at most chunk_size.
    """
    while True:
        chunk = file_object.read(chunk_size)
        if chunk:
            yield chunk
        else:
            return  # End of file.


def compute_hashes(file_path):
    """Compute SHA and MD5 hashes for the specified file object.

    The MD5 is only included to be compatible with other security tools.

    Args:
        file_path: [string] File path to be analyzed.

    Returns:
        String tuple (sha_hash, md5_hash).
    """
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with open(file_path, mode='rb') as file_object:
        for chunk in _read_in_chunks(file_object):
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()
