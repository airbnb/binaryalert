"""Update YARA rules cloned from remote sources."""
from fnmatch import fnmatch
import json
import os
import shutil
import subprocess
import tempfile
from typing import Generator, List, Optional

RULES_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
REMOTE_RULE_SOURCES = os.path.join(RULES_DIR, 'rule_sources.json')


def _copy_required(path: str, include: Optional[List[str]], exclude: Optional[List[str]]) -> bool:
    """Return True if the given filepath should be copied, given the include/exclude directives."""
    # 1) If the path is not in the "include" list (which defaults to everything), skip it.
    if include and not any(fnmatch(path, pattern) for pattern in include):
        return False

    # 2) If the path is specifically excluded, skip it.
    if exclude and any(fnmatch(path, pattern) for pattern in exclude):
        return False

    # 3) If the path is not a .yar or .yara file, skip it.
    lower_filename = path.lower()
    if not lower_filename.endswith('.yar') and not lower_filename.endswith('.yara'):
        return False

    return True


def _files_to_copy(
        cloned_repo_root: str, include: Optional[List[str]],
        exclude: Optional[List[str]]) -> Generator[str, None, None]:
    """Yields string paths to copy, each relative to the root of the repo."""
    for root, _, files in os.walk(cloned_repo_root):
        for filename in files:
            # Compute path *relative to the root of its repository*
            relative_path = os.path.relpath(os.path.join(root, filename), start=cloned_repo_root)
            if _copy_required(relative_path, include, exclude):
                yield relative_path


def _clone_repo(url: str, include: Optional[List[str]], exclude: Optional[List[str]]) -> int:
    """Clone the given repo and copy only the YARA files from the specified paths.

    Returns:
        Number of files copied.
    """
    # Shallow clone entire repo into a temp directory.
    cloned_repo_root = os.path.join(tempfile.gettempdir(), os.path.basename(url))
    if os.path.exists(cloned_repo_root):
        shutil.rmtree(cloned_repo_root)
    subprocess.check_call(['git', 'clone', '--quiet', '--depth', '1', url, cloned_repo_root])

    # Remove existing rules in target folder before copying (in case upstream rules were deleted).
    if '//' in url:
        target_repo_root = os.path.join(RULES_DIR, url.split('//')[1])
    else:
        target_repo_root = os.path.join(RULES_DIR, url.split('@')[1].replace(':', '/', 1))
    if os.path.exists(target_repo_root):
        shutil.rmtree(target_repo_root)

    # Copy each applicable file into the target folder in the rules/ directory.
    files_copied = 0
    for relative_path in _files_to_copy(cloned_repo_root, include, exclude):
        # Create all of the intermediate directories, if they don't already exist.
        os.makedirs(os.path.join(target_repo_root, os.path.dirname(relative_path)), exist_ok=True)
        src = os.path.join(cloned_repo_root, relative_path)
        dst = os.path.join(target_repo_root, relative_path)
        shutil.copy(src, dst)
        files_copied += 1

    # Remove temporary cloned repo.
    shutil.rmtree(cloned_repo_root)

    return files_copied


def clone_remote_rules() -> None:
    """Clone YARA rules from all remote sources into the rules/ directory."""
    with open(REMOTE_RULE_SOURCES) as f:
        rule_sources = json.load(f)

    num_repos = len(rule_sources['repos'])
    total_files_copied = 0
    for count, source in enumerate(rule_sources['repos'], start=1):
        print('[{}/{}] Cloning {}... '.format(count, num_repos, source['url']), end='', flush=True)
        files_copied = _clone_repo(source['url'], source.get('include'), source.get('exclude'))
        print('{} YARA {} copied'.format(files_copied, 'file' if files_copied == 1 else 'files'))
        total_files_copied += files_copied

    print('Done! {} YARA {} cloned from {} {}.'.format(
        total_files_copied, 'file' if total_files_copied == 1 else 'files',
        num_repos, 'repository' if num_repos == 1 else 'repositories'))
