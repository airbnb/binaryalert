"""Update YARA rules cloned from remote sources."""
import os
import shutil
import subprocess
import tempfile

RULES_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
REMOTE_RULE_SOURCES = {
    'https://github.com/Neo23x0/signature-base.git': ['yara'],
    'https://github.com/YARA-Rules/rules.git': ['CVE_Rules']
}


def update_github_rules() -> None:
    """Update YARA rules cloned from GitHub."""
    for url, folders in REMOTE_RULE_SOURCES.items():
        # Clone repo into a temporary directory.
        print('Cloning YARA rules from {}/{}...'.format(url, folders))
        cloned_repo_root = os.path.join(tempfile.gettempdir(), os.path.basename(url))
        if os.path.exists(cloned_repo_root):
            shutil.rmtree(cloned_repo_root)
        subprocess.check_call(['git', 'clone', '--depth', '1', url, cloned_repo_root])

        # Copy each specified folder into the target rules directory.
        for folder in folders:
            source = os.path.join(cloned_repo_root, folder)
            destination = os.path.join(RULES_DIR, url.split('//')[1], folder)
            if os.path.exists(destination):
                # Remove existing rules in this folder before copying
                # (in case upstream rules were deleted).
                shutil.rmtree(destination)
            shutil.copytree(source, destination)

        shutil.rmtree(cloned_repo_root)  # Remove temporary cloned repo.


if __name__ == '__main__':
    update_github_rules()
