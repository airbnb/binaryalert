#!/usr/bin/env python3
"""Command-line tool for easily managing BinaryAlert."""
import argparse
import os
import sys

from cli import __version__
from cli.manager import Manager


def main() -> None:
    """Main command dispatcher."""
    if not (sys.version_info.major == 3 and sys.version_info.minor in {6, 7}):
        print('ERROR: Python 3.6/7 is required, found Python {}.{}.{}'.format(
            sys.version_info.major, sys.version_info.minor, sys.version_info.micro))
        exit(1)

    manager = Manager()

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        'command', choices=sorted(manager.commands), help=manager.help, metavar='command')
    parser.add_argument(
        '--version', action='version', version='BinaryAlert v{}'.format(__version__))
    args = parser.parse_args()

    os.environ['TF_IN_AUTOMATION'] = '1'
    manager.run(args.command)


if __name__ == '__main__':
    main()
