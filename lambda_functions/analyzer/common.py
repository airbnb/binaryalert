"""Common resources shared among the analyzer components."""
import logging
import os

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

# Define the name and location of the compiled YARA rules file.
COMPILED_RULES_FILENAME = 'compiled_yara_rules.bin'
THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
COMPILED_RULES_FILEPATH = os.path.join(THIS_DIRECTORY, COMPILED_RULES_FILENAME)
