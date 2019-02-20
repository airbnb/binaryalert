#!/usr/bin/env bash
printf "~~~~~~~~~~ [1] Bandit Security Linting ~~~~~~~~~~\n" &&
bandit -r . &&  # Configuration in .bandit

printf "\n~~~~~~~~~~ [2] Mypy Type Checking ~~~~~~~~~~\n" &&
mypy cli lambda_functions rules *.py --disallow-untyped-defs --ignore-missing-imports --warn-unused-ignores &&

printf "\n~~~~~~~~~~ [3] Unit Tests ~~~~~~~~~~\n" &&
coverage run manage.py unit_test &&

printf "\n~~~~~~~~~~ [4] Measure Coverage ~~~~~~~~~~\n" &&
coverage report &&  # Required coverage threshold specified in .coveragerc

printf "\n~~~~~~~~~~ [5] Pylint ~~~~~~~~~~\n" &&
pylint --init-hook="import sys; sys.setrecursionlimit(2000)" cli lambda_functions rules tests *.py -j 1 &&  # Config in .pylintrc. Max recursion needed in python3.7

printf "\n~~~~~~~~~~ [6] Build Documentation ~~~~~~~~~~\n" &&
sphinx-build -W docs/source docs/build &&

printf "\nSUCCESS: ALL TESTS PASSED!\n"
