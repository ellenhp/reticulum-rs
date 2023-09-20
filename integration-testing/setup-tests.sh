#!/bin/bash

# This script is used to partially automate setup for the integration tests. Run it from this directory.

rm -r test-venv
python3 -m venv test-venv
source test-venv/bin/activate
pip install -e ./Reticulum