#!/bin/bash

python3 -m venv test-venv
source test-venv/bin/activate

python server.py --server --config $PWD/reticulum_config