#!/bin/bash
export PYTHONPATH=$PYTHONPATH:.
uv run python -m app.worker
