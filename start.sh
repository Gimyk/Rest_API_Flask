#!/bin/bash
poetry run python -m gunicorn -w 2 --reload --bind=127.0.0.1:8000 app.run:app

