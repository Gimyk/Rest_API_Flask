#!/bin/bash
poetry run python -m gunicorn -w 1 app.run:app

