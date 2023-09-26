# Use ARG for Python version
ARG PYTHON_VERSION=3.10.13
FROM python:$PYTHON_VERSION

# Configure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 
ENV APP_PATH=/app

# Install essential packages and upgrade pip
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y --no-install-recommends sudo nvi net-tools tree \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip \
    && pip install 'poetry==1.6.1'

# Configure poetry
RUN poetry config virtualenvs.create false

# Set working directory
WORKDIR $APP_PATH

# Copy only the poetry lock and pyproject.toml first to leverage Docker cache
COPY ./poetry.lock ./pyproject.toml ./
# Install python libraries
RUN poetry install --no-interaction

# Finally, copy the rest of the code (this layer will only be rebuilt if the code changes)
COPY ./app $APP_PATH/

