ARG PYTHON_VERSION=3.10.13

FROM python:$PYTHON_VERSION

# Configure environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 
ENV  APP_PATH=/app


# Avoid unnecessary packages
RUN echo 'APT::Install-Suggests "0";' >> /etc/apt/apt.conf.d/00-docker
RUN echo 'APT::Install-Recommends "0";' >> /etc/apt/apt.conf.d/00-docker

# Install essential packages
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update \
    && apt-get install -y sudo nvi net-tools tree \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
# upgrade pip
RUN pip install --upgrade pip

# Install Poetry
RUN pip install 'poetry==1.6.1'
RUN poetry config virtualenvs.create false

# Set working directory and install python libraries 
WORKDIR $APP_PATH
COPY ./poetry.lock ./pyproject.toml ./
RUN poetry install --no-interaction

# Copy code
COPY ./app $APP_PATH/
