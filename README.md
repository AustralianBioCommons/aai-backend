# AAI Backend

The backend library between Auth0 and the AAI portal front end. Technical design document for this project lives in [this Google doc](https://docs.google.com/document/d/1W3-7Hme08M-b4kwMvcQoUscznVNxtOldxuKYPPRhBFE/edit?tab=t.0).

## Requirements

Ensure you have the following installed:

- python 3.13+
- uv ([installation instructions](https://github.com/astral-sh/uv#installation))

## Installation

Follow these steps to set up the project:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/AustralianBioCommons/aai-backend.git
   cd aai-backend
   ```

2. **Set Up a Virtual Environment**:
   Create and activate a virtual environment:

   ```bash
   uv venv
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   uv pip install
   ```

   For dev:
   ```bash
   uv sync --extra dev
   ```

4. **Install pre-commit**:
   ```bash
   pre-commit install
   ```

## Run the Application

Use `uv` to run the FastAPI application:

```bash
uv run fastapi dev main.py
```

## Run Tests

Execute the test suite using `pytest`:

```bash
uv run pytest
```
## Run the Linter

This command will automatically fix issues where possible:

```bash
uv run -- ruff check . --fix
```

## Manually run pre-commit
```bash
pre-commit run --all-files
```

# Deployment

Currently the service is deployed to AWS via the CDK scripts in `deploy/`,
and updated on each commit to `main`.

Secrets/configuration variables for the deployment are stored in the
GitHub Secrets for the repository.
