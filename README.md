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
   (aai-backend) uv sync

   ```bash
   uv sync
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
