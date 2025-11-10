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
   uv sync
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

# Database management

The deployed service uses a Postgres database on AWS RDS (provisioned automatically by the
infrastructure stack). In order to generate migrations for the database locally,
we use a Postgres docker container to generate migrations against.

At runtime the task receives database connection details through environment variables
(`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`) sourced from AWS Secrets Manager.

After making any changes to the database models, after ensuring that Docker is runnning on your local machine, 
run the `generate_migrations.py` script to create migrations:

```shell
python generate_migrations.py -m <migration_name_of_your_choice>
```

and commit them to git. Once your updated code has been
deployed on AWS, you can connect to the container via
the [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html).
Run `aws sso login` first, then `aws ecs execute-command`
to access a shell in the container:

```shell
aws ecs execute-command \
--cluster <cluster-id> \
--task <task-id> \
--container FastAPIContainer \
--command "/bin/sh" \
--interactive
```

and run the migrations:

```shell
uv run alembic upgrade head
```

## Populating the Database on your Local Machine
1. Remove the exisiting database (if exists)
```bash
cd aai-backend
rm database.db
```

2. Create the database once
```bash
uv run fastapi dev
```

3. Sync Auth0 to local database
```bash
uv run python run_scheduler.py --immediate
```

4. Start the database locally
```bash
uv run fastapi dev main.py
```

# Job scheduler

We use the `apscheduler` library to schedule recurring jobs. Currently
this is used to synchronize user information from Auth0 to the AAI
database. You can run the job scheduler locally using:

```shell
uv run python run_scheduler.py
```

Note that for small jobs that run on-demand, e.g. sending a notification email when a user
signs up, you can use FastAPI's built-in [background tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/)
within the FastAPI app, instead of using the dedicated job scheduler.

# Deployment

Currently the service is deployed to AWS via the CDK scripts in `deploy/`,
and updated on each commit to `main`.

Secrets/configuration variables for the deployment are stored in the
GitHub Secrets for the repository.

The service deploys two containers (which both use the same image/Python environment):

* The FastAPI app
* The `apscheduler` job scheduler

# Database Schema Diagram Update
When the database models are changed, the database schema diagram in [`db_diagram.svg`](./db_diagram.svg) should be updated to reflect the changes.

### Generating the Database Schema Diagram

1. The `aai-backend/scripts/generate_db_diagram.py` script generates a database schema diagram from the SQLAlchemy models defined in the codebase, when a models are added, removed, or modified, the `models` module should be updated accordingly.

2. To generate an updated database schema diagram, run the following command:

   ```shell
   bash generate_db_diagram.sh
   ```

   The updated diagram will be saved in [`db_diagram.svg`](./db_diagram.svg).  See [this pull request](https://github.com/AustralianBioCommons/aai-backend/pull/85) as an example.


## Documents to be updated
Please update the following documents if there are changes to the database schema:
- [AAI User Database Technical Design Document](https://docs.google.com/document/d/1xECcTqXH9ykXBCEESBSg43SOMncXT6Zayi5FwqvCT4Y/edit?tab=t.0#heading=h.sj9060dgy5fu)
