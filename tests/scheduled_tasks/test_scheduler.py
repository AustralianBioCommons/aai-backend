from types import SimpleNamespace
from unittest.mock import ANY

from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_MISSED

import run_scheduler
from scheduled_tasks import scheduler as scheduler_module
from scheduled_tasks.tasks import process_email_queue_job


def test_create_scheduler_configures_job_store(mocker):
    mocker.patch("db.setup.get_db_config", return_value=("sqlite://", {}))

    scheduler = scheduler_module.create_scheduler()

    assert "default" in scheduler._jobstores
    assert scheduler_module.EMAIL_QUEUE_EXECUTOR in scheduler._executors
    assert scheduler._listeners


def test_job_listener_logs_success(mocker):
    mock_logger = mocker.Mock()
    context = mocker.MagicMock()
    context.__enter__.return_value = None
    context.__exit__.return_value = None
    mock_logger.contextualize.return_value = context
    mocker.patch("scheduled_tasks.scheduler.logger", mock_logger)
    event = SimpleNamespace(job_id="job-1", code=EVENT_JOB_EXECUTED, scheduled_run_time=None)

    scheduler_module.job_listener(event)

    mock_logger.info.assert_called_once_with("job executed successfully")


def test_job_listener_logs_missed(mocker):
    mock_logger = mocker.Mock()
    context = mocker.MagicMock()
    context.__enter__.return_value = None
    context.__exit__.return_value = None
    mock_logger.contextualize.return_value = context
    mocker.patch("scheduled_tasks.scheduler.logger", mock_logger)
    event = SimpleNamespace(job_id="job-2", code=EVENT_JOB_MISSED, scheduled_run_time=None)

    scheduler_module.job_listener(event)

    mock_logger.warning.assert_called_once_with("job missed its run time")


def test_schedule_jobs_routes_email_queue_to_dedicated_executor(mocker):
    scheduler = mocker.Mock()

    run_scheduler.schedule_jobs(scheduler, email_only=True)

    scheduler.add_job.assert_any_call(
        process_email_queue_job,
        trigger=ANY,
        id="process_email_queue",
        executor=scheduler_module.EMAIL_QUEUE_EXECUTOR,
        max_instances=1,
        replace_existing=True,
        next_run_time=ANY,
    )
