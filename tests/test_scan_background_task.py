import asyncio
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks

from app.api.scan import _run_scan_task, trigger_scan


@patch("app.api.scan.ScanService")
@patch("app.api.scan.SessionLocal")
def test_background_scan_owns_and_closes_session(mock_session_local, mock_service):
    session = MagicMock()
    mock_session_local.return_value = session

    _run_scan_task(42)

    mock_service.assert_called_once_with(session)
    mock_service.return_value.run_scan_by_id.assert_called_once_with(42)
    session.close.assert_called_once()


@patch("app.api.scan.ScanService")
@patch("app.api.scan.SessionLocal")
def test_background_scan_marks_error_when_task_raises(mock_session_local, mock_service):
    session = MagicMock()
    scan = MagicMock()
    mock_session_local.return_value = session
    session.query.return_value.filter.return_value.first.return_value = scan
    mock_service.return_value.run_scan_by_id.side_effect = RuntimeError("boom")

    _run_scan_task(7)

    assert scan.status == "error"
    assert scan.completed_at is not None
    session.rollback.assert_called_once()
    session.commit.assert_called_once()
    session.close.assert_called_once()


def test_trigger_scan_returns_queued_response_and_schedules_task():
    from types import SimpleNamespace

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = MagicMock(
        user_id=1
    )

    def assign_scan_id(scan):
        scan.id = 99

    db.refresh.side_effect = assign_scan_id
    tasks = BackgroundTasks()

    response = asyncio.run(
        trigger_scan(
            email_id=5,
            background_tasks=tasks,
            db=db,
            user=SimpleNamespace(id=1, email="t@example.com"),
        )
    )

    assert response.status == "queued"
    assert response.scan_id == 99
    assert response.email_id == 5
    assert len(tasks.tasks) == 1
