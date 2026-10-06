import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from core.file_monitor import LiveLogMonitor
from models.database import Base, APILog, SecurityAlert


class LiveLogMonitorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine)

    def tearDown(self):
        self.engine.dispose()

    async def test_monitor_reads_existing_and_appended_lines_until_stopped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "access.log"
            first_line = (
                '203.0.113.1 - - [02/Oct/2026:20:10:00 +0300] '
                '"GET /private HTTP/1.1" 403 10 "-" "test"\n'
            )
            second_line = (
                '203.0.113.2 - - [02/Oct/2026:20:10:01 +0300] '
                '"GET /home HTTP/1.1" 200 10 "-" "test"\n'
            )
            path.write_text(first_line, encoding="utf-8")
            monitor = LiveLogMonitor(poll_interval_seconds=0.02)

            with patch("core.file_monitor.SessionLocal", self.session_factory):
                status = await monitor.start(path)
                self.assertTrue(status["active"])
                await asyncio.sleep(0.06)
                with path.open("a", encoding="utf-8") as log_file:
                    log_file.write(second_line)
                await asyncio.sleep(0.06)
                status = await monitor.stop()

            self.assertFalse(status["active"])
            self.assertEqual(status["state"], "stopped")
            self.assertEqual(status["processed"], 2)
            self.assertEqual(status["invalid"], 0)
            with self.session_factory() as db:
                self.assertEqual(db.query(APILog).count(), 2)
                self.assertEqual(db.query(SecurityAlert).count(), 1)

    async def test_monitor_rejects_a_second_active_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "access.log"
            path.write_text("", encoding="utf-8")
            monitor = LiveLogMonitor(poll_interval_seconds=0.02)
            with patch("core.file_monitor.scan_log_file", return_value={"processed": 0, "invalid": 0}):
                await monitor.start(path)
                with self.assertRaises(RuntimeError):
                    await monitor.start(path)
                await monitor.stop()


if __name__ == "__main__":
    unittest.main()
