import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import main


class ApplicationStartupTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_does_not_automatically_ingest_demo_logs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            watch_dir = Path(temp_dir) / "logs"
            with (
                patch("main.Base.metadata.create_all"),
                patch("main.migrate_legacy_schema"),
                patch("main.seed_default_roles"),
                patch("main.stop_live_log_monitor", new=AsyncMock()) as stop_monitor,
                patch.object(asyncio, "to_thread", new_callable=AsyncMock) as to_thread,
            ):
                async with main.lifespan(main.app):
                    pass

            to_thread.assert_not_awaited()
            stop_monitor.assert_awaited_once()
            self.assertFalse(watch_dir.exists())


if __name__ == "__main__":
    unittest.main()
