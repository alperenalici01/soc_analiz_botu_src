import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.endpoints import get_all_alerts, get_all_logs, ingest_text_logs
from core.file_monitor import scan_log_file
from core.ingestion import ingest_log
from models.database import APILog, Base, FileCheckpoint, SecurityAlert, migrate_legacy_schema
from models.schemas import APILogCreate, TextLogIngest


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(bind=self.engine)

    def tearDown(self):
        self.engine.dispose()

    def test_ingestion_persists_log_and_alert(self):
        log_data = APILogCreate(
            timestamp=datetime(2026, 10, 2, 17, 10),
            source_ip="203.0.113.1",
            endpoint="/api/private",
            http_method="GET",
            status_code=403,
        )
        with self.session_factory() as db:
            result = ingest_log(db, log_data)
            db.commit()
            self.assertEqual(result["status"], "danger")
            self.assertEqual(db.query(APILog).count(), 1)
            self.assertEqual(db.query(SecurityAlert).count(), 1)

    def test_legacy_database_schema_is_migrated_without_data_loss(self):
        legacy_engine = create_engine("sqlite:///:memory:")
        try:
            with legacy_engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE TABLE api_logs (log_id INTEGER PRIMARY KEY, timestamp DATETIME, "
                    "source_ip VARCHAR(45), endpoint VARCHAR(255), http_method VARCHAR(10), "
                    "status_code INTEGER, payload_data TEXT)"
                )
                connection.exec_driver_sql(
                    "INSERT INTO api_logs (log_id, source_ip, endpoint, http_method, status_code) "
                    "VALUES (7, '203.0.113.7', '/old', 'GET', 200)"
                )
            migrate_legacy_schema(legacy_engine)
            with legacy_engine.connect() as connection:
                columns = {
                    row[1]
                    for row in connection.exec_driver_sql("PRAGMA table_info(api_logs)")
                }
                preserved_log = connection.exec_driver_sql(
                    "SELECT log_id, source_ip FROM api_logs"
                ).one()
        finally:
            legacy_engine.dispose()
        self.assertTrue({"raw_line", "source_file"}.issubset(columns))
        self.assertEqual(tuple(preserved_log), (7, "203.0.113.7"))

    def test_file_monitor_ingests_new_lines_once_and_saves_cursor(self):
        contents = (
            '203.0.113.1 - - [02/Oct/2026:20:10:00 +0300] '
            '"GET /private HTTP/1.1" 403 10 "-" "test"\n'
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "access.log"
            path.write_text(contents, encoding="utf-8")
            with patch("core.file_monitor.SessionLocal", self.session_factory):
                self.assertEqual(scan_log_file(path), {"processed": 1, "invalid": 0})
                self.assertEqual(scan_log_file(path), {"processed": 0, "invalid": 0})

            with self.session_factory() as db:
                self.assertEqual(db.query(APILog).count(), 1)
                self.assertEqual(db.query(SecurityAlert).count(), 1)
                checkpoint = db.query(FileCheckpoint).one()
                self.assertEqual(checkpoint.byte_offset, path.stat().st_size)

    def test_supplied_demo_log_exercises_each_requested_alert_type(self):
        demo_log = Path(__file__).parents[1] / "dummy_data" / "server_access.log"
        with patch("core.file_monitor.SessionLocal", self.session_factory):
            result = scan_log_file(demo_log)
        self.assertEqual(result, {"processed": 25, "invalid": 0})
        with self.session_factory() as db:
            alert_types = {alert.alert_type for alert in db.query(SecurityAlert).all()}
        self.assertTrue(any("403" in alert_type for alert_type in alert_types))
        self.assertTrue(any("POST" in alert_type for alert_type in alert_types))
        self.assertTrue(any("SQL" in alert_type for alert_type in alert_types))
        self.assertTrue(any("Rate Limit" in alert_type for alert_type in alert_types))

    def test_text_ingestion_endpoint_reports_invalid_lines_and_returns_history(self):
        content = (
            '203.0.113.1 - - [02/Oct/2026:20:10:00 +0300] '
            '"GET /private HTTP/1.1" 403 10 "-" "test"\n'
            "invalid log line\n"
        )
        with self.session_factory() as db:
            result = ingest_text_logs(TextLogIngest(content=content), db)
            db.commit()
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["threats"], 1)
            self.assertEqual(result["errors"][0]["line"], 2)
            self.assertEqual(len(get_all_logs(limit=50, db=db)), 1)
            self.assertEqual(len(get_all_alerts(limit=50, db=db)), 1)


if __name__ == "__main__":
    unittest.main()
