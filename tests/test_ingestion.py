import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.endpoints import (
    get_all_alerts,
    get_all_logs,
    get_report,
    get_report_csv,
    ingest_text_logs,
    reset_test_data,
)
from core.file_monitor import scan_log_file
from core.ingestion import ingest_log
from models.database import APILog, Base, FileCheckpoint, Role, SecurityAlert, User, migrate_legacy_schema
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
            result = ingest_text_logs(
                TextLogIngest(content=content, source_file="uploaded-access.log"),
                db,
            )
            db.commit()
            self.assertEqual(result["processed"], 1)
            self.assertEqual(result["threats"], 1)
            self.assertEqual(result["errors"][0]["line"], 2)
            self.assertEqual(len(get_all_logs(limit=50, db=db)), 1)
            self.assertEqual(len(get_all_alerts(limit=50, db=db)), 1)
            self.assertEqual(db.query(APILog).one().source_file, "uploaded-access.log")

    def test_report_aggregates_alarm_logs_and_alert_types(self):
        with self.session_factory() as db:
            first_log = APILog(
                source_ip="203.0.113.10",
                endpoint="/private",
                http_method="GET",
                status_code=403,
                source_file="attack-sample.jsonl",
                payload_data="UNION SELECT",
                raw_line='{"source_ip":"203.0.113.10"}',
            )
            second_log = APILog(
                source_ip="203.0.113.10",
                endpoint="/private",
                http_method="POST",
                status_code=200,
            )
            clean_log = APILog(
                source_ip="203.0.113.11",
                endpoint="/",
                http_method="GET",
                status_code=200,
            )
            db.add_all([first_log, second_log, clean_log])
            db.flush()
            db.add_all([
                SecurityAlert(log_id=first_log.log_id, alert_type="403 Forbidden", severity_level="Yüksek"),
                SecurityAlert(log_id=first_log.log_id, alert_type="SQL error", severity_level="Yüksek"),
                SecurityAlert(log_id=second_log.log_id, alert_type="403 Forbidden", severity_level="Yüksek"),
            ])
            db.commit()

            report = get_report(db)

        self.assertEqual(report["total_logs"], 3)
        self.assertEqual(report["threat_logs"], 2)
        self.assertEqual(report["total_alerts"], 3)
        self.assertEqual(report["top_attackers"], [{"source_ip": "203.0.113.10", "count": 2}])
        self.assertEqual(
            report["vulnerability_types"],
            [{"alert_type": "403 Forbidden", "count": 2}, {"alert_type": "SQL error", "count": 1}],
        )
        self.assertEqual(len(report["imported_files"]), 1)
        file_report = report["imported_files"][0]
        self.assertEqual(file_report["file_name"], "attack-sample.jsonl")
        self.assertEqual(file_report["total_logs"], 1)
        self.assertEqual(file_report["threat_logs"], 1)
        self.assertEqual(file_report["logs"][0]["payload_data"], "UNION SELECT")
        self.assertEqual(file_report["logs"][0]["alerts"][0]["alert_type"], "403 Forbidden")

    def test_reset_data_clears_logs_alerts_and_checkpoints_but_preserves_users(self):
        with self.session_factory() as db:
            role = Role(name="admin", description="Admin")
            db.add(role)
            db.flush()
            db.add(User(username="test-admin", role_id=role.role_id))
            log = APILog(
                source_ip="203.0.113.1",
                endpoint="/",
                http_method="GET",
                status_code=403,
            )
            db.add(log)
            db.flush()
            db.add(SecurityAlert(
                log_id=log.log_id,
                alert_type="403 Forbidden",
                severity_level="Yüksek",
            ))
            db.add(FileCheckpoint(file_path="test.log", byte_offset=10))
            db.commit()

            result = reset_test_data(db)

            self.assertEqual(result["deleted_logs"], 1)
            self.assertEqual(result["deleted_alerts"], 1)
            self.assertEqual(result["deleted_checkpoints"], 1)
            self.assertEqual(db.query(APILog).count(), 0)
            self.assertEqual(db.query(SecurityAlert).count(), 0)
            self.assertEqual(db.query(FileCheckpoint).count(), 0)
            self.assertEqual(db.query(User).count(), 1)
            self.assertEqual(db.query(Role).count(), 1)

    def test_report_csv_is_excel_friendly_and_neutralizes_formula_values(self):
        with self.session_factory() as db:
            log = APILog(
                source_ip="=HYPERLINK('https://example.test')",
                endpoint="/private",
                http_method="GET",
                status_code=403,
            )
            db.add(log)
            db.flush()
            db.add(SecurityAlert(
                log_id=log.log_id,
                alert_type="+SUM(1,1)",
                severity_level="Yüksek",
            ))
            db.commit()

            response = get_report_csv(db)

        csv_content = bytes(response.body).decode("utf-8")
        self.assertTrue(csv_content.startswith("\ufeff"))
        self.assertIn("attachment; filename=\"guvenlik-raporu.csv\"", response.headers["content-disposition"])
        self.assertIn("'=HYPERLINK", csv_content)
        self.assertIn("'+SUM(1,1)", csv_content)


if __name__ == "__main__":
    unittest.main()
