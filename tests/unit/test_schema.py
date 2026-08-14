import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from thesis_pipeline.storage import initialise_database


class SchemaTests(unittest.TestCase):
    def test_versioned_schema_initialises_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = initialise_database(Path(directory) / "thesis.sqlite")
            with closing(sqlite3.connect(path)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                version = connection.execute("SELECT MAX(version) FROM schema_version").fetchone()[
                    0
                ]
            self.assertIn("priority_decision", tables)
            self.assertIn("dynamic_exploit_evidence", tables)
            self.assertEqual(version, 1)


if __name__ == "__main__":
    unittest.main()
