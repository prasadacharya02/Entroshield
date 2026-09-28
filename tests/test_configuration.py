import os
from pathlib import Path
from unittest import mock
import unittest

import config


class ConfigurationTests(unittest.TestCase):
    def test_relative_paths_resolve_from_repository_root(self):
        resolved = config._resolve_path("runtime/example.db")
        self.assertEqual(Path(resolved), config.BASE_PATH / "runtime" / "example.db")

    def test_boolean_environment_values_are_strict(self):
        for raw in ("true", "YES", "1", "on"):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"TEST_BOOL": raw}):
                self.assertTrue(config._env_bool("TEST_BOOL", False))

        for raw in ("false", "NO", "0", "off"):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"TEST_BOOL": raw}):
                self.assertFalse(config._env_bool("TEST_BOOL", True))

        with mock.patch.dict(os.environ, {"TEST_BOOL": "sometimes"}):
            with self.assertRaises(ValueError):
                config._env_bool("TEST_BOOL", False)

    def test_numeric_settings_reject_values_below_minimum(self):
        with mock.patch.dict(os.environ, {"TEST_INT": "0"}):
            with self.assertRaises(ValueError):
                config._env_int("TEST_INT", 5, minimum=1)
        with mock.patch.dict(os.environ, {"TEST_FLOAT": "-1.5"}):
            with self.assertRaises(ValueError):
                config._env_float("TEST_FLOAT", 1.0, minimum=0.0)

    def test_default_watch_folders_include_the_victim_estate(self):
        """The defended asset is always watched, whatever the .env says.

        A .env copied from .env.example ships ``ENTROPY_WATCH_FOLDERS=``
        (empty); the monitor then watched data/testing while an attack on
        the victim estate ran to completion and the SOC dashboard stayed
        at 0 events. The victim folder must be in the list even then.
        """
        victim = str(Path(config.VICTIM_USER_FILES).resolve())
        self.assertIn(victim, config.WATCH_FOLDERS)
        self.assertIn(str(Path(config.TESTING_DATA_DIR).resolve()),
                      config.WATCH_FOLDERS)

        for raw in ("", "   ", "data/testing"):
            with self.subTest(raw=raw), \
                    mock.patch.dict(os.environ,
                                    {"ENTROPY_WATCH_FOLDERS": raw}):
                folders = [str(Path(p).resolve())
                           for p in config._watch_folders()]
            self.assertIn(victim, folders)
            self.assertEqual(len(folders), len(set(folders)))

    def test_watch_victim_can_be_disabled_explicitly(self):
        with mock.patch.dict(os.environ,
                             {"ENTROPY_WATCH_FOLDERS": "data/testing",
                              "ENTROPY_WATCH_VICTIM": "false"}):
            folders = [str(Path(p).resolve()) for p in config._watch_folders()]
        self.assertNotIn(str(Path(config.VICTIM_USER_FILES).resolve()),
                         folders)

    def test_pipeline_supervision_defaults_are_demo_ready(self):
        self.assertTrue(config.AUTOSTART_PIPELINE)
        self.assertGreater(config.PIPELINE_STALE_SECONDS, 2.0)
        self.assertGreater(config.PIPELINE_SUPERVISOR_INTERVAL, 0.0)
        self.assertGreater(config.PIPELINE_RESTART_COOLDOWN, 0.0)


if __name__ == "__main__":
    unittest.main()
