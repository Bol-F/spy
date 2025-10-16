"""
performance_monitor.py - Monitor the system monitor's performance
"""

import json
import time
from datetime import datetime
from pathlib import Path

import psutil


class PerformanceMonitor:
    """Monitor resource usage of the main application"""

    def __init__(self, target_process="python.exe", output_file="performance.json"):
        self.target_process = target_process
        self.output_file = Path(output_file)
        self.metrics = []

    def find_monitor_process(self):
        """Find the monitor process"""
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'].lower() == self.target_process.lower():
                    cmdline = proc.info.get('cmdline', [])
                    if any('monitor.py' in arg for arg in cmdline):
                        return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def collect_metrics(self, process):
        """Collect performance metrics"""
        try:
            with process.oneshot():
                return {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': process.cpu_percent(),
                    'memory_rss': process.memory_info().rss / 1024 / 1024,  # MB
                    'memory_vms': process.memory_info().vms / 1024 / 1024,  # MB
                    'num_threads': process.num_threads(),
                    'num_handles': process.num_handles() if hasattr(process, 'num_handles') else 0,
                    'io_read_bytes': process.io_counters().read_bytes if hasattr(process, 'io_counters') else 0,
                    'io_write_bytes': process.io_counters().write_bytes if hasattr(process, 'io_counters') else 0,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def save_metrics(self):
        """Save metrics to file"""
        with open(self.output_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)

    def run(self, duration=3600, interval=10):
        """Run performance monitoring"""
        print(f"Starting performance monitoring for {duration} seconds...")
        print(f"Collecting metrics every {interval} seconds...")

        start_time = time.time()

        while time.time() - start_time < duration:
            proc = self.find_monitor_process()

            if proc:
                metrics = self.collect_metrics(proc)
                if metrics:
                    self.metrics.append(metrics)
                    print(f"[{metrics['timestamp']}] CPU: {metrics['cpu_percent']:.1f}%, "
                          f"Memory: {metrics['memory_rss']:.1f}MB")
            else:
                print("Monitor process not found")

            time.sleep(interval)

        self.save_metrics()
        print(f"Performance data saved to {self.output_file}")


if __name__ == "__main__":
    monitor = PerformanceMonitor()
    monitor.run(duration=300, interval=5)  # Monitor for 5 minutes
