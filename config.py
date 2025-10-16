"""
Alternative configuration management using JSON
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


class ConfigManager:
    """
    JSON-based configuration management with defaults
    """

    DEFAULT_CONFIG = {
        "telegram": {
            "token": "",
            "chat_id": 0
        },
        "monitoring": {
            "report_interval": 5,
            "max_buffer_size": 1000,
            "max_retries": 3,
            "ignore_processes": [],
            "window_check_interval": 0.5,
            "retention_days": 7
        },
        "security": {
            "encrypt_logs": True,
            "use_dpapi": True
        },
        "performance": {
            "cache_size": 256,
            "queue_timeout": 2,
            "typing_timeout": 3.0
        }
    }

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path(os.environ.get('APPDATA', '')) / 'SystemHelper' / 'config.json'

        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    return self._merge_configs(self.DEFAULT_CONFIG, user_config)
            except Exception as e:
                print(f"Error loading config: {e}")
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            self._save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Recursively merge user config with defaults"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self._save_config(self.config)
