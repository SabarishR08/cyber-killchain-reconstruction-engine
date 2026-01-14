"""
Configuration management for the Kill Chain Reconstruction Engine.
Loads settings from config.yaml with environment variable overrides.
"""
import os
import yaml
from typing import Dict, Any, Optional


DEFAULT_CONFIG = {
    "correlation": {
        "time_window_minutes": 10,
        "brute_force_threshold": 3,
        "credential_compromise_threshold": 2,
    },
    "severity": {
        "login_failed": 6,
        "login_success": 3,
        "suspicious": 7,
    },
    "risk_scoring": {
        "severity_weights": {
            "LOW": 5,
            "MEDIUM": 15,
            "HIGH": 30,
            "CRITICAL": 40,
        },
        "confidence_threshold": 0.7,
        "mitre_bonus": 20,
    },
    "priority_thresholds": {
        "CRITICAL": 90,
        "HIGH": 70,
        "MEDIUM": 40,
        "LOW": 0,
    },
    "attribution": {
        "multi_source_threshold": 4,
        "time_clustering_tolerance": 300,
    },
    "logging": {
        "level": "INFO",
        "file": "logs/killchain.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
    "database": {
        "path": "events.db",
        "timeout": 5,
        "check_same_thread": False,
    },
    "alerts": {
        "enabled": True,
        "threshold": 70,
        "channels": ["stdout", "file"],
    },
    "advanced": {
        "deterministic_mode": True,
        "audit_logging": True,
        "error_recovery": True,
    },
}


class ConfigManager:
    """Manages configuration loading and access."""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize config manager.
        
        Args:
            config_file: Path to config.yaml. If not provided, uses default.
        """
        self.config = self._load_config(config_file)
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """
        Load configuration from file with environment variable overrides.
        
        Args:
            config_file: Path to YAML config file
            
        Returns:
            Configuration dictionary
        """
        config = DEFAULT_CONFIG.copy()
        
        # Try to load from file if provided
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = yaml.safe_load(f) or {}
                    self._deep_merge(config, file_config)
            except Exception as e:
                print(f"[!] Warning: Failed to load config file {config_file}: {e}")
        
        # Apply environment variable overrides
        self._apply_env_overrides(config)
        
        return config
    
    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Recursively merge override config into base."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _apply_env_overrides(self, config: Dict[str, Any]) -> None:
        """Apply environment variable overrides to config."""
        env_mapping = {
            "KILLCHAIN_TIME_WINDOW": ("correlation", "time_window_minutes", int),
            "KILLCHAIN_BRUTE_FORCE_THRESHOLD": ("correlation", "brute_force_threshold", int),
            "KILLCHAIN_LOG_LEVEL": ("logging", "level", str),
            "KILLCHAIN_DB_PATH": ("database", "path", str),
        }
        
        for env_var, (section, key, cast_type) in env_mapping.items():
            value = os.getenv(env_var)
            if value:
                try:
                    config[section][key] = cast_type(value)
                except (ValueError, KeyError) as e:
                    print(f"[!] Warning: Invalid environment variable {env_var}: {e}")
    
    def get(self, *keys) -> Any:
        """
        Get configuration value by dot-notation keys.
        
        Args:
            *keys: Configuration path (e.g., get("correlation", "time_window_minutes"))
            
        Returns:
            Configuration value or None if not found
        """
        value = self.config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value
    
    def get_or_default(self, default: Any, *keys) -> Any:
        """Get config value with fallback to default."""
        value = self.get(*keys)
        return value if value is not None else default
    
    def validate(self) -> bool:
        """
        Validate configuration integrity.
        
        Returns:
            True if valid, False otherwise
        """
        required_sections = [
            ("correlation", "time_window_minutes"),
            ("correlation", "brute_force_threshold"),
            ("database", "path"),
            ("logging", "level"),
        ]
        
        for *path, key in required_sections:
            if self.get(*path, key) is None:
                print(f"[!] Configuration error: Missing {'.'.join(path + [key])}")
                return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Return entire configuration as dictionary."""
        return self.config.copy()


# Global config instance
_config_manager: Optional[ConfigManager] = None


def init_config(config_file: Optional[str] = None) -> ConfigManager:
    """
    Initialize global configuration manager.
    
    Args:
        config_file: Optional path to config.yaml
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    _config_manager = ConfigManager(config_file)
    return _config_manager


def get_config() -> ConfigManager:
    """Get global config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager
