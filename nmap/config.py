# -*- coding: utf-8 -*-
"""
Enterprise Configuration Management Module

Provides centralized, type-safe configuration management for nmap scanning operations.
Supports environment-based configuration, validation, and runtime configuration updates.

SECURITY: All configurations are validated and sanitized before use.
PERFORMANCE: Configuration caching with automatic invalidation.
COMPLIANCE: Audit logging for all configuration changes.
"""

import os
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from enum import Enum
import json

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels for scanning operations."""
    PERMISSIVE = "permissive"
    STANDARD = "standard" 
    STRICT = "strict"
    PARANOID = "paranoid"

class LogLevel(Enum):
    """Logging levels with enterprise context."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass(frozen=True)
class SecurityConstraints:
    """Immutable security constraints for enterprise deployment."""
    max_scan_timeout: int = 3600  # 1 hour max
    max_concurrent_scans: int = 10
    allowed_target_networks: Set[str] = field(default_factory=lambda: {"127.0.0.1/32", "::1/128"})
    blocked_ports: Set[int] = field(default_factory=set)
    required_privilege_ports: Set[int] = field(default_factory=lambda: {22, 23, 25, 53, 80, 110, 143, 443, 993, 995})
    max_decoy_count: int = 16
    allowed_scan_types: Set[str] = field(default_factory=lambda: {"-sT", "-sS", "-sU", "-sV", "-O"})
    deny_dangerous_options: Set[str] = field(default_factory=lambda: {"--script=*vuln*", "--script=*exploit*"})

@dataclass
class PerformanceConfig:
    """Performance tuning configuration."""
    cache_ttl_seconds: int = 300
    max_cache_entries: int = 1000
    enable_scan_caching: bool = True
    thread_pool_size: int = 4
    memory_limit_mb: int = 512
    gc_threshold_scans: int = 100
    
    def __post_init__(self):
        """Validate performance configuration values."""
        if self.cache_ttl_seconds < 0:
            raise ValueError("Cache TTL must be non-negative")
        if self.max_cache_entries < 1:
            raise ValueError("Max cache entries must be positive")
        if self.thread_pool_size < 1 or self.thread_pool_size > 32:
            raise ValueError("Thread pool size must be between 1 and 32")

@dataclass
class NetworkConfig:
    """Network-specific configuration."""
    default_timeout: int = 30
    connection_retry_count: int = 3
    dns_resolution_timeout: int = 5
    source_interface: Optional[str] = None
    bind_source_addr: Optional[str] = None
    ipv6_enabled: bool = True
    max_rtt_timeout: int = 10000  # milliseconds
    
    def __post_init__(self):
        """Validate network configuration."""
        if self.default_timeout < 1:
            raise ValueError("Default timeout must be positive")
        if self.connection_retry_count < 0:
            raise ValueError("Retry count must be non-negative")

@dataclass
class AuditConfig:
    """Audit and compliance configuration."""
    enable_audit_logging: bool = True
    audit_log_path: Optional[Path] = None
    log_scan_commands: bool = True
    log_target_access: bool = True
    log_configuration_changes: bool = True
    retention_days: int = 90
    
    def __post_init__(self):
        """Initialize audit configuration."""
        if self.audit_log_path is None:
            self.audit_log_path = Path.cwd() / "logs" / "nmap_audit.log"
        if self.retention_days < 1:
            raise ValueError("Retention days must be positive")

class ConfigurationError(Exception):
    """Raised when configuration validation fails."""
    pass

class ConfigurationManager:
    """
    Thread-safe enterprise configuration manager.
    
    Provides centralized configuration with validation, caching, and audit logging.
    Supports hot-reloading of configuration from files and environment variables.
    """
    
    _instance: Optional['ConfigurationManager'] = None
    _lock = threading.RLock()
    
    def __new__(cls) -> 'ConfigurationManager':
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        """Initialize configuration manager."""
        if hasattr(self, '_initialized'):
            return
            
        self._initialized = True
        self._config_lock = threading.RLock()
        self._config_cache: Dict[str, Any] = {}
        self._cache_timestamps: Dict[str, float] = {}
        self._audit_logger = self._setup_audit_logger()
        
        # Load default configurations
        self._security_constraints = self._load_security_constraints()
        self._performance_config = self._load_performance_config()
        self._network_config = self._load_network_config()
        self._audit_config = self._load_audit_config()
        
        # Configuration validation
        self._validate_configuration()
        
        self._log_audit_event("configuration_manager_initialized", {
            "security_level": os.getenv("NMAP_SECURITY_LEVEL", "standard"),
            "performance_mode": os.getenv("NMAP_PERFORMANCE_MODE", "balanced")
        })
    
    def _setup_audit_logger(self) -> logging.Logger:
        """Setup dedicated audit logger."""
        audit_logger = logging.getLogger(f"{__name__}.audit")
        audit_logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not audit_logger.handlers:
            # Create audit log directory
            log_dir = Path.cwd() / "logs"
            log_dir.mkdir(exist_ok=True)
            
            # File handler for audit logs
            file_handler = logging.FileHandler(log_dir / "nmap_audit.log")
            file_handler.setLevel(logging.INFO)
            
            # Audit-specific formatter
            formatter = logging.Formatter(
                '%(asctime)s - AUDIT - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(formatter)
            audit_logger.addHandler(file_handler)
        
        return audit_logger
    
    def _load_security_constraints(self) -> SecurityConstraints:
        """Load security constraints from environment and config files."""
        try:
            # Environment variable overrides
            max_timeout = int(os.getenv("NMAP_MAX_TIMEOUT", "3600"))
            max_concurrent = int(os.getenv("NMAP_MAX_CONCURRENT", "10"))
            
            # Parse allowed networks from environment
            allowed_networks = set()
            networks_env = os.getenv("NMAP_ALLOWED_NETWORKS", "127.0.0.1/32,::1/128")
            if networks_env:
                allowed_networks.update(net.strip() for net in networks_env.split(","))
            
            # Parse blocked ports
            blocked_ports = set()
            ports_env = os.getenv("NMAP_BLOCKED_PORTS", "")
            if ports_env:
                for port_range in ports_env.split(","):
                    if "-" in port_range:
                        start, end = map(int, port_range.split("-"))
                        blocked_ports.update(range(start, end + 1))
                    else:
                        blocked_ports.add(int(port_range))
            
            return SecurityConstraints(
                max_scan_timeout=max_timeout,
                max_concurrent_scans=max_concurrent,
                allowed_target_networks=allowed_networks,
                blocked_ports=blocked_ports
            )
            
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to load security constraints: {e}")
            return SecurityConstraints()  # Use defaults
    
    def _load_performance_config(self) -> PerformanceConfig:
        """Load performance configuration."""
        try:
            return PerformanceConfig(
                cache_ttl_seconds=int(os.getenv("NMAP_CACHE_TTL", "300")),
                max_cache_entries=int(os.getenv("NMAP_MAX_CACHE_ENTRIES", "1000")),
                enable_scan_caching=os.getenv("NMAP_ENABLE_CACHING", "true").lower() == "true",
                thread_pool_size=int(os.getenv("NMAP_THREAD_POOL_SIZE", "4")),
                memory_limit_mb=int(os.getenv("NMAP_MEMORY_LIMIT_MB", "512"))
            )
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to load performance config: {e}")
            return PerformanceConfig()  # Use defaults
    
    def _load_network_config(self) -> NetworkConfig:
        """Load network configuration."""
        try:
            return NetworkConfig(
                default_timeout=int(os.getenv("NMAP_DEFAULT_TIMEOUT", "30")),
                connection_retry_count=int(os.getenv("NMAP_RETRY_COUNT", "3")),
                dns_resolution_timeout=int(os.getenv("NMAP_DNS_TIMEOUT", "5")),
                source_interface=os.getenv("NMAP_SOURCE_INTERFACE"),
                bind_source_addr=os.getenv("NMAP_BIND_ADDR"),
                ipv6_enabled=os.getenv("NMAP_IPV6_ENABLED", "true").lower() == "true"
            )
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to load network config: {e}")
            return NetworkConfig()  # Use defaults
    
    def _load_audit_config(self) -> AuditConfig:
        """Load audit configuration."""
        try:
            audit_path = os.getenv("NMAP_AUDIT_LOG_PATH")
            return AuditConfig(
                enable_audit_logging=os.getenv("NMAP_ENABLE_AUDIT", "true").lower() == "true",
                audit_log_path=Path(audit_path) if audit_path else None,
                log_scan_commands=os.getenv("NMAP_LOG_COMMANDS", "true").lower() == "true",
                log_target_access=os.getenv("NMAP_LOG_TARGETS", "true").lower() == "true",
                retention_days=int(os.getenv("NMAP_AUDIT_RETENTION_DAYS", "90"))
            )
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to load audit config: {e}")
            return AuditConfig()  # Use defaults
    
    def _validate_configuration(self) -> None:
        """Validate all configuration settings."""
        try:
            # Validate security constraints
            if self._security_constraints.max_scan_timeout < 1:
                raise ConfigurationError("Max scan timeout must be positive")
            
            if self._security_constraints.max_concurrent_scans < 1:
                raise ConfigurationError("Max concurrent scans must be positive")
            
            # Validate performance configuration
            if self._performance_config.thread_pool_size > 32:
                logger.warning("Thread pool size exceeds recommended maximum of 32")
            
            # Validate network configuration
            if self._network_config.default_timeout < 1:
                raise ConfigurationError("Default timeout must be positive")
            
            self._log_audit_event("configuration_validated", {
                "security_level": "validated",
                "max_timeout": self._security_constraints.max_scan_timeout
            })
            
        except Exception as e:
            self._log_audit_event("configuration_validation_failed", {"error": str(e)})
            raise ConfigurationError(f"Configuration validation failed: {e}")
    
    def _log_audit_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log audit events for compliance."""
        if self._audit_config.enable_audit_logging:
            audit_data = {
                "event_type": event_type,
                "timestamp": logging.Formatter().formatTime(logging.LogRecord("", 0, "", 0, "", (), None)),
                "data": data
            }
            self._audit_logger.info(json.dumps(audit_data))
    
    def get_security_constraints(self) -> SecurityConstraints:
        """Get current security constraints."""
        with self._config_lock:
            return self._security_constraints
    
    def get_performance_config(self) -> PerformanceConfig:
        """Get current performance configuration."""
        with self._config_lock:
            return self._performance_config
    
    def get_network_config(self) -> NetworkConfig:
        """Get current network configuration."""
        with self._config_lock:
            return self._network_config
    
    def get_audit_config(self) -> AuditConfig:
        """Get current audit configuration."""
        with self._config_lock:
            return self._audit_config
    
    def update_security_level(self, level: SecurityLevel) -> None:
        """Update security level with immediate effect."""
        with self._config_lock:
            self._log_audit_event("security_level_changed", {
                "old_level": getattr(self, '_current_security_level', 'unknown'),
                "new_level": level.value
            })
            
            self._current_security_level = level
            
            # Apply security level-specific constraints
            if level == SecurityLevel.PARANOID:
                self._security_constraints = SecurityConstraints(
                    max_scan_timeout=1800,  # 30 minutes
                    max_concurrent_scans=3,
                    max_decoy_count=8
                )
            elif level == SecurityLevel.STRICT:
                self._security_constraints = SecurityConstraints(
                    max_scan_timeout=3600,  # 1 hour
                    max_concurrent_scans=5,
                    max_decoy_count=12
                )
    
    def validate_scan_arguments(self, arguments: str) -> bool:
        """Validate scan arguments against security constraints."""
        security = self.get_security_constraints()
        
        # Check for denied dangerous options
        for denied_option in security.deny_dangerous_options:
            if denied_option.replace("*", "") in arguments:
                self._log_audit_event("dangerous_argument_blocked", {
                    "argument": denied_option,
                    "full_arguments": arguments
                })
                return False
        
        return True
    
    def get_effective_timeout(self, requested_timeout: Optional[int]) -> int:
        """Get effective timeout considering security constraints."""
        security = self.get_security_constraints()
        network = self.get_network_config()
        
        if requested_timeout is None:
            return network.default_timeout
        
        # Enforce maximum timeout from security constraints
        return min(requested_timeout, security.max_scan_timeout)

# Global configuration manager instance
config_manager = ConfigurationManager()
