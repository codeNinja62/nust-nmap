# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-01-10

### Added
- Production-grade Python nmap wrapper with comprehensive feature coverage
- Built-in firewall and IDS evasion capabilities with predefined profiles
- Asynchronous scanning support with callback-based result processing
- Memory-efficient yield-based scanning for large network ranges
- Intelligent caching system with TTL-based result storage
- Performance monitoring and statistics collection
- Complete type annotations with runtime validation
- Cross-platform nmap executable detection and path resolution
- Thread-safe operations with proper resource management
- Modern API aliases for improved developer experience

### Enhanced
- XML parsing engine with comprehensive host, port, and service data extraction
- Error handling with contextual exception hierarchy and recovery mechanisms
- Argument validation and safe parameter construction for nmap commands
- Process lifecycle management with automatic cleanup and termination safeguards
- Memory optimization for enterprise-scale network scanning operations

### Security
- Argument sanitization and validation to prevent command injection
- Safe parameter handling for all nmap command construction
- Built-in stealth scanning profiles for operational security requirements

## [1.0.0] - 2025-01-08

### Added
- Initial release of professional nmap Python wrapper
- Complete nmap feature coverage through argument passthrough
- Type-safe API with comprehensive annotations
- Cross-platform compatibility (Windows, macOS, Linux)
- Comprehensive XML output parsing
- Error handling and logging infrastructure
- Documentation and usage examples