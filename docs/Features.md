# Features

This Python nmap wrapper provides comprehensive coverage of nmap functionality through a clean, type-safe API designed for professional use.

## Core Capabilities

### Port Scanning
- **All scan types**: TCP, UDP, IP, SCTP through nmap argument passthrough
- **Service detection**: Version scanning (-sV) with comprehensive service data
- **OS fingerprinting**: Complete OS detection with match confidence scoring
- **Custom arguments**: Full nmap command-line argument support

### Built-in Security Features
- **Firewall evasion**: Predefined stealth profiles (Basic, Stealth, Ghost, Adaptive)
- **IDS evasion**: Timing manipulation, packet fragmentation, MAC spoofing
- **Argument validation**: Safe parameter construction preventing command injection
- **Stealth scanning**: Convenient functions for operational security requirements

### Performance & Scalability
- **Asynchronous scanning**: Non-blocking operations with callback support
- **Memory efficiency**: Yield-based scanning for large network ranges
- **Intelligent caching**: TTL-based result storage with thread-safe operations
- **Performance monitoring**: Built-in statistics collection and optimization

## API Design

### Type Safety
- Complete type annotations with runtime validation
- IDE-friendly development with full autocompletion
- Comprehensive error handling with contextual exception hierarchy
- Modern Python best practices throughout

### Cross-Platform Support
- Automatic nmap executable detection (Windows, macOS, Linux)
- Universal XML parsing with error recovery
- Platform-specific path handling and process management
- Consistent API across all supported operating systems

### Developer Experience
- Clean, intuitive interface with backward compatibility
- Modern API aliases for contemporary development
- Comprehensive documentation and usage examples
- Zero-redundancy design with single source of truth

## Nmap Feature Coverage

### Fully Supported
- **Host Discovery**: Ping scanning, list scanning, network enumeration
- **Port Scanning**: All TCP/UDP/IP/SCTP scan types via argument passthrough
- **Service Detection**: Version scanning with complete service fingerprinting
- **OS Detection**: Operating system fingerprinting with confidence scoring
- **Script Engine**: NSE script output parsing and result processing
- **Timing Control**: All timing templates (-T0 to -T5) and custom timing
- **Output Formats**: XML parsing with comprehensive data extraction
- **IPv4/IPv6**: Native dual-stack support through nmap capabilities
- **Privilege Escalation**: Cross-platform sudo/administrator privilege handling

### Enhanced Features
- **Built-in Evasion**: Stealth profiles without complex configuration
- **Async Operations**: Non-blocking scanning with proper resource management
- **Memory Optimization**: Generator-based iteration for enterprise-scale networks
- **Performance Monitoring**: Real-time statistics and optimization metrics
- **Thread Safety**: Atomic operations with proper resource protection

## Security Considerations

### Safe Operation
- Input validation and sanitization for all parameters
- Safe command construction preventing injection attacks
- Proper process lifecycle management with automatic cleanup
- Resource limits and timeout controls for operational safety

### Operational Security
- Built-in stealth scanning profiles for sensitive environments
- Configurable timing and evasion techniques
- MAC address spoofing and packet fragmentation support
- Adaptive evasion selection based on target characteristics

## Enterprise Features

### Resource Management
- Automatic process cleanup and termination safeguards
- Memory leak prevention with proper resource disposal
- Configurable caching with TTL-based expiration
- Thread-safe operations for concurrent usage

### Monitoring & Observability
- Performance statistics collection and reporting
- Configurable logging levels and output destinations
- Real-time scan progress monitoring and callbacks
- Error tracking and recovery mechanisms

### Production Readiness
- Comprehensive error handling with graceful degradation
- Type-safe operations with runtime validation
- Cross-platform compatibility with automatic detection
- Zero-redundancy architecture with clean separation of concerns