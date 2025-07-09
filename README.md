<h1 align="center">nust-nmap</h1>
<p align="center">
    <img src="https://badge.fury.io/py/nust-nmap.svg" alt="PyPI version" />
    <img src="https://img.shields.io/pypi/pyversions/nust-nmap.svg" alt="Python versions" />
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT" />
    <img src="https://pepy.tech/badge/nust-nmap" alt="Downloads" />
</p>

<p align="center">
    <strong>🎯 Enhanced Python Nmap Wrapper</strong><br>
    <em>Enterprise-grade Python interface with built-in stealth capabilities</em>
</p>

## 🌟 **Enhanced Nmap Wrapper with Evasion**

An enterprise-grade Python wrapper that enhances the original nmap functionality with built-in stealth capabilities, async operations, and comprehensive parsing. Designed for security professionals, penetration testers, and network administrators who need reliable nmap functionality with modern Python features.

### ✅ **Key Features**

- **Enhanced PortScanner**: Original API with built-in evasion profiles
- **Stealth Capabilities**: Built-in firewall/IDS evasion techniques
- **Async Operations**: Non-blocking scanning with callbacks and generators
- **Type Safety**: Complete type annotations and runtime validation
- **Memory Efficient**: Generator-based scanning for large networks
- **Enterprise Ready**: Production-grade error handling and resource management
- **100% Compatible**: Full backward compatibility with python-nmap
- **Modern Aliases**: Scanner, AsyncScanner, YieldScanner for new projects

## 🚀 Key Features

- **🎯 Enhanced Nmap Integration**: All nmap capabilities via arguments + built-in profiles
- **�️ Enterprise Security**: Built-in evasion profiles and security validation
- **⚡ High Performance**: Async scanning with intelligent caching
- **� Stealth Capabilities**: Ghost, Stealth, and Adaptive evasion profiles
- **🔍 Complete Parsing**: Full nmap XML output analysis with type safety
- **� Rich Output**: Enhanced CSV, JSON, and XML result processing
- **🌐 Cross-Platform**: Windows, macOS, Linux support with auto-detection
- **⚙️ Production Ready**: Thread-safe, resource-managed, enterprise-grade design

## 📦 Installation

### Prerequisites

**System Requirements:**
- Python 3.8 or higher
- Nmap 7.90+ installed on your system (7.94+ recommended)

### Install nust-nmap

```bash
pip install nust-nmap
```

### Install Nmap

#### Ubuntu/Debian
```bash
sudo apt update && sudo apt install nmap
```

#### CentOS/RHEL/Fedora
```bash
sudo dnf install nmap  # Fedora
sudo yum install nmap  # CentOS/RHEL
```

#### macOS
```bash
brew install nmap
```

#### Windows
Download and install from [nmap.org/download.html](https://nmap.org/download.html)

## � Quick Start

## 🚀 Quick Start

### Enhanced Scanner Usage

```python
import nmap

# Standard usage (enhanced internally)
scanner = nmap.PortScanner()
result = scanner.scan('192.168.1.0/24', '22,80,443', '-sV')

# Modern alias for new projects
scanner = nmap.Scanner()
result = scanner.scan('target.com', ports='1-1000')

# Analyze results
for host in result.get('scan', {}):
    host_data = result['scan'][host]
    print(f"🟢 {host} - {host_data['status']['state']}")
    
    # Check TCP services
    if 'tcp' in host_data:
        for port, port_info in host_data['tcp'].items():
            if port_info['state'] == 'open':
                service = port_info.get('name', 'unknown')
                version = port_info.get('version', '')
                print(f"   Port {port}/tcp: {service} {version}")
```

### Built-in Stealth Scanning

```python
# Using built-in evasion profiles
result = scanner.scan(
    hosts='target.com',
    ports='22,80,443,8080',
    evasion_profile=nmap.EvasionProfile.STEALTH
)

# Maximum stealth with ghost profile
result = scanner.scan(
    hosts='sensitive-target.com',
    ports='1-1000',
    evasion_profile=nmap.EvasionProfile.GHOST
)

# Convenience functions
result = nmap.scan_stealth('target.com', '22,80,443')
result = nmap.scan_ghost('target.com', '1-1000')
```

### Async and Memory-Efficient Scanning

```python
# Async scanning with callback
def scan_callback(host, result):
    print(f"Completed scan for {host}")
    # Process results immediately

nmap.scan_progressive('192.168.1.0/24', callback=scan_callback)

# Memory-efficient large network scanning
yield_scanner = nmap.YieldScanner()
for host, result in yield_scanner.scan('10.0.0.0/16'):
    if result.get('scan'):
        print(f"Found host: {host}")
```
        randomize_hosts=True,
        random_decoys=5,
        spoof_mac="00:11:22:33:44:55"
    )
)
```

### Advanced Features

```python
# Enable performance monitoring
nmap.enable_performance_monitoring(True)

# Configure caching for repeated scans
scanner.enable_caching(True, max_age=600)  # 10 minutes

# Get performance statistics
stats = scanner.get_performance_stats()
print(f"Scan duration: {stats['scan_duration']}s")
print(f"Hosts scanned: {stats['hosts_scanned']}")

# Enhanced host information
host_dict = nmap.PortScannerHostDict(result, '192.168.1.1')
print(f"Primary hostname: {host_dict.hostname()}")
print(f"All hostnames: {host_dict.hostnames()}")
print(f"Host state: {host_dict.state()}")
```

### NSE Script Integration

```python
# NSE scripts work through nmap arguments
result = scanner.scan(
    hosts='web-server.example.com',
    ports='80,443',
    arguments='--script http-title,http-headers,ssl-cert'
)

# Check for script output in results
for host in result['scan']:
    if 'tcp' in result['scan'][host]:
        for port, port_info in result['scan'][host]['tcp'].items():
            if 'script' in port_info:
                for script_name, script_output in port_info['script'].items():
                    print(f"Script {script_name}: {script_output}")
```

### Cross-Platform Compatibility

```python
# Automatic nmap detection across platforms
scanner = nmap.PortScanner()  # Finds nmap automatically

# Custom nmap path if needed
scanner = nmap.PortScanner(nmap_search_path=['/custom/path/nmap'])

# Check nmap version
version = scanner.nmap_version()
print(f"Using nmap version: {version[0]}.{version[1]}")
```

## 📖 Usage Guide

### All Scan Types Support

```python
# All nmap scan types available through arguments
scanner = nmap.Scanner()

# TCP scans
result = scanner.scan('target.com', '80,443', '-sS')  # SYN scan
result = scanner.scan('target.com', '80,443', '-sT')  # Connect scan
result = scanner.scan('target.com', '80,443', '-sA')  # ACK scan
result = scanner.scan('target.com', '80,443', '-sW')  # Window scan
result = scanner.scan('target.com', '80,443', '-sM')  # Maimon scan

# Stealth scans
result = scanner.scan('target.com', '80,443', '-sN')  # NULL scan
result = scanner.scan('target.com', '80,443', '-sF')  # FIN scan
result = scanner.scan('target.com', '80,443', '-sX')  # Xmas scan

# Other protocols
result = scanner.scan('target.com', '53,161', '-sU')   # UDP scan
result = scanner.scan('target.com', '80,443', '-sY')   # SCTP INIT
result = scanner.scan('target.com', '80,443', '-sZ')   # SCTP COOKIE
result = scanner.scan('target.com', '', '-sO')         # IP protocol
```

### Enhanced Scanning Techniques

```python
# Service and version detection
result = scanner.scan('target.com', '22,80,443', '-sV')

# OS detection
result = scanner.scan('target.com', '1-1000', '-O')

# Aggressive scanning (OS, version, scripts, traceroute)
result = scanner.scan('target.com', '1-1000', '-A')

# Fast scan (top 100 ports)
result = scanner.scan('target.com', '', '-F')

# Comprehensive scan with timing
result = scanner.scan('target.com', '1-65535', '-sS -sV -O -T4')
```

### NSE Script Integration

```python
# Run specific NSE scripts
result = scanner.scan(
    hosts='web-server.com',
    ports='80,443',
    arguments='--script http-title,http-headers,ssl-cert'
)

# Run script categories
result = scanner.scan(
    hosts='target.com',
    ports='22,80,443',
    arguments='--script vuln,auth'
)

# Custom script arguments
result = scanner.scan(
    hosts='web-server.com',
    ports='80',
    arguments='--script http-enum --script-args http-enum.basepath=/admin'
)
```

# SCTP INIT Scan
scanner.scan_comprehensive(targets="target.com", scan_type=ScanType.SCTP_INIT)

# SCTP COOKIE-ECHO Scan
scanner.scan_comprehensive(targets="target.com", scan_type=ScanType.SCTP_COOKIE_ECHO)
```

### Complete Evasion Technique Arsenal

#### Built-in Stealth Profiles
```python
# Using built-in evasion profiles
result = scanner.scan(
    hosts='target.com',
    ports='22,80,443',
    evasion_profile=nmap.EvasionProfile.STEALTH
)

# Maximum stealth with ghost profile
result = scanner.scan(
    hosts='sensitive-target.com',
    ports='1-1000',
    evasion_profile=nmap.EvasionProfile.GHOST
)
```

#### Convenience Functions
```python
# Quick stealth scanning
result = nmap.scan_stealth('target.com', '1-1000')

# Maximum evasion scanning
result = nmap.scan_ghost('target.com', '80,443')

# Progressive async scanning
def scan_callback(host, result):
    print(f"Completed scan for {host}")

nmap.scan_progressive('192.168.1.0/24', callback=scan_callback)
```

#### Advanced Evasion Integration
```python
# Custom stealth scanning with additional arguments
result = scanner.scan_with_evasion(
    hosts='target.com',
    ports='22,80,443',
    profile=nmap.EvasionProfile.STEALTH,
    additional_args='--source-port 53'
)
```

### Enterprise Security Features

#### Security Constraints
```python
from nmap import config_manager

# Configure security policies
security = config_manager.get_security_constraints()
print(f"Max scan timeout: {security.max_scan_timeout}s")
print(f"Allowed networks: {security.allowed_target_networks}")

# Validate scan arguments
is_valid = config_manager.validate_scan_arguments("-sS -p 80,443")
```

#### Audit Logging
```python
# All scans are automatically logged for compliance
# Configure audit settings via environment variables:
# NMAP_ENABLE_AUDIT=true
# NMAP_AUDIT_LOG_PATH=/var/log/nmap_audit.log
# NMAP_AUDIT_RETENTION_DAYS=90
```

### Performance Optimization

#### Built-in Performance Features
```python
# Enable performance monitoring
nmap.enable_performance_monitoring(True)

# Configure intelligent caching
scanner.enable_caching(True, max_age=600)  # 10 minutes

# Get performance statistics
stats = scanner.get_performance_stats()
print(f"Scan duration: {stats['scan_duration']:.2f}s")
print(f"Hosts scanned: {stats['hosts_scanned']}")
```

#### Timing Control via Arguments
```python
# Fast aggressive scanning
result = scanner.scan('target.com', '1-1000', '-T4 --min-rate 1000')

# Stealth timing with delays
result = scanner.scan('target.com', '80,443', '-T1 --scan-delay 2s')

# Paranoid stealth scanning
result = scanner.scan('target.com', '22,80,443', '-T0 --max-scan-delay 5s')
```

#### Cache Management
```python
# Configure global cache settings
nmap.set_cache_max_age(300)  # 5 minutes

# Clear all cached results
nmap.clear_global_cache()

# Clear scanner-specific cache
scanner.clear_cache()
```

#### Scan Caching and Metrics
```python
# Get performance metrics
metrics = scanner.get_scan_metrics()
for scan_id, metric in metrics.items():
    print(f"Scan {scan_id}: {metric['duration']:.2f}s - {metric['success']}")

# Monitor active scans
active = scanner.get_active_scans()
print(f"Currently running: {len(active)} scans")
```

### Convenience Functions

```python
from nmap import quick_scan, stealth_scan, aggressive_scan, vulnerability_scan

# Quick basic scan
result = quick_scan("192.168.1.100", ports="22,80,443")

# Stealth scan with evasion
result = stealth_scan("target.com", ports="1-1000")

# Aggressive information gathering
result = aggressive_scan("target.com", ports="1-65535")

# Vulnerability assessment
result = vulnerability_scan("web-server.com", ports="80,443")
```

### Legacy Compatibility

```python
# Traditional PortScanner interface still available
from nmap import PortScanner

scanner = PortScanner()
result = scanner.scan('192.168.1.1', '22-443')

# Enhanced with new capabilities
for host in scanner.all_hosts():
    print(f"Host: {host} - {scanner[host].state()}")
```
        if scan_result:
            self.results.append((host, scan_result))
            print(f"✅ Completed scan for {host}")
        else:
            print(f"❌ Failed to scan {host}")
    
    def scan_network_async(self, network, ports):
        """Perform asynchronous network scan"""
        scanner = nmap.PortScannerAsync()
        
        scanner.scan(
            hosts=network,
            ports=ports,
            arguments='-sS -sV',
            callback=self.scan_callback
        )
        
        # Monitor scan progress
        while scanner.still_scanning():
            print(f"⏳ Scanning in progress... ({len(self.results)} hosts completed)")
            time.sleep(2)
        
        print(f"🎉 Network scan completed! Found {len(self.results)} responsive hosts")
        return self.results

# Usage
network_scanner = NetworkScanner()
results = network_scanner.scan_network_async('192.168.1.0/24', '22,80,443,8080')
```

### Generator-Based Processing

```python
def process_large_network(network_range, ports):
    """Efficiently process large network ranges"""
    scanner = nmap.PortScannerYield()
    
    active_hosts = []
    
    for host, result in scanner.scan(network_range, ports=ports, arguments='-sS'):
        if result and result['nmap']['scanstats']['uphosts'] != '0':
            active_hosts.append(host)
            print(f"📡 Active host discovered: {host}")
            
            # Process immediately to save memory
            yield host, result
    
    print(f"🔍 Discovery complete: {len(active_hosts)} active hosts found")

# Process enterprise network efficiently
for host, data in process_large_network('10.0.0.0/16', '22,80,443'):
    # Handle each host as discovered
    pass
```

### Data Export and Analysis

```python
import csv
from datetime import datetime

def export_scan_results(scanner, filename=None):
    """Export scan results to multiple formats"""
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nmap_scan_{timestamp}"
    
    # Export to CSV
    csv_data = scanner.csv()
    with open(f"{filename}.csv", 'w', newline='') as f:
        f.write(csv_data)
    
    # Export raw XML
    xml_data = scanner.get_nmap_last_output()
    with open(f"{filename}.xml", 'w') as f:
        f.write(xml_data)
    
    print(f"📄 Results exported:")
    print(f"   CSV: {filename}.csv")
    print(f"   XML: {filename}.xml")
    
    return filename

# Usage
scanner.scan('192.168.1.0/24', '22,80,443,8080', '-sV')
export_scan_results(scanner, "network_audit_2024")
```

## 🔧 API Reference

### Core Classes

#### `PortScanner`
Primary synchronous scanning interface.

```python
scanner = nmap.PortScanner()
```

**Key Methods:**
- `scan(hosts, ports=None, arguments='-sV', sudo=False, timeout=0)` - Execute scan
- `listscan(hosts)` - Host discovery without port scanning
- `all_hosts()` - Retrieve all discovered hosts
- `has_host(host)` - Check if host exists in results
- `csv()` - Export results as CSV
- `get_nmap_last_output()` - Get raw XML output

#### `PortScannerAsync`
High-performance asynchronous scanning.

```python
async_scanner = nmap.PortScannerAsync()
async_scanner.scan(hosts, ports, arguments, callback)
```

#### `PortScannerYield`
Memory-efficient generator-based scanning.

```python
yield_scanner = nmap.PortScannerYield()
for host, result in yield_scanner.scan(hosts, ports):
    process_host(host, result)
```

### Host Data Access

```python
# Access host information
host = scanner['192.168.1.1']

# Host properties
host.hostname()              # DNS hostname
host.state()                # Host state (up/down)
host.all_protocols()        # Available protocols
host.all_tcp()              # TCP ports
host.all_udp()              # UDP ports

# Port-specific data
host.has_tcp(80)            # Check TCP port existence
port_info = host.tcp(80)    # Get port details
```

## 🛡️ Security Best Practices

### Ethical Scanning Guidelines

```python
import ipaddress

def validate_scan_target(target):
    """Validate scan targets against ethical guidelines"""
    
    # Define restricted networks
    restricted_networks = [
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('224.0.0.0/4'),    # Multicast
        ipaddress.ip_network('127.0.0.0/8'),    # Loopback (allow for testing)
    ]
    
    try:
        target_network = ipaddress.ip_network(target, strict=False)
        
        for restricted in restricted_networks:
            if target_network.overlaps(restricted) and not target.startswith('127.'):
                raise ValueError(f"Scanning {target} is not recommended")
                
    except ValueError as e:
        print(f"⚠️  Target validation warning: {e}")
        return False
    
    return True

# Always validate targets
if validate_scan_target('192.168.1.0/24'):
    scanner.scan('192.168.1.0/24', '22,80,443')
```

### Error Handling and Resilience

```python
import logging
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@contextmanager
def safe_scan_context():
    """Context manager for safe scanning with cleanup"""
    scanner = None
    try:
        scanner = nmap.PortScanner()
        yield scanner
    except nmap.PortScannerError as e:
        logger.error(f"Scan error: {e}")
        raise
    except nmap.PortScannerTimeout as e:
        logger.warning(f"Scan timeout: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise
    finally:
        if scanner:
            logger.info("Scan context cleanup completed")

# Robust scanning implementation
def robust_network_scan(network, ports, max_retries=3):
    """Perform network scan with retry logic"""
    
    for attempt in range(max_retries):
        try:
            with safe_scan_context() as scanner:
                result = scanner.scan(network, ports, arguments='-sS -T3')
                return scanner, result
                
        except nmap.PortScannerTimeout:
            if attempt < max_retries - 1:
                logger.warning(f"Timeout on attempt {attempt + 1}, retrying...")
                continue
            raise
        except nmap.PortScannerError as e:
            logger.error(f"Scan failed: {e}")
            if "permission" in str(e).lower():
                logger.info("Try running with sudo for raw socket access")
            raise

# Usage
try:
    scanner, results = robust_network_scan('192.168.1.0/24', '22,80,443')
    logger.info(f"Successfully scanned {len(scanner.all_hosts())} hosts")
except Exception as e:
    logger.error(f"Network scan failed: {e}")
```

## 📊 Common Scan Patterns

| Scan Type | Command | Use Case |
|-----------|---------|----------|
| **Host Discovery** | `-sn` | Network reconnaissance |
| **Stealth Scan** | `-sS` | Firewall evasion |
| **Version Detection** | `-sV` | Service enumeration |
| **OS Detection** | `-O` | Operating system fingerprinting |
| **Aggressive Scan** | `-A` | Comprehensive analysis |
| **Script Scan** | `--script <category>` | Vulnerability assessment |
| **UDP Scan** | `-sU` | UDP service discovery |
| **Fast Scan** | `-T4 --min-rate 1000` | Time-sensitive scanning |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/codeNinja62/nust-nmap.git
cd nust-nmap

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Sameer Ahmed**
- Email: [sameer.cs@proton.me](mailto:sameer.cs@proton.me)
- GitHub: [@codeNinja62](https://github.com/codeNinja62)

## 🙏 Acknowledgments

- Built upon the robust [Nmap Security Scanner](https://nmap.org/)
- Inspired by the original python-nmap library
- Special thanks to the cybersecurity community for feedback and contributions

## 🔗 Links

- [📦 PyPI Package](https://pypi.org/project/nust-nmap/)
- [📚 Documentation](https://github.com/codeNinja62/nust-nmap/wiki)
- [🐛 Issue Tracker](https://github.com/codeNinja62/nust-nmap/issues)
- [🌐 Nmap Official Site](https://nmap.org/)

## ⚠️ Legal Disclaimer

**IMPORTANT: This tool is designed for authorized security testing and network administration only.**

- ✅ **Authorized Use**: Own networks, approved penetration testing, security research
- ❌ **Prohibited Use**: Unauthorized scanning, malicious activities, illegal reconnaissance

**Users are solely responsible for compliance with applicable laws and regulations. Always obtain explicit permission before scanning networks you do not own or administer.**

---

*"Know your network, secure your future."* 🛡️