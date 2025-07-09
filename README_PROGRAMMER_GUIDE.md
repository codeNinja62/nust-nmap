# nust-nmap: Comprehensive Technical Reference

> **Enterprise-Grade Python Nmap Wrapper for Developers**  
> Complete technical documentation for integrating nust-nmap into production systems.

---

## 📋 **Table of Contents**

1. [Architecture Overview](#architecture-overview)
2. [Core Classes & APIs](#core-classes--apis)
3. [Advanced Usage Patterns](#advanced-usage-patterns)
4. [Security & Evasion](#security--evasion)
5. [Performance Optimization](#performance-optimization)
6. [Enterprise Integration](#enterprise-integration)
7. [Error Handling](#error-handling)
8. [Migration Guide](#migration-guide)

---

## 🏗️ **Architecture Overview**

### Design Principles
- **Zero Redundancy**: Single enhanced API, no duplicate functionality
- **Thread Safety**: Safe for concurrent enterprise use
- **Resource Management**: Automatic cleanup and leak prevention
- **Security Focus**: Input validation and safe temporary file handling
- **Comprehensive Error Handling**: Contextual exceptions with recovery strategies

### Core Components
```python
nmap/
├── PortScanner          # Primary synchronous interface
├── PortScannerAsync     # Asynchronous scanning with callbacks
├── PortScannerYield     # Memory-efficient generator-based scanning
├── PortScannerHostDict  # Enhanced host data access
└── Evasion & Security   # Built-in stealth and validation
```

---

## 🔧 **Core Classes & APIs**
        if info['state'] == 'open':
            print(f"  {port}/tcp - {info['name']} {info.get('version', '')}")

# Vulnerability assessment
vulns = nm.vuln_scan("target.com")
vuln_summary = nm.vulnerability_summary()
```

## Advanced Usage

### Stealth and Evasion
```python
# Stealth scanning with evasion
result = nm.scan_with_evasion(
    "target.com", 
    profile=nmap.EvasionProfile.GHOST,
    additional_args="-p 80,443"
)

# Custom evasion techniques
result = nm.advanced_evasion_scan(
    "target.com",
    fragment=True,
    decoys="192.168.1.1,192.168.1.2,ME,192.168.1.3",
    spoof_mac=True
)
```

### Asynchronous Scanning
```python
def host_found(host, data):
    print(f"Discovered: {host}")
    # Process immediately for real-time analysis

nm_async = nmap.PortScannerAsync()
nm_async.scan("192.168.1.0/24", callback=host_found)
nm_async.wait()
```

### Memory-Efficient Large Networks
```python
# Scan large networks without memory issues
nm_yield = nmap.PortScannerYield()
for host, data in nm_yield.scan("10.0.0.0/16", "80,443"):
    # Process one host at a time
    analyze_host(host, data)
```

### Specialized Scanning
```python
# Web application scanning
web_result = nm.web_scan("target.com")

# Database service discovery
db_result = nm.database_scan("target.com")

# SSL/TLS security assessment
ssl_result = nm.ssl_scan("target.com")

# SMB/NetBIOS enumeration
smb_result = nm.smb_scan("target.com")
```

### Performance Optimization
```python
# Enable caching for repeated scans
nm.enable_caching(enabled=True, max_age=300)

# Parallel scanning for speed
result = nm.parallel_scan("192.168.1.0/24", max_workers=10)

# Adaptive timing based on target responsiveness
result = nm.adaptive_timing_scan("target.com")
```

### Compliance and Audit
```python
# PCI DSS compliance scanning
pci_result = nm.compliance_scan("target.com", standard="pci")

# Comprehensive security audit
audit_result = nm.audit_scan("target.com")

# Generate compliance reports
json_report = nm.generate_report(format_type="json")
csv_report = nm.generate_report(format_type="csv")
```

## Network Analysis System Example

```python
import nmap
from typing import Dict, List, Any

class NetworkAnalyzer:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.scanner.enable_caching(True, 300)
        
    def discover_network(self, network: str) -> List[str]:
        """Discover live hosts in network"""
        result = self.scanner.network_discovery(network)
        return self.scanner.all_hosts()
    
    def analyze_host(self, host: str) -> Dict[str, Any]:
        """Comprehensive host analysis"""
        # Service detection
        services = self.scanner.version_scan(host, "1-65535")
        
        # Vulnerability assessment
        vulns = self.scanner.vuln_scan(host)
        
        # OS detection
        os_info = self.scanner.os_scan(host)
        
        return {
            'host': host,
            'services': self._extract_services(host),
            'vulnerabilities': self.scanner.vulnerability_summary(),
            'os': self._extract_os(host),
            'security_score': self._calculate_security_score(host)
        }
    
    def security_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Security-focused scanning with evasion"""
        results = {}
        
        for target in targets:
            # Use stealth scanning
            result = self.scanner.scan_with_evasion(
                target,
                profile=nmap.EvasionProfile.STEALTH
            )
            
            # Firewall detection
            fw_test = self.scanner.firewall_test_scan(target)
            
            results[target] = {
                'scan_result': result,
                'firewall_analysis': fw_test,
                'performance': self.scanner.get_performance_stats()
            }
        
        return results

# Usage
analyzer = NetworkAnalyzer()
hosts = analyzer.discover_network("192.168.1.0/24")
for host in hosts:
    analysis = analyzer.analyze_host(host)
    print(f"Host {host}: {analysis['security_score']} security score")
```

## Best Practices

### 1. Resource Management
```python
# Always enable caching for repeated scans
nm.enable_caching(True, 300)

# Use yield scanner for large networks
nm_yield = nmap.PortScannerYield()
for host, data in nm_yield.scan("large_network"):
    process_immediately(host, data)  # Don't accumulate in memory
```

### 2. Error Handling
```python
try:
    result = nm.scan(target, ports)
except nmap.PortScannerTimeout:
    # Handle timeouts specifically
    result = nm.scan(target, ports, timeout=300)
except nmap.PortScannerError as e:
    # Handle other scan errors
    logger.error(f"Scan failed: {e}")
```

### 3. Security Considerations
```python
# Use evasion for sensitive environments
result = nm.scan_with_evasion(
    target, 
    profile=nmap.EvasionProfile.GHOST
)

# Validate inputs (built-in, but be aware)
# The library automatically validates hosts and ports
```

### 4. Performance Optimization
```python
# For large deployments
nm.enable_performance_monitoring(True)
result = nm.parallel_scan(targets, max_workers=cpu_count())
stats = nm.get_performance_stats()
```

## Integration Examples

### With Security Frameworks
```python
# MISP integration example
def export_to_misp(scan_results):
    misp_event = create_misp_event()
    for host, data in scan_results.items():
        misp_event.add_attribute('ip-dst', host)
        # Add service and vulnerability attributes
    
# SIEM integration example  
def send_to_siem(scan_results):
    for host, vulns in scan_results.items():
        siem_alert = create_alert(host, vulns)
        siem_client.send(siem_alert)
```

### With Automation Platforms
```python
# Ansible playbook integration
def ansible_inventory_from_scan(network):
    nm = nmap.PortScanner()
    hosts = nm.network_discovery(network)
    
    inventory = {'all': {'hosts': {}}}
    for host in hosts:
        services = nm.version_scan(host)
        inventory['all']['hosts'][host] = {
            'ansible_host': host,
            'services': extract_services(services)
        }
    return inventory
```

## Conclusion

This nust-nmap implementation provides a production-ready, enterprise-grade Python interface to nmap that enables programmers to easily build sophisticated network and vulnerability analysis systems. All enhancements are seamlessly integrated into the original API following strict quality guidelines.

The library supports the complete nmap feature set while adding enterprise capabilities like caching, async operations, advanced evasion, and comprehensive error handling—making it ideal for both simple scripts and complex security platforms.

---

## 📚 **Advanced Examples**

See the [examples/](examples/) directory for comprehensive usage examples:

- `comprehensive_usage_guide.py` - Complete feature demonstration
- `async_scan.py` - Asynchronous scanning patterns
- `network_discovery.py` - Enterprise network discovery
- `yield_scanner.py` - Memory-efficient large network scanning

---

## 🔗 **Related Documentation**

- **[Main README](README.md)**: Quick start and basic usage
- **[API Reference](docs/)**: Complete API documentation
- **[Changelog](docs/CHANGELOG.md)**: Version history and updates
- **[Features Matrix](docs/Features.md)**: Complete feature coverage

---

<p align="center">
    <strong>📖 For basic usage, see the <a href="README.md">main README</a></strong>
</p>

---

## PortScanner (Primary Interface)

The main synchronous scanning interface with enhanced capabilities built-in.

```python
import nmap

# Initialize with automatic nmap detection
scanner = nmap.PortScanner()

# Initialize with custom nmap path
scanner = nmap.PortScanner(nmap_search_path=['/custom/path'])

# Enhanced scanning methods
result = scanner.scan(
    hosts='192.168.1.0/24',          # Target specification
    ports='22,80,443,8080-8090',     # Port ranges
    arguments='-sS -sV -O',          # nmap arguments
    sudo=False,                      # Privilege escalation
    timeout=300,                     # Scan timeout (seconds)
    evasion_profile=nmap.EvasionProfile.STEALTH  # Built-in evasion
)
```

#### Core Methods
```python
# Scanning operations
scanner.scan(hosts, ports=None, arguments='-sV', **kwargs)
scanner.listscan(hosts)  # Host discovery only
scanner.all_hosts()      # Get discovered hosts
scanner.csv()           # Export to CSV format

# Enhanced specialized scans
scanner.network_discovery(network)           # Network enumeration
scanner.version_scan(hosts, ports)          # Service detection
scanner.vuln_scan(hosts, ports=None)        # Vulnerability assessment
scanner.os_scan(hosts, ports=None)          # OS fingerprinting
scanner.script_scan(hosts, scripts, ports=None)  # NSE script execution

# Stealth and evasion
scanner.scan_with_evasion(hosts, profile, additional_args="")
scanner.stealth_scan(hosts, ports=None)     # Quick stealth scanning
scanner.ghost_scan(hosts, ports=None)       # Maximum stealth

# Performance and caching
scanner.enable_caching(enabled=True, max_age=300)
scanner.get_performance_stats()
scanner.parallel_scan(hosts, max_workers=10)
```

### PortScannerAsync (Asynchronous Interface)

High-performance non-blocking scanning with callback support.

```python
import nmap

async_scanner = nmap.PortScannerAsync()

def scan_complete_callback(host, scan_result):
    """Process results as they arrive"""
    print(f"Scan completed for {host}")
    if scan_result.get('scan'):
        # Process host data immediately
        process_host_data(host, scan_result['scan'][host])

# Start asynchronous scan
async_scanner.scan(
    hosts='192.168.1.0/24',
    ports='22,80,443',
    arguments='-sS -sV',
    callback=scan_complete_callback
)

# Wait for completion
async_scanner.wait()

# Check scan status
still_scanning = async_scanner.still_scanning()
```

### PortScannerYield (Memory-Efficient Interface)

Generator-based scanning for large networks without memory overhead.

```python
import nmap

yield_scanner = nmap.PortScannerYield()

# Process large networks efficiently
for host, scan_data in yield_scanner.scan('10.0.0.0/16', '80,443'):
    if scan_data.get('scan'):
        # Process one host at a time
        host_info = scan_data['scan'][host]
        if 'tcp' in host_info:
            open_ports = [p for p, info in host_info['tcp'].items() 
                         if info['state'] == 'open']
            if open_ports:
                store_in_database(host, open_ports)
```

### PortScannerHostDict (Enhanced Host Access)

Rich host data access with additional methods for detailed analysis.

```python
# Access host data
host = scanner['192.168.1.100']

# Basic properties
hostname = host.hostname()           # Primary hostname
hostnames = host.hostnames()         # All hostnames
state = host.state()                 # Host state (up/down/unknown)

# Protocol and port access
protocols = host.all_protocols()     # ['tcp', 'udp', 'ip']
tcp_ports = host.all_tcp()          # Dict of TCP ports
udp_ports = host.all_udp()          # Dict of UDP ports

# Port-specific queries
has_port = host.has_tcp(80)         # Boolean port check
port_info = host.tcp(80)            # Detailed port information

# Advanced host analysis
os_info = host.get_os_info()        # OS detection results
script_results = host.get_script_results()  # NSE script outputs
```

---

## 🚀 **Advanced Usage Patterns**

### Enterprise Network Discovery

```python
import nmap
from concurrent.futures import ThreadPoolExecutor
import ipaddress

class EnterpriseNetworkScanner:
    def __init__(self, max_workers=20):
        self.scanner = nmap.PortScanner()
        self.max_workers = max_workers
        
    def discover_enterprise_network(self, networks, ports="22,80,443,8080"):
        """Discover assets across multiple enterprise networks"""
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for network in networks:
                future = executor.submit(self._scan_network, network, ports)
                futures[future] = network
                
            for future in futures:
                network = futures[future]
                try:
                    results[network] = future.result()
                except Exception as e:
                    print(f"Failed to scan {network}: {e}")
                    
        return results
    
    def _scan_network(self, network, ports):
        """Scan individual network segment"""
        result = self.scanner.scan(network, ports, '-sS -sV --open')
        return self._process_results(result)
    
    def _process_results(self, scan_result):
        """Extract actionable intelligence from scan results"""
        assets = []
        
        for host in self.scanner.all_hosts():
            host_data = self.scanner[host]
            asset = {
                'ip': host,
                'hostname': host_data.hostname(),
                'state': host_data.state(),
                'services': {}
            }
            
            # Extract service information
            for protocol in host_data.all_protocols():
                ports = host_data[protocol]
                for port, info in ports.items():
                    if info['state'] == 'open':
                        asset['services'][f"{port}/{protocol}"] = {
                            'service': info.get('name', 'unknown'),
                            'version': info.get('version', ''),
                            'product': info.get('product', ''),
                            'cpe': info.get('cpe', [])
                        }
            
            assets.append(asset)
            
        return assets

# Usage
scanner = EnterpriseNetworkScanner()
networks = ['192.168.1.0/24', '10.0.0.0/16', '172.16.0.0/12']
enterprise_assets = scanner.discover_enterprise_network(networks)
```

### Vulnerability Assessment Pipeline

```python
import nmap
import json
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def comprehensive_vuln_assessment(self, targets, output_file=None):
        """Perform comprehensive vulnerability assessment"""
        
        # Phase 1: Discovery and port scanning
        print("Phase 1: Network discovery...")
        discovery_result = self.scanner.scan(
            targets, 
            arguments='-sS -sV -O --top-ports 1000'
        )
        
        # Phase 2: Vulnerability scanning
        print("Phase 2: Vulnerability assessment...")
        vuln_result = self.scanner.scan(
            targets,
            arguments='--script vuln,auth,safe --script-timeout 10m'
        )
        
        # Phase 3: Analysis and reporting
        print("Phase 3: Analysis...")
        vulnerabilities = self._analyze_vulnerabilities()
        
        # Generate report
        report = self._generate_vuln_report(vulnerabilities)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
                
        return report
    
    def _analyze_vulnerabilities(self):
        """Extract and categorize vulnerabilities"""
        vulnerabilities = {'critical': [], 'high': [], 'medium': [], 'low': []}
        
        for host in self.scanner.all_hosts():
            host_data = self.scanner[host]
            
            # Check for script results
            for protocol in host_data.all_protocols():
                ports = host_data[protocol]
                for port, info in ports.items():
                    if 'script' in info:
                        for script_name, script_output in info['script'].items():
                            vuln = self._parse_vulnerability(
                                host, port, protocol, script_name, script_output
                            )
                            if vuln:
                                severity = self._assess_severity(vuln)
                                vulnerabilities[severity].append(vuln)
        
        return vulnerabilities
    
    def _parse_vulnerability(self, host, port, protocol, script, output):
        """Parse vulnerability information from script output"""
        # Implementation depends on specific vulnerability scripts
        return {
            'host': host,
            'port': f"{port}/{protocol}",
            'script': script,
            'description': output,
            'timestamp': datetime.now().isoformat()
        }
    
    def _assess_severity(self, vulnerability):
        """Assess vulnerability severity based on script and context"""
        # Implement severity assessment logic
        critical_scripts = ['ssl-heartbleed', 'ms17-010', 'smb-vuln-ms08-067']
        if vulnerability['script'] in critical_scripts:
            return 'critical'
        return 'medium'  # Default
    
    def _generate_vuln_report(self, vulnerabilities):
        """Generate comprehensive vulnerability report"""
        return {
            'scan_timestamp': datetime.now().isoformat(),
            'summary': {
                'critical': len(vulnerabilities['critical']),
                'high': len(vulnerabilities['high']),
                'medium': len(vulnerabilities['medium']),
                'low': len(vulnerabilities['low'])
            },
            'vulnerabilities': vulnerabilities,
            'recommendations': self._generate_recommendations(vulnerabilities)
        }
```

---

## 🛡️ **Security & Evasion**

### Built-in Evasion Profiles

```python
import nmap

scanner = nmap.PortScanner()

# Predefined evasion profiles
profiles = {
    nmap.EvasionProfile.BASIC: "Basic stealth (-T2 --randomize-hosts)",
    nmap.EvasionProfile.STEALTH: "Advanced stealth (-T1 -f --scan-delay)",
    nmap.EvasionProfile.GHOST: "Maximum stealth (-T0 -f -f --spoof-mac 0)", 
    nmap.EvasionProfile.ADAPTIVE: "Context-aware evasion selection"
}

# Use predefined profiles
result = scanner.scan(
    hosts='target.com',
    evasion_profile=nmap.EvasionProfile.GHOST
)

# Advanced custom evasion
result = scanner.scan(
    hosts='target.com',
    arguments='-sS -f -f --scan-delay 2s --data-length 25 -D RND:10'
)
```

### Security Validation

```python
import nmap

# Input validation is automatic
scanner = nmap.PortScanner()

try:
    # This will raise PortScannerError due to validation
    result = scanner.scan('target.com; rm -rf /', '80')
except nmap.PortScannerError as e:
    print(f"Security validation caught: {e}")

# Safe argument handling
safe_args = scanner._validate_nmap_arguments('-sS -sV')
print(f"Arguments validated: {safe_args}")
```

---

## ⚡ **Performance Optimization**

### Intelligent Caching

```python
import nmap

scanner = nmap.PortScanner()

# Enable caching with custom TTL
scanner.enable_caching(enabled=True, max_age=600)  # 10 minutes

# First scan - hits nmap
result1 = scanner.scan('192.168.1.100', '80,443')

# Second scan - hits cache (if within TTL)
result2 = scanner.scan('192.168.1.100', '80,443')

# Cache management
cache_stats = scanner.get_cache_stats()
print(f"Cache hits: {cache_stats['hits']}, misses: {cache_stats['misses']}")

# Clear cache
scanner.clear_cache()
```

### Performance Monitoring

```python
import nmap

# Enable global performance monitoring
nmap.enable_performance_monitoring(True)

scanner = nmap.PortScanner()
result = scanner.scan('192.168.1.0/24', '22,80,443')

# Get performance metrics
stats = scanner.get_performance_stats()
print(f"Scan duration: {stats['scan_duration']:.2f}s")
print(f"Hosts scanned: {stats['hosts_scanned']}")
print(f"Ports per second: {stats['ports_per_second']:.1f}")

# Resource usage (if psutil available)
if stats.get('resource_usage'):
    usage = stats['resource_usage']
    print(f"CPU usage: {usage['cpu_percent']:.1f}%")
    print(f"Memory usage: {usage['memory_mb']:.1f}MB")
```

### Parallel Scanning

```python
import nmap

scanner = nmap.PortScanner()

# Parallel scanning for improved performance
result = scanner.parallel_scan(
    hosts='192.168.1.0/24',
    max_workers=10,
    chunk_size=5  # Hosts per worker
)

# Adaptive timing based on network conditions
result = scanner.adaptive_timing_scan('192.168.1.0/24')
```

---

## 🏢 **Enterprise Integration**

### Configuration Management

```python
import nmap
import os

# Environment-based configuration
scanner = nmap.PortScanner()

# Configure via environment variables
scan_timeout = int(os.getenv('NMAP_SCAN_TIMEOUT', '300'))
cache_ttl = int(os.getenv('NMAP_CACHE_TTL', '300'))
max_workers = int(os.getenv('NMAP_MAX_WORKERS', '10'))

scanner.enable_caching(True, max_age=cache_ttl)

# Security constraints from environment
allowed_networks = os.getenv('NMAP_ALLOWED_NETWORKS', '').split(',')
if allowed_networks and targets not in allowed_networks:
    raise ValueError("Target network not in allowed list")
```

### Audit Logging

```python
import nmap
import logging
from datetime import datetime

# Configure audit logging
audit_logger = logging.getLogger('nmap.audit')
audit_logger.setLevel(logging.INFO)

handler = logging.FileHandler('/var/log/nmap_audit.log')
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

class AuditedScanner(nmap.PortScanner):
    def scan(self, hosts, ports=None, arguments='-sV', **kwargs):
        # Log scan initiation
        audit_logger.info(f"SCAN_START: user={os.getuser()}, "
                         f"targets={hosts}, ports={ports}, args={arguments}")
        
        try:
            result = super().scan(hosts, ports, arguments, **kwargs)
            
            # Log successful completion
            host_count = len(self.all_hosts())
            audit_logger.info(f"SCAN_SUCCESS: hosts_discovered={host_count}")
            
            return result
            
        except Exception as e:
            # Log failures
            audit_logger.error(f"SCAN_FAILURE: error={str(e)}")
            raise

# Usage
scanner = AuditedScanner()
result = scanner.scan('192.168.1.0/24', '22,80,443')
```

### Database Integration

```python
import nmap
import sqlite3
from datetime import datetime

class DatabaseIntegratedScanner:
    def __init__(self, db_path='scan_results.db'):
        self.scanner = nmap.PortScanner()
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                target TEXT,
                host TEXT,
                port INTEGER,
                protocol TEXT,
                state TEXT,
                service TEXT,
                version TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def scan_and_store(self, targets, ports='22,80,443'):
        """Scan targets and store results in database"""
        result = self.scanner.scan(targets, ports, '-sS -sV')
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        timestamp = datetime.now().isoformat()
        
        for host in self.scanner.all_hosts():
            host_data = self.scanner[host]
            
            for protocol in host_data.all_protocols():
                ports_data = host_data[protocol]
                
                for port, info in ports_data.items():
                    cursor.execute('''
                        INSERT INTO scan_results 
                        (timestamp, target, host, port, protocol, state, service, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        timestamp, targets, host, port, protocol,
                        info['state'], info.get('name', ''), info.get('version', '')
                    ))
        
        conn.commit()
        conn.close()
        
        return result
```

---

## 🚨 **Error Handling**

### Exception Hierarchy

```python
import nmap

try:
    scanner = nmap.PortScanner()
    result = scanner.scan('invalid-target', '80')
    
except nmap.PortScannerError as e:
    # Base exception for all nmap-related errors
    print(f"Scanner error: {e}")
    
except nmap.PortScannerTimeout as e:
    # Specific timeout handling
    print(f"Scan timeout: {e}")
    
except Exception as e:
    # Unexpected errors
    print(f"Unexpected error: {e}")
```

### Graceful Degradation

```python
import nmap

class ResilientScanner:
    def __init__(self, max_retries=3):
        self.scanner = nmap.PortScanner()
        self.max_retries = max_retries
    
    def resilient_scan(self, hosts, ports='22,80,443', **kwargs):
        """Scan with automatic retry and degradation"""
        
        for attempt in range(self.max_retries):
            try:
                return self.scanner.scan(hosts, ports, **kwargs)
                
            except nmap.PortScannerTimeout:
                if attempt < self.max_retries - 1:
                    # Reduce scope on timeout
                    if isinstance(ports, str) and ',' in ports:
                        ports = ports.split(',')[0]  # Scan fewer ports
                    kwargs['arguments'] = kwargs.get('arguments', '') + ' -T4'
                    continue
                raise
                
            except nmap.PortScannerError as e:
                if 'permission' in str(e).lower() and not kwargs.get('sudo'):
                    # Try with sudo if permission denied
                    kwargs['sudo'] = True
                    continue
                raise
        
        raise Exception("All retry attempts failed")
```

---

## 🔄 **Migration Guide**

### From python-nmap

```python
# OLD: python-nmap
import nmap
nm = nmap.PortScanner()
result = nm.scan('127.0.0.1', '22-443')

# NEW: nust-nmap (same interface, enhanced features)
import nmap
nm = nmap.PortScanner()
result = nm.scan('127.0.0.1', '22-443')  # Works identically

# ENHANCED: Additional capabilities
result = nm.scan('127.0.0.1', '22-443', 
                evasion_profile=nmap.EvasionProfile.STEALTH)
```

### API Compatibility Matrix

| python-nmap Method | nust-nmap Support | Enhancements |
|-------------------|------------------|--------------|
| `scan()` | ✅ 100% Compatible | + Evasion profiles, caching |
| `listscan()` | ✅ 100% Compatible | + Enhanced error handling |
| `all_hosts()` | ✅ 100% Compatible | + Performance optimization |
| `csv()` | ✅ 100% Compatible | + Additional fields |
| Host access `nm[host]` | ✅ 100% Compatible | + Additional methods |

---
