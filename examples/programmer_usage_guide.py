#!/usr/bin/env python3
"""
Programmer's Usage Guide for nust-nmap
=====================================

This guide demonstrates how to use nust-nmap for building network and vulnerability
analysis systems. All examples show real-world usage patterns for programmers.

The library provides a comprehensive Python API for nmap with enhanced enterprise
features built into the original functions (no "Enhanced" duplicates).
"""

import sys
import time
from typing import Dict, Any, List
from pathlib import Path

# Add the parent directory to the path so we can import nmap
sys.path.insert(0, str(Path(__file__).parent.parent))

import nmap
from nmap import PortScanner, PortScannerAsync, PortScannerYield, EvasionProfile


def basic_network_discovery():
    """Basic network discovery and host enumeration"""
    print("=== Basic Network Discovery ===")
    
    nm = PortScanner()
    
    # Discover live hosts in a network
    print("Discovering live hosts...")
    result = nm.network_discovery("192.168.1.0/24")
    
    live_hosts = nm.all_hosts()
    print(f"Found {len(live_hosts)} live hosts:")
    for host in live_hosts:
        hostname = nm[host].hostname()
        print(f"  {host} ({hostname if hostname else 'No hostname'})")
    
    return live_hosts


def comprehensive_host_scan(target_host: str):
    """Comprehensive analysis of a single host"""
    print(f"\n=== Comprehensive Host Analysis: {target_host} ===")
    
    nm = PortScanner()
    
    # Aggressive scan with service detection, OS detection, and scripts
    print("Running comprehensive scan...")
    result = nm.aggressive_scan(target_host, "1-1000")
    
    if not nm.has_host(target_host):
        print(f"Host {target_host} appears to be down or filtered")
        return
    
    host_data = nm[target_host]
    
    # Host information
    print(f"Host State: {host_data.state()}")
    print(f"Hostnames: {', '.join(host_data.hostnames())}")
    
    # Open ports analysis
    tcp_ports = host_data.all_tcp()
    if tcp_ports:
        print(f"Open TCP ports: {len(tcp_ports)}")
        for port, port_info in tcp_ports.items():
            if port_info.get('state') == 'open':
                service = port_info.get('name', 'unknown')
                version = port_info.get('product', '')
                version_info = f" ({version})" if version else ""
                print(f"  {port}/tcp - {service}{version_info}")
    
    # OS detection
    if 'osmatch' in nm[target_host]:
        os_matches = nm[target_host]['osmatch']
        if os_matches:
            print(f"OS Detection: {os_matches[0].get('name', 'Unknown')}")
    
    return result


def vulnerability_assessment(target: str):
    """Vulnerability assessment using NSE scripts"""
    print(f"\n=== Vulnerability Assessment: {target} ===")
    
    nm = PortScanner()
    
    # Run vulnerability scan
    print("Running vulnerability scan...")
    result = nm.vuln_scan(target, "80,443,22,21,23,25,53,110,143,993,995")
    
    # Extract vulnerability summary
    vulns = nm.vulnerability_summary()
    
    print("Vulnerability Summary:")
    for severity, vuln_list in vulns.items():
        if vuln_list:
            print(f"  {severity.upper()}: {len(vuln_list)} findings")
            for vuln in vuln_list[:3]:  # Show first 3
                print(f"    - {vuln}")
            if len(vuln_list) > 3:
                print(f"    ... and {len(vuln_list) - 3} more")
    
    return vulns


def stealth_scanning(target: str):
    """Advanced stealth scanning to evade detection"""
    print(f"\n=== Stealth Scanning: {target} ===")
    
    nm = PortScanner()
    
    # Use different evasion techniques
    print("Running stealth scan with basic evasion...")
    result1 = nm.scan_with_evasion(
        target, 
        ports="80,443,22",
        profile=EvasionProfile.STEALTH
    )
    
    print("Running ghost-mode scan with maximum evasion...")
    result2 = nm.scan_with_evasion(
        target,
        ports="80,443,22", 
        profile=EvasionProfile.GHOST
    )
    
    # Compare results
    stealth_hosts = list(result1.get('scan', {}).keys())
    ghost_hosts = list(result2.get('scan', {}).keys())
    
    print(f"Stealth scan found: {len(stealth_hosts)} hosts")
    print(f"Ghost scan found: {len(ghost_hosts)} hosts")
    
    return result1, result2


def async_network_scan():
    """Asynchronous scanning for large networks"""
    print("\n=== Asynchronous Network Scanning ===")
    
    discovered_hosts = []
    
    def host_discovered_callback(host: str, data: Dict[str, Any]):
        """Callback function for each discovered host"""
        discovered_hosts.append(host)
        print(f"Discovered host: {host}")
        
        # Process host data immediately
        if host in data.get('scan', {}):
            host_info = data['scan'][host]
            status = host_info.get('status', {}).get('state', 'unknown')
            print(f"  Status: {status}")
    
    # Start async scan
    nm_async = PortScannerAsync()
    
    print("Starting async scan of network...")
    nm_async.scan(
        hosts="192.168.1.1-10",
        ports="22,80,443",
        callback=host_discovered_callback
    )
    
    # Wait for completion
    print("Waiting for scan completion...")
    nm_async.wait(timeout=30)
    
    print(f"Async scan completed. Found {len(discovered_hosts)} hosts")
    return discovered_hosts


def memory_efficient_large_scan():
    """Memory-efficient scanning for very large networks"""
    print("\n=== Memory-Efficient Large Network Scan ===")
    
    nm_yield = PortScannerYield()
    
    host_count = 0
    open_port_count = 0
    
    print("Scanning large network range (yielding results)...")
    
    # Scan and process hosts one by one to minimize memory usage
    for host, data in nm_yield.scan("192.168.1.1-20", ports="22,80,443"):
        host_count += 1
        
        if 'scan' in data and host in data['scan']:
            host_data = data['scan'][host]
            
            # Count open ports
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port, port_info in host_data[protocol].items():
                        if port_info.get('state') == 'open':
                            open_port_count += 1
                            print(f"  {host}:{port}/{protocol} - {port_info.get('name', 'unknown')}")
        
        # Simulate processing delay
        time.sleep(0.1)
    
    print(f"Processed {host_count} hosts with {open_port_count} open ports")
    return host_count, open_port_count


def specialized_service_scanning():
    """Specialized scanning for specific services"""
    print("\n=== Specialized Service Scanning ===")
    
    nm = PortScanner()
    target = "scanme.nmap.org"  # Safe target for testing
    
    # Web application scanning
    print("Scanning web services...")
    web_result = nm.web_scan(target)
    
    # SSH scanning
    print("Scanning SSH service...")
    ssh_result = nm.ssh_scan(target)
    
    # SSL/TLS scanning
    print("Scanning SSL/TLS services...")
    ssl_result = nm.ssl_scan(target)
    
    # Database scanning
    print("Scanning database services...")
    db_result = nm.database_scan(target)
    
    print("Specialized scans completed")
    return web_result, ssh_result, ssl_result, db_result


def compliance_and_audit():
    """Security compliance and audit scanning"""
    print("\n=== Compliance and Audit Scanning ===")
    
    nm = PortScanner()
    target = "scanme.nmap.org"
    
    # PCI compliance scan
    print("Running PCI compliance scan...")
    pci_result = nm.compliance_scan(target, standard="pci")
    
    # General security audit
    print("Running security audit...")
    audit_result = nm.audit_scan(target)
    
    # Generate reports
    print("Generating compliance reports...")
    json_report = nm.generate_report(format_type="json")
    csv_report = nm.generate_report(format_type="csv")
    
    print("Compliance scanning completed")
    return pci_result, audit_result


def performance_optimization():
    """Performance optimization techniques"""
    print("\n=== Performance Optimization ===")
    
    nm = PortScanner()
    
    # Enable caching
    nm.enable_caching(enabled=True, max_age=300)
    
    # Parallel scanning
    print("Running parallel scan...")
    parallel_result = nm.parallel_scan(
        "192.168.1.1-10", 
        ports="22,80,443",
        max_workers=5
    )
    
    # Adaptive timing
    print("Running adaptive timing scan...")
    adaptive_result = nm.adaptive_timing_scan("scanme.nmap.org")
    
    # Get performance statistics
    stats = nm.get_performance_stats()
    print(f"Scan duration: {stats.get('scan_duration', 0):.2f} seconds")
    print(f"Hosts scanned: {stats.get('hosts_scanned', 0)}")
    
    return parallel_result, adaptive_result, stats


def main():
    """Main demonstration function"""
    print("nust-nmap Programmer's Usage Guide")
    print("=" * 40)
    
    try:
        # Basic network discovery
        live_hosts = basic_network_discovery()
        
        if live_hosts:
            # Use first live host for detailed analysis
            target = live_hosts[0]
            
            # Comprehensive host analysis
            comprehensive_host_scan(target)
            
            # Vulnerability assessment
            vulnerability_assessment(target)
            
            # Stealth scanning
            stealth_scanning(target)
        
        # Async scanning demo
        async_network_scan()
        
        # Memory-efficient scanning
        memory_efficient_large_scan()
        
        # Specialized service scanning
        specialized_service_scanning()
        
        # Compliance and audit
        compliance_and_audit()
        
        # Performance optimization
        performance_optimization()
        
        print("\n=== Demo Complete ===")
        print("This demonstrates how programmers can use nust-nmap for")
        print("building comprehensive network and vulnerability analysis systems.")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        print("Note: Some examples require network access and may not work in all environments")


if __name__ == "__main__":
    main()
