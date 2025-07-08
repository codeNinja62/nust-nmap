"""
Memory-efficient scanning using PortScannerYield
"""

import nmap
import time
import ipaddress


def memory_efficient_scan(network, ports="22,80,443"):
    """Demonstrate memory-efficient scanning for large networks"""
    print(f"🔄 Memory-efficient scan of {network}")
    print("   Using yield-based scanning to minimize memory usage")
    
    try:
        # Validate network
        network_obj = ipaddress.ip_network(network, strict=False)
        host_count = network_obj.num_addresses
        
        if host_count > 256:
            print(f"⚠️  Large network detected ({host_count} addresses)")
            response = input("   Continue? This may take a while (y/N): ")
            if response.lower() != 'y':
                return
        
        # Initialize yield scanner
        yield_scanner = nmap.PortScannerYield()
        
        start_time = time.time()
        processed_hosts = 0
        live_hosts = 0
        
        print(f"\n🎯 Scanning {network} for ports {ports}")
        print("   Processing hosts as they complete...\n")
        
        # Process results as they come in
        for host, scan_result in yield_scanner.scan(
            hosts=str(network),
            ports=ports,
            arguments='-T4 --min-rate 100'
        ):
            processed_hosts += 1
            
            # Extract host data
            if isinstance(scan_result, dict) and 'scan' in scan_result and host in scan_result['scan']:
                host_data = scan_result['scan'][host]
                state = host_data.get('status', {}).get('state', 'unknown')
                
                if state == 'up':
                    live_hosts += 1
                    
                    # Show live host immediately
                    hostname = 'unknown'
                    hostnames = host_data.get('hostnames', [])
                    if hostnames:
                        hostname = hostnames[0].get('name', 'unknown')
                    
                    print(f"✅ {host} ({hostname}) - {state}")
                    
                    # Show open ports
                    open_ports = []
                    for protocol in ['tcp', 'udp']:
                        if protocol in host_data:
                            for port, port_info in host_data[protocol].items():
                                if port_info.get('state') == 'open':
                                    service = port_info.get('name', 'unknown')
                                    open_ports.append(f"{port}/{protocol}({service})")
                    
                    if open_ports:
                        print(f"   🔓 Open: {', '.join(open_ports)}")
                    else:
                        print("   🔒 No open ports detected")
                
                else:
                    # Just show a dot for non-responsive hosts
                    print(".", end="", flush=True)
            
            # Progress update every 10 hosts
            if processed_hosts % 10 == 0:
                elapsed = time.time() - start_time
                rate = processed_hosts / elapsed if elapsed > 0 else 0
                print(f"\n📊 Progress: {processed_hosts} hosts processed, {live_hosts} alive ({rate:.1f} hosts/sec)")
        
        # Final summary
        total_time = time.time() - start_time
        print(f"\n🎉 Scan Complete!")
        print(f"   Total hosts processed: {processed_hosts}")
        print(f"   Live hosts found: {live_hosts}")
        print(f"   Total time: {total_time:.2f} seconds")
        print(f"   Average rate: {processed_hosts/total_time:.1f} hosts/second")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")


def compare_scan_methods(target="127.0.0.1", ports="22,80,443"):
    """Compare different scanning methods"""
    print("⚖️  Comparing Scan Methods")
    print("=" * 30)
    
    methods = [
        ("Standard PortScanner", lambda: standard_scan(target, ports)),
        ("Yield-based Scanner", lambda: yield_scan(target, ports)),
        ("Async Scanner", lambda: async_scan(target, ports))
    ]
    
    results = {}
    
    for method_name, method_func in methods:
        print(f"\n🧪 Testing {method_name}...")
        
        start_time = time.time()
        start_memory = get_memory_usage()
        
        try:
            method_func()
            end_time = time.time()
            end_memory = get_memory_usage()
            
            results[method_name] = {
                'time': end_time - start_time,
                'memory_delta': end_memory - start_memory,
                'success': True
            }
            
        except Exception as e:
            results[method_name] = {
                'error': str(e),
                'success': False
            }
    
    # Display comparison
    print(f"\n📊 Performance Comparison:")
    for method, data in results.items():
        if data['success']:
            print(f"   {method}:")
            print(f"     Time: {data['time']:.2f}s")
            print(f"     Memory: {data['memory_delta']:.1f}MB")
        else:
            print(f"   {method}: Failed - {data['error']}")


def standard_scan(target, ports):
    """Standard synchronous scan"""
    scanner = nmap.PortScanner()
    scanner.scan(target, ports)
    return len(scanner.all_hosts())


def yield_scan(target, ports):
    """Yield-based scan"""
    yield_scanner = nmap.PortScannerYield()
    count = 0
    for host, result in yield_scanner.scan(target, ports):
        count += 1
    return count


def async_scan(target, ports):
    """Async scan with callback"""
    results = []
    
    def callback(host, result):
        results.append((host, result))
    
    async_scanner = nmap.PortScannerAsync()
    async_scanner.scan(target, ports, callback=callback)
    
    while async_scanner.still_scanning():
        time.sleep(0.1)
    
    return len(results)


def get_memory_usage():
    """Get current memory usage (simplified)"""
    try:
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024  # MB
    except ImportError:
        return 0  # psutil not available


def main():
    """Main function for yield scanner demo"""
    print("🔄 nust-nmap Yield Scanner Demo")
    print("=" * 35)
    
    choice = input("""
Choose demo mode:
1. Memory-efficient network scan
2. Compare scanning methods
3. Custom yield scan

Enter choice (1-3): """).strip()
    
    if choice == "1":
        network = input("Enter network (e.g., 192.168.1.0/24): ").strip()
        if network:
            memory_efficient_scan(network)
        else:
            print("❌ No network specified")
    
    elif choice == "2":
        target = input("Enter target for comparison (default: 127.0.0.1): ").strip()
        if not target:
            target = "127.0.0.1"
        compare_scan_methods(target)
    
    elif choice == "3":
        target = input("Enter target: ").strip()
        ports = input("Enter ports (default: 22,80,443): ").strip()
        if not ports:
            ports = "22,80,443"
        
        if target:
            yield_scanner = nmap.PortScannerYield()
            print(f"🎯 Scanning {target}:{ports}")
            
            for host, result in yield_scanner.scan(target, ports, arguments='-sV'):
                print(f"📨 Result for {host}: {len(str(result))} bytes")
        else:
            print("❌ No target specified")
    
    else:
        print("❌ Invalid choice")


if __name__ == "__main__":
    main()