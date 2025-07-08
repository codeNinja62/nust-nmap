"""
Network discovery and reconnaissance example
"""

import nmap
import ipaddress
import sys
from collections import defaultdict


class NetworkDiscovery:
    """Network discovery and analysis tools"""
    
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.discovered_hosts = []
    
    def validate_network(self, network):
        """Validate network range"""
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            
            # Check for private networks (more ethical)
            if not network_obj.is_private:
                response = input(f"⚠️  Warning: {network} appears to be a public network. Continue? (y/N): ")
                if response.lower() != 'y':
                    return False
            
            return True
        except ValueError as e:
            print(f"❌ Invalid network: {e}")
            return False
    
    def discover_hosts(self, network):
        """Discover live hosts in network"""
        if not self.validate_network(network):
            return []
        
        print(f"🔍 Discovering hosts in {network}...")
        
        try:
            # Host discovery scan (ping scan)
            hosts = self.scanner.listscan(network)
            self.discovered_hosts = hosts
            
            print(f"✅ Found {len(hosts)} potential hosts")
            return hosts
            
        except Exception as e:
            print(f"❌ Host discovery failed: {e}")
            return []
    
    def port_scan_hosts(self, hosts, ports="22,80,443,8080,21,23,25,53,110,993,995"):
        """Perform detailed port scanning on discovered hosts"""
        results = {}
        
        print(f"\n🎯 Port scanning {len(hosts)} hosts...")
        print(f"   Ports: {ports}")
        
        for i, host in enumerate(hosts, 1):
            print(f"\n📡 Scanning host {i}/{len(hosts)}: {host}")
            
            try:
                result = self.scanner.scan(host, ports, arguments='-sV -T4')
                
                if host in self.scanner.all_hosts():
                    host_info = self.scanner[host]
                    results[host] = {
                        'state': host_info.state(),
                        'hostname': host_info.hostname(),
                        'protocols': {},
                    }
                    
                    # Collect port information
                    for protocol in host_info.all_protocols():
                        results[host]['protocols'][protocol] = {}
                        for port in host_info[protocol]:
                            port_info = host_info[protocol][port]
                            results[host]['protocols'][protocol][port] = {
                                'state': port_info['state'],
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                            }
                    
                    # Quick status
                    open_ports = self.count_open_ports(results[host])
                    print(f"   ✅ {host}: {open_ports} open ports")
                else:
                    print(f"   ❌ {host}: No response")
                    
            except Exception as e:
                print(f"   ❌ {host}: Scan failed - {e}")
        
        return results
    
    def count_open_ports(self, host_data):
        """Count open ports for a host"""
        count = 0
        for protocol_data in host_data.get('protocols', {}).values():
            for port_data in protocol_data.values():
                if port_data.get('state') == 'open':
                    count += 1
        return count
    
    def analyze_services(self, scan_results):
        """Analyze discovered services"""
        print(f"\n📊 Service Analysis:")
        
        service_stats = defaultdict(int)
        os_fingerprints = defaultdict(int)
        
        for host, data in scan_results.items():
            if data['state'] != 'up':
                continue
                
            for protocol, ports in data.get('protocols', {}).items():
                for port, port_info in ports.items():
                    if port_info['state'] == 'open':
                        service = port_info.get('name', 'unknown')
                        service_stats[f"{service}/{protocol}"] += 1
        
        # Display service statistics
        print("\n🔧 Most Common Services:")
        for service, count in sorted(service_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {service}: {count} hosts")
    
    def generate_report(self, scan_results):
        """Generate comprehensive network report"""
        print(f"\n📋 Network Discovery Report")
        print("=" * 50)
        
        total_hosts = len(scan_results)
        live_hosts = sum(1 for data in scan_results.values() if data['state'] == 'up')
        
        print(f"📊 Summary:")
        print(f"   Total hosts scanned: {total_hosts}")
        print(f"   Live hosts: {live_hosts}")
        print(f"   Response rate: {(live_hosts/total_hosts)*100:.1f}%" if total_hosts > 0 else "   Response rate: 0%")
        
        # Detailed host information
        print(f"\n🖥️  Host Details:")
        for host, data in scan_results.items():
            if data['state'] != 'up':
                continue
                
            print(f"\n   Host: {host}")
            if data['hostname']:
                print(f"   Hostname: {data['hostname']}")
            
            open_ports = self.count_open_ports(data)
            print(f"   Open ports: {open_ports}")
            
            # Show top open ports
            for protocol, ports in data.get('protocols', {}).items():
                open_ports_list = [
                    f"{port}({info['name']})" 
                    for port, info in ports.items() 
                    if info['state'] == 'open'
                ]
                if open_ports_list:
                    print(f"   {protocol.upper()}: {', '.join(open_ports_list[:5])}")


def main():
    """Main network discovery function"""
    print("🌐 nust-nmap Network Discovery Tool")
    print("=" * 40)
    
    # Get network from user
    if len(sys.argv) > 1:
        network = sys.argv[1]
    else:
        network = input("Enter network to scan (e.g., 192.168.1.0/24): ").strip()
    
    if not network:
        print("❌ No network specified")
        sys.exit(1)
    
    try:
        # Initialize discovery
        discovery = NetworkDiscovery()
        
        # Step 1: Host discovery
        hosts = discovery.discover_hosts(network)
        if not hosts:
            print("😞 No hosts discovered")
            return
        
        # Limit hosts for demo (optional)
        if len(hosts) > 10:
            print(f"⚠️  Found {len(hosts)} hosts. Limiting to first 10 for demo.")
            hosts = hosts[:10]
        
        # Step 2: Port scanning
        scan_results = discovery.port_scan_hosts(hosts)
        
        # Step 3: Analysis
        discovery.analyze_services(scan_results)
        
        # Step 4: Generate report
        discovery.generate_report(scan_results)
        
        # Export option
        export = input("\n💾 Export results to CSV? (y/N): ").strip().lower()
        if export == 'y':
            csv_data = discovery.scanner.csv()
            filename = f"network_scan_{network.replace('/', '_')}.csv"
            with open(filename, 'w') as f:
                f.write(csv_data)
            print(f"✅ Results exported to {filename}")
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()