"""
Basic nmap scanning example with error handling
"""

import nmap
import sys


def main():
    """Demonstrate basic scanning functionality"""
    try:
        # Initialize scanner
        print("🔧 Initializing nmap scanner...")
        scanner = nmap.PortScanner()
        print(f"✅ Nmap version: {'.'.join(map(str, scanner.nmap_version()))}")
        
        # Perform basic scan
        print("\n🔍 Scanning localhost (127.0.0.1)...")
        result = scanner.scan('127.0.0.1', '22,80,443,8080', arguments='-sV')
        
        # Display scan summary
        print(f"\n📊 Scan Summary:")
        print(f"   Command: {result['nmap']['command_line']}")
        print(f"   Scan time: {result['nmap']['scanstats']['elapsed']}s")
        print(f"   Hosts scanned: {result['nmap']['scanstats']['totalhosts']}")
        print(f"   Hosts up: {result['nmap']['scanstats']['uphosts']}")
        
        # Display detailed results
        print("\n🎯 Detailed Results:")
        for host in scanner.all_hosts():
            print(f"\n🖥️  Host: {host}")
            print(f"   Hostname: {scanner[host].hostname()}")
            print(f"   State: {scanner[host].state()}")
            
            # Show all protocols found
            protocols = scanner[host].all_protocols()
            print(f"   Protocols: {', '.join(protocols) if protocols else 'None'}")
            
            # Show port details for each protocol
            for protocol in protocols:
                ports = scanner[host][protocol].keys()
                print(f"\n   📡 {protocol.upper()} Ports:")
                
                for port in sorted(ports):
                    port_info = scanner[host][protocol][port]
                    state = port_info['state']
                    name = port_info.get('name', 'unknown')
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    
                    service_info = f"{name}"
                    if product:
                        service_info += f" ({product}"
                        if version:
                            service_info += f" {version}"
                        service_info += ")"
                    
                    state_emoji = "🟢" if state == "open" else "🔴" if state == "closed" else "🟡"
                    print(f"      {state_emoji} Port {port}: {state} - {service_info}")
        
        # Export to CSV
        print(f"\n💾 CSV Export:")
        csv_data = scanner.csv()
        print("   First few lines of CSV:")
        for i, line in enumerate(csv_data.split('\n')[:5]):
            if line.strip():
                print(f"   {line}")
        
    except nmap.PortScannerError as e:
        print(f"❌ Scanner Error: {e}")
        print("💡 Make sure nmap is installed and accessible")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()