"""
Asynchronous nmap scanning example
"""

import nmap
import time
import threading


class AsyncScanDemo:
    """Demonstrate asynchronous scanning capabilities"""
    
    def __init__(self):
        self.results = {}
        self.scan_complete = False
    
    def scan_callback(self, host, scan_result):
        """Callback function for async scan results"""
        self.results[host] = scan_result
        print(f"📨 Received result for {host}")
        
        # Display basic info
        if host in scan_result['scan']:
            host_info = scan_result['scan'][host]
            state = host_info.get('status', {}).get('state', 'unknown')
            print(f"   State: {state}")
            
            # Count open ports
            open_ports = 0
            for protocol in ['tcp', 'udp']:
                if protocol in host_info:
                    for port, info in host_info[protocol].items():
                        if info.get('state') == 'open':
                            open_ports += 1
            print(f"   Open ports: {open_ports}")
    
    def run_async_scan(self):
        """Run asynchronous scan on multiple hosts"""
        print("🚀 Starting asynchronous scan...")
        
        # Initialize async scanner
        async_scanner = nmap.PortScannerAsync()
        
        # List of hosts to scan
        hosts = ['127.0.0.1', '127.0.0.2', '127.0.0.3']  # Add more IPs as needed
        
        # Start async scans
        for host in hosts:
            print(f"🎯 Queuing scan for {host}")
            async_scanner.scan(
                hosts=host,
                ports='22,80,443',
                arguments='-sS',  # SYN scan
                callback=self.scan_callback
            )
        
        # Monitor scan progress
        print("\n⏳ Monitoring scan progress...")
        start_time = time.time()
        
        while async_scanner.still_scanning():
            print(f"   📡 Scanning... ({time.time() - start_time:.1f}s elapsed)")
            time.sleep(2)
        
        print("✅ All scans completed!")
        
        # Display final results
        self.display_results()
    
    def display_results(self):
        """Display comprehensive scan results"""
        print(f"\n📊 Final Results Summary:")
        print(f"   Total hosts scanned: {len(self.results)}")
        
        for host, result in self.results.items():
            print(f"\n🖥️  Host: {host}")
            
            if 'scan' in result and host in result['scan']:
                host_data = result['scan'][host]
                
                # Host state
                state = host_data.get('status', {}).get('state', 'unknown')
                print(f"   State: {state}")
                
                # Hostname
                hostnames = host_data.get('hostnames', [])
                if hostnames:
                    hostname = hostnames[0].get('name', 'unknown')
                    print(f"   Hostname: {hostname}")
                
                # Port information
                for protocol in ['tcp', 'udp']:
                    if protocol in host_data:
                        ports = host_data[protocol]
                        print(f"   {protocol.upper()} ports:")
                        
                        for port, info in sorted(ports.items()):
                            state = info.get('state', 'unknown')
                            name = info.get('name', 'unknown')
                            emoji = "🟢" if state == "open" else "🔴"
                            print(f"     {emoji} {port}: {state} ({name})")


def main():
    """Main function for async scan demo"""
    try:
        demo = AsyncScanDemo()
        demo.run_async_scan()
        
    except nmap.PortScannerError as e:
        print(f"❌ Scanner Error: {e}")
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")


if __name__ == "__main__":
    main()