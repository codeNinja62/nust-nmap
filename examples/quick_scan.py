"""
Quick and simple scanning examples for beginners
"""

import nmap


def quick_host_check(host):
    """Quick check if host is alive"""
    print(f"🏠 Checking if {host} is alive...")
    
    scanner = nmap.PortScanner()
    result = scanner.scan(host, arguments='-sn')  # Ping scan only
    
    if host in scanner.all_hosts():
        print(f"✅ {host} is UP")
        return True
    else:
        print(f"❌ {host} is DOWN or filtered")
        return False


def quick_port_check(host, port):
    """Quick check if specific port is open"""
    print(f"🚪 Checking if port {port} is open on {host}...")
    
    scanner = nmap.PortScanner()
    result = scanner.scan(host, str(port))
    
    if host in scanner.all_hosts():
        host_info = scanner[host]
        if host_info.has_tcp(int(port)):
            state = host_info.tcp(int(port))['state']
            service = host_info.tcp(int(port)).get('name', 'unknown')
            
            if state == 'open':
                print(f"✅ Port {port} is OPEN ({service})")
                return True
            else:
                print(f"❌ Port {port} is {state.upper()}")
                return False
    
    print(f"❌ Cannot reach {host}")
    return False


def quick_web_check(host):
    """Quick check for web servers"""
    print(f"🌐 Checking for web servers on {host}...")
    
    scanner = nmap.PortScanner()
    web_ports = "80,443,8080,8443"
    result = scanner.scan(host, web_ports)
    
    if host in scanner.all_hosts():
        host_info = scanner[host]
        web_services = []
        
        for port in [80, 443, 8080, 8443]:
            if host_info.has_tcp(port):
                port_info = host_info.tcp(port)
                if port_info['state'] == 'open':
                    service = port_info.get('name', 'unknown')
                    web_services.append(f"{port}({service})")
        
        if web_services:
            print(f"✅ Web services found: {', '.join(web_services)}")
            return web_services
        else:
            print("❌ No web services found")
            return []
    
    print(f"❌ Cannot reach {host}")
    return []


def quick_common_ports(host):
    """Scan most common ports quickly"""
    print(f"⚡ Quick scan of common ports on {host}...")
    
    scanner = nmap.PortScanner()
    # Top 20 most common ports
    common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3389,5900,8080"
    
    result = scanner.scan(host, common_ports, arguments='-T4')
    
    if host in scanner.all_hosts():
        host_info = scanner[host]
        open_ports = []
        
        for protocol in host_info.all_protocols():
            for port in host_info[protocol]:
                port_info = host_info[protocol][port]
                if port_info['state'] == 'open':
                    service = port_info.get('name', 'unknown')
                    open_ports.append(f"{port}/{protocol}({service})")
        
        if open_ports:
            print(f"✅ Open ports: {', '.join(open_ports)}")
            return open_ports
        else:
            print("🔒 No open ports found")
            return []
    
    print(f"❌ Cannot reach {host}")
    return []


def main():
    """Interactive quick scan menu"""
    print("⚡ nust-nmap Quick Scan Tools")
    print("=" * 30)
    
    while True:
        print("""
🚀 Quick Scan Options:
1. Check if host is alive
2. Check specific port
3. Find web servers
4. Scan common ports
5. Exit

""")
        
        choice = input("Choose an option (1-5): ").strip()
        
        if choice == "1":
            host = input("Enter host to check: ").strip()
            if host:
                quick_host_check(host)
        
        elif choice == "2":
            host = input("Enter host: ").strip()
            port = input("Enter port: ").strip()
            if host and port:
                quick_port_check(host, port)
        
        elif choice == "3":
            host = input("Enter host: ").strip()
            if host:
                quick_web_check(host)
        
        elif choice == "4":
            host = input("Enter host: ").strip()
            if host:
                quick_common_ports(host)
        
        elif choice == "5":
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid choice")
        
        input("\n📱 Press Enter to continue...")


if __name__ == "__main__":
    main()