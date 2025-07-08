"""
Advanced service detection and vulnerability assessment
"""

import nmap
import json
import sys
from datetime import datetime


class ServiceDetector:
    """Advanced service detection and analysis"""
    
    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.results = {}
    
    def detect_services(self, target, ports=None):
        """Perform comprehensive service detection"""
        print(f"🔍 Detecting services on {target}")
        
        # Default comprehensive port list
        if ports is None:
            ports = "21,22,23,25,53,80,110,143,443,993,995,1433,3306,5432,6379,27017"
        
        try:
            # Service version detection with OS detection
            print("   Running service detection scan...")
            result = self.scanner.scan(
                target, 
                ports, 
                arguments='-sV -O -sC --version-intensity 7'
            )
            
            self.results[target] = result
            return result
            
        except Exception as e:
            print(f"❌ Service detection failed: {e}")
            return None
    
    def analyze_services(self, target):
        """Analyze detected services for security insights"""
        if target not in self.results:
            print(f"❌ No scan results for {target}")
            return
        
        scan_data = self.results[target]
        if target not in scan_data.get('scan', {}):
            print(f"❌ No host data for {target}")
            return
        
        host_data = scan_data['scan'][target]
        
        print(f"\n🔬 Service Analysis for {target}")
        print("=" * 50)
        
        # Basic host info
        state = host_data.get('status', {}).get('state', 'unknown')
        print(f"Host State: {state}")
        
        # Hostname information
        hostnames = host_data.get('hostnames', [])
        if hostnames:
            print(f"Hostnames: {', '.join([h.get('name', '') for h in hostnames])}")
        
        # OS Detection
        if 'osmatch' in host_data:
            print(f"\n🖥️  Operating System Detection:")
            for os_match in host_data['osmatch'][:3]:  # Top 3 matches
                accuracy = os_match.get('accuracy', 0)
                name = os_match.get('name', 'Unknown')
                print(f"   {name} (Accuracy: {accuracy}%)")
        
        # Service analysis by protocol
        for protocol in ['tcp', 'udp']:
            if protocol not in host_data:
                continue
                
            print(f"\n📡 {protocol.upper()} Services:")
            ports = host_data[protocol]
            
            for port, port_info in sorted(ports.items()):
                self.analyze_port_service(port, port_info, protocol)
    
    def analyze_port_service(self, port, port_info, protocol):
        """Analyze individual port service"""
        state = port_info.get('state', 'unknown')
        name = port_info.get('name', 'unknown')
        product = port_info.get('product', '')
        version = port_info.get('version', '')
        extrainfo = port_info.get('extrainfo', '')
        
        # Status emoji
        emoji = "🟢" if state == "open" else "🔴" if state == "closed" else "🟡"
        
        print(f"   {emoji} Port {port}/{protocol}: {state}")
        
        if state == "open":
            # Service details
            service_line = f"      Service: {name}"
            if product:
                service_line += f" ({product}"
                if version:
                    service_line += f" {version}"
                service_line += ")"
            
            print(service_line)
            
            if extrainfo:
                print(f"      Extra: {extrainfo}")
            
            # Security insights
            self.security_insights(port, name, product, version)
            
            # Script results
            if 'script' in port_info:
                print(f"      📜 Script Results:")
                for script_name, script_output in port_info['script'].items():
                    print(f"         {script_name}: {script_output[:100]}...")
    
    def security_insights(self, port, service, product, version):
        """Provide basic security insights"""
        insights = []
        
        # Common vulnerable services
        if service == 'ssh' and version:
            if 'OpenSSH' in product and version:
                insights.append("Consider updating SSH if version is outdated")
        
        elif service == 'http' or service == 'https':
            insights.append("Check for web vulnerabilities and SSL configuration")
            if 'Apache' in product:
                insights.append("Verify Apache version for known CVEs")
            elif 'nginx' in product:
                insights.append("Verify nginx version for known CVEs")
        
        elif service == 'ftp':
            insights.append("⚠️  FTP detected - consider SFTP for secure transfers")
        
        elif service == 'telnet':
            insights.append("⚠️  Telnet detected - highly insecure, use SSH instead")
        
        elif service == 'mysql':
            insights.append("🔒 Database detected - ensure proper authentication")
        
        elif service == 'postgresql':
            insights.append("🔒 Database detected - ensure proper authentication")
        
        elif service == 'redis':
            insights.append("🔒 Redis detected - check for authentication and encryption")
        
        # Display insights
        for insight in insights:
            print(f"         💡 {insight}")
    
    def generate_security_report(self, target):
        """Generate security-focused report"""
        if target not in self.results:
            return
        
        print(f"\n🛡️  Security Assessment Report")
        print("=" * 50)
        print(f"Target: {target}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        scan_data = self.results[target]['scan'].get(target, {})
        
        # Risk assessment
        high_risk_services = ['telnet', 'ftp', 'rsh', 'rlogin']
        medium_risk_services = ['http', 'ssh', 'smtp']
        
        risks = {'high': [], 'medium': [], 'low': []}
        
        for protocol in ['tcp', 'udp']:
            if protocol not in scan_data:
                continue
                
            for port, port_info in scan_data[protocol].items():
                if port_info.get('state') == 'open':
                    service = port_info.get('name', 'unknown')
                    
                    if service in high_risk_services:
                        risks['high'].append(f"{port}/{protocol} ({service})")
                    elif service in medium_risk_services:
                        risks['medium'].append(f"{port}/{protocol} ({service})")
                    else:
                        risks['low'].append(f"{port}/{protocol} ({service})")
        
        # Display risk summary
        print(f"\n⚠️  Risk Summary:")
        print(f"   🔴 High Risk Services: {len(risks['high'])}")
        for service in risks['high']:
            print(f"      {service}")
        
        print(f"   🟡 Medium Risk Services: {len(risks['medium'])}")
        for service in risks['medium'][:5]:  # Limit output
            print(f"      {service}")
        
        print(f"   🟢 Low Risk Services: {len(risks['low'])}")
        
        # Recommendations
        print(f"\n📋 Security Recommendations:")
        if risks['high']:
            print("   1. Immediately review high-risk services")
            print("   2. Consider disabling unnecessary services")
        
        print("   3. Ensure all services are updated to latest versions")
        print("   4. Implement proper firewall rules")
        print("   5. Use strong authentication for all services")
        print("   6. Enable logging and monitoring")
    
    def export_results(self, target, filename=None):
        """Export results to JSON"""
        if target not in self.results:
            return False
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"service_scan_{target.replace('.', '_')}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results[target], f, indent=2)
            
            print(f"✅ Results exported to {filename}")
            return True
            
        except Exception as e:
            print(f"❌ Export failed: {e}")
            return False


def main():
    """Main service detection function"""
    print("🔬 nust-nmap Service Detection Tool")
    print("=" * 40)
    
    # Get target from user
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter target to scan (IP or hostname): ").strip()
    
    if not target:
        print("❌ No target specified")
        sys.exit(1)
    
    # Get custom ports
    ports = input("Enter ports to scan (or press Enter for default): ").strip()
    if not ports:
        ports = None
    
    try:
        # Initialize detector
        detector = ServiceDetector()
        
        # Perform service detection
        result = detector.detect_services(target, ports)
        if not result:
            return
        
        # Analyze services
        detector.analyze_services(target)
        
        # Generate security report
        detector.generate_security_report(target)
        
        # Export option
        export = input("\n💾 Export detailed results to JSON? (y/N): ").strip().lower()
        if export == 'y':
            detector.export_results(target)
        
    except KeyboardInterrupt:
        print("\n⏹️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()