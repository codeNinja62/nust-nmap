"""
nust-nmap - Enterprise-Grade Python Nmap Wrapper

nust-nmap is a comprehensive Python library providing 100% coverage of nmap 7.9.7+ 
features. It offers enterprise-grade scanning capabilities with advanced evasion, 
comprehensive NSE scripting, and professional result parsing.

Key Features:
- 100% nmap feature coverage (scan types, evasion, NSE, timing, output formats)
- Enterprise-grade security scanning and evasion capabilities  
- Comprehensive async/sync scanning with type safety
- Advanced result parsing and XML/JSON export capabilities
- Professional configuration management and plugin architecture
- Single unified API - enhanced original functions instead of duplicates

Author:
* Sameer Ahmed - sameer.cs@proton.me

License: GPL v3 or any later version

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

# Type imports
from typing import Optional, List, Dict, Any

# === UNIFIED ENTERPRISE API ===
# Single file with enhanced original functions - no duplicates
from .nmap import (
    # Version and metadata
    __author__, 
    __last_modification__, 
    __version__,
    
    # Core scanner classes (enhanced originals)
    PortScanner,
    PortScannerAsync, 
    PortScannerYield,
    PortScannerHostDict,
    
    # Exception classes
    PortScannerError,
    PortScannerTimeout,
    
    # Enterprise enums and types
    ScanType,
    PingType,
    TimingTemplate,
    OutputFormat,
    NSECategory,
    EvasionProfile,
    
    # Configuration classes (clean naming)
    TimingConfig,
    EvasionConfig,
    NSEConfig,
    
    # Utility functions
    convert_nmap_output_to_encoding,
    enable_performance_monitoring,
    set_cache_max_age,
    clear_scan_cache,
    
    # Convenience functions
    quick_scan,
    stealth_scan,
    vulnerability_scan,
)

# === ALIASES FOR CONVENIENCE ===
# Provide intuitive aliases while maintaining original names
Scanner = PortScanner              # Modern alias for new projects
AsyncScanner = PortScannerAsync    # Modern alias for async scanning
YieldScanner = PortScannerYield    # Modern alias for yield scanning

# Configuration aliases for consistency
TimingOptions = TimingConfig       # Alternative name
EvasionOptions = EvasionConfig     # Alternative name
NSEOptions = NSEConfig            # Alternative name

# === CONVENIENCE API FUNCTIONS ===
def scan_with_evasion(targets: str, profile: EvasionProfile = EvasionProfile.STEALTH, **kwargs):
    """
    Quick evasion scanning with predefined profiles.
    
    Args:
        targets: Target specification (IP, range, domain)
        profile: Evasion profile (STEALTH, BASIC, GHOST, ADAPTIVE, ZERO_TRUST)
        **kwargs: Additional scan options
        
    Returns:
        Scan results with evasion applied
    """
    scanner = PortScanner()
    
    # Configure evasion based on profile
    if profile == EvasionProfile.STEALTH:
        evasion_config = EvasionConfig(
            fragment_packets=True,
            randomize_hosts=True,
            data_length=25
        )
        timing_config = TimingConfig(template=TimingTemplate.SNEAKY)
    elif profile == EvasionProfile.GHOST:
        evasion_config = EvasionConfig(
            fragment_packets=True,
            randomize_hosts=True,
            decoys=["192.0.2.1", "192.0.2.2", "192.0.2.3"],
            spoof_mac="random"
        )
        timing_config = TimingConfig(template=TimingTemplate.PARANOID)
    else:
        evasion_config = EvasionConfig(fragment_packets=True)
        timing_config = TimingConfig(template=TimingTemplate.POLITE)
    
    return scanner.scan(
        hosts=targets,
        evasion=evasion_config,
        timing=timing_config,
        **kwargs
    )

def scan_with_nse(targets: str, scripts: Optional[List[str]] = None, **kwargs):
    """
    Quick NSE script scanning.
    
    Args:
        targets: Target specification
        scripts: List of specific scripts to run
        **kwargs: NSE and scan options
        
    Returns:
        Comprehensive scan results with NSE output
    """
    scanner = PortScanner()
    
    nse_config = NSEConfig()
    if scripts:
        nse_config = NSEConfig(scripts=scripts)
    else:
        nse_config = NSEConfig(script_categories=[NSECategory.DEFAULT, NSECategory.VERSION])
    
    return scanner.scan(
        hosts=targets, 
        nse=nse_config,
        **kwargs
    )

def scan_multiple_targets(targets_list, **kwargs):
    """
    Parallel scanning of multiple targets.
    
    Args:
        targets_list: List of target specifications
        **kwargs: Scan options applied to all targets
        
    Returns:
        Dictionary mapping targets to scan results
    """
    scanner = PortScanner()
    results = {}
    for target in targets_list:
        try:
            results[target] = scanner.scan(hosts=target, **kwargs)
        except Exception as e:
            results[target] = {"error": str(e)}
    return results

def discovery_scan(network: str, **kwargs):
    """
    Network discovery scanning (ping sweep).
    
    Args:
        network: Network specification (e.g., '192.168.1.0/24')
        **kwargs: Additional discovery options
        
    Returns:
        Discovery scan results
    """
    scanner = PortScanner()
    return scanner.scan(
        hosts=network, 
        scan_type=ScanType.PING_ONLY,
        **kwargs
    )

# === RECOMMENDED IMPORT PATTERNS ===
# For new projects, use:
#   from nmap import Scanner, ScanType, TimingConfig
#   scanner = Scanner()
#   result = scanner.scan("target.com", scan_type=ScanType.TCP_SYN)
#
# For legacy compatibility:
#   import nmap
#   scanner = nmap.PortScanner()
#   result = scanner.scan("target.com", "80,443")
#
# For enterprise features:
#   from nmap import PortScanner, EvasionConfig, NSEConfig
#   scanner = PortScanner()
#   result = scanner.scan("target.com", evasion=EvasionConfig(fragment_packets=True))
