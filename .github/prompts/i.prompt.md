---
mode: agent
---
### prompt.md
```markdown
# Nmap Wrapper: Firewall/IDS Evasion Module Implementation

## Current System Status
```python
"""
✅ FULLY SUPPORTED:
  - Port scanning (TCP, UDP, IP, SCTP)
  - Service/version detection (-sV)
  - OS detection (basic osmatch parsing)
  - Host discovery (-sL)
  - Custom arguments passthrough
  - Script output parsing (basic)
  - Timing templates (-T0 to -T5)
  - Output formats (XML parsing)
  - IPv4/IPv6 support
  - Sudo/privilege escalation

⚠️ PARTIALLY SUPPORTED:
  - NSE Scripts: Parses output but no script management
  - OS Detection: Basic parsing, missing advanced fingerprinting
  - Firewall/IDS Evasion: Passthrough only, no built-in methods
  - Advanced Timing: Basic timeout, missing detailed timing controls
"""
Implementation Requirements

---

## Implementation Requirements & Step-by-Step Guide

### 1. NSE Script Integration & Management
- **Requirements:**
    - Allow users to select specific NSE scripts to run.
    - Support custom script paths and script arguments.
    - Parse and structure NSE script output.
- **Steps:**
    1. Add CLI/API options for script selection (`--script`, `--script-args`).
    2. Validate script existence and arguments.
    3. Pass selected scripts/args to nmap command.
    4. Parse and organize script output in results.

### 2. Advanced OS Detection (Fingerprinting)
- **Requirements:**
    - Parse detailed OS fingerprinting output.
    - Expose advanced OS match data (accuracy, classes, CPEs).
- **Steps:**
    1. Enhance output parser to extract all OS match blocks.
    2. Structure OS fingerprint data in results.
    3. Optionally, provide confidence/accuracy metrics.

### 3. Firewall/IDS Evasion Techniques
- **Requirements:**
    - Expose nmap evasion options (decoy, source port, fragmentation, etc.).
    - Allow users to configure evasion techniques.
- **Steps:**
    1. Add CLI/API options for evasion methods (`-D`, `-S`, `-f`, `--data-length`, etc.).
    2. Validate and pass evasion options to nmap.
    3. Document evasion features and usage.

### 4. Advanced Timing Controls
- **Requirements:**
    - Support granular timing options (retries, host/group parallelism, scan delay).
- **Steps:**
    1. Add CLI/API options for timing controls (`--min-rate`, `--max-rate`, `--host-timeout`, etc.).
    2. Pass timing options to nmap.
    3. Parse and report timing-related scan stats.

### 5. Performance Optimization
- **Requirements:**
    - Enable scan parallelization and rate limiting.
- **Steps:**
    1. Expose nmap parallelism/rate options.
    2. Optionally, implement wrapper-level concurrency for multiple targets.
    3. Monitor and report performance metrics.

### 6. Enhanced Output Format Support
- **Requirements:**
    - Parse and support grepable (`-oG`) and normal (`-oN`) nmap outputs.
- **Steps:**
    1. Add options to select output format.
    2. Implement parsers for `-oG` and `-oN` formats.
    3. Structure parsed data consistently with XML/JSON output.

### 7. Traceroute Integration
- **Requirements:**
    - Parse and expose traceroute data from nmap output.
- **Steps:**
    1. Enable traceroute in nmap command (`--traceroute`).
    2. Parse traceroute section from output.
    3. Structure hop data in results.

### 8. Advanced Host Discovery
- **Requirements:**
    - Support ping sweeps, ARP discovery, and custom host discovery methods.
- **Steps:**
    1. Add options for host discovery techniques (`-sn`, `-PR`, etc.).
    2. Parse and report discovered hosts with method used.

### 9. Firewall Evasion (Advanced)
- **Requirements:**
    - Implement decoy scanning, source port manipulation, packet fragmentation.
- **Steps:**
    1. Expose and document advanced evasion flags.
    2. Validate user input and pass to nmap.
    3. Parse and report on evasion effectiveness if possible.

### 10. IPv6 Advanced Features
- **Requirements:**
    - Support IPv6-specific scan types and discovery.
- **Steps:**
    1. Add options for IPv6 scanning.
    2. Parse IPv6-specific output.

### 11. Custom Packet Crafting
- **Requirements:**
    - Allow raw packet manipulation for advanced scans.
- **Steps:**
    1. Expose nmap packet crafting options.
    2. Validate and pass custom packet options.

### 12. Scan Optimization
- **Requirements:**
    - Implement adaptive timing and bandwidth management.
- **Steps:**
    1. Monitor scan performance.
    2. Adjust timing/rate options dynamically if possible.

---
"""
