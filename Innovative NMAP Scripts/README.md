# Innovative Nmap Scripts Collection - Quick Start Guide

## Overview

This collection contains 6 innovative Nmap Scripting Engine (NSE) scripts that I've developed to address gaps in modern network reconnaissance capabilities. Each script focuses on contemporary technologies and deployment patterns that aren't adequately covered by existing NSE scripts.

After years of conducting security assessments, I got tired of manually identifying modern web frameworks, cloud services, and containerized applications. These scripts automate that entire process and provide detailed intelligence about the technologies you're actually encountering in the field today.

## Scripts Included

### 1. Cloud Metadata Detection (cloud-metadata-detect.nse)
**Purpose:** Detects exposure of cloud platform metadata services through web applications
**Key Features:**
- AWS, Azure, GCP metadata service detection
- SSRF vulnerability identification
- Instance information extraction
- Security configuration analysis

**Usage:**
```bash
nmap --script cloud-metadata-detect -p 80,443 target.com
nmap --script cloud-metadata-detect --script-args timeout=10 target.com
```

### 2. Container Detection (container-detect.nse)
**Purpose:** Identifies containerized applications and orchestration platforms
**Key Features:**
- Docker daemon detection and analysis
- Kubernetes cluster identification
- Container configuration extraction
- Security assessment capabilities

**Usage:**
```bash
nmap --script container-detect -p 80,443,2375,2376,8080,8443 target.com
nmap --script container-detect --script-args deep-scan=true target.com
```

### 3. Modern Web Technology Detection (modern-web-tech-detect.nse)
**Purpose:** Identifies contemporary web frameworks and technologies
**Key Features:**
- React, Vue.js, Angular detection
- Backend framework identification
- API architecture analysis
- Build tool detection

**Usage:**
```bash
nmap --script modern-web-tech-detect -p 80,443 target.com
nmap --script modern-web-tech-detect --script-args check-apis=true target.com
```

### 4. IoT Device Detection (iot-device-detect.nse)
**Purpose:** Comprehensive IoT device identification and security assessment
**Key Features:**
- IP camera detection (Hikvision, Dahua, Axis)
- Smart home device identification
- Industrial IoT detection
- Security vulnerability assessment

**Usage:**
```bash
nmap --script iot-device-detect -p 80,443,8080,8081 target.com
nmap --script iot-device-detect --script-args deep-probe=true target.com
```

### 5. Cryptocurrency Service Detection (crypto-service-detect.nse)
**Purpose:** Identifies blockchain nodes, mining services, and crypto exchanges
**Key Features:**
- Bitcoin/Ethereum node detection
- Mining pool identification
- Exchange platform detection
- Security analysis capabilities

**Usage:**
```bash
nmap --script crypto-service-detect -p 8332,8333,30303 target.com
nmap --script crypto-service-detect --script-args check-rpc=true target.com
```

### 6. Network Behavior Analysis (network-behavior-analysis.nse)
**Purpose:** Analyzes dynamic infrastructure behavior patterns
**Key Features:**
- Load balancer detection
- CDN identification
- Rate limiting analysis
- Geographic distribution assessment

**Usage:**
```bash
nmap --script network-behavior-analysis -p 80,443 target.com
nmap --script network-behavior-analysis --script-args samples=20,delay=2 target.com
```

## Installation Instructions

1. Copy all `.nse` files to your Nmap scripts directory:
   ```bash
   sudo cp *.nse /usr/share/nmap/scripts/
   ```

2. Update the NSE script database:
   ```bash
   sudo nmap --script-updatedb
   ```

3. Verify installation:
   ```bash
   nmap --script-help cloud-metadata-detect
   ```

## Important Legal and Ethical Considerations

⚠️ **CRITICAL:** I've designed these scripts for authorized security testing and research only. Please make sure you:

- Get explicit written authorization before scanning any systems
- Comply with all applicable laws and regulations in your jurisdiction
- Follow responsible disclosure principles for any vulnerabilities you discover
- Respect network resources and avoid causing service disruption
- Maintain confidentiality of any sensitive information you discover

I've been doing this work for years, and I can't stress enough how important it is to stay within legal and ethical boundaries. These tools are powerful, but they come with responsibility.

## Quick Examples

**Comprehensive scan of a web application:**
```bash
nmap --script cloud-metadata-detect,container-detect,modern-web-tech-detect,network-behavior-analysis -p 80,443 webapp.example.com
```

**IoT device discovery on local network:**
```bash
nmap --script iot-device-detect -p 80,443,8080 192.168.1.0/24
```

**Cryptocurrency service detection:**
```bash
nmap --script crypto-service-detect -p 8332,8333,30303,8545 blockchain-node.example.com
```

## Documentation

- **Complete Documentation:** `nmap_scripts_documentation.md` (50+ pages)
- **Technical Implementation:** Detailed in individual script files
- **Troubleshooting Guide:** Section 12 of complete documentation
- **Best Practices:** Section 11 of complete documentation

## Support and Contributions

These scripts represent my attempt to bridge the gap between traditional network reconnaissance and modern technology environments. I've designed them to be:

- **Minimally Intrusive:** Careful traffic management and error handling based on real-world experience
- **Comprehensive:** Extensive coverage of the technologies I actually encounter during assessments
- **Extensible:** Framework for adding new detection capabilities as technologies evolve
- **Professional:** Suitable for enterprise security assessments and compliance work

I'm always looking to improve these tools based on real-world feedback. If you find bugs, have feature requests, or want to contribute improvements, I'd love to hear from you.

For questions, issues, or contributions, check out the complete documentation for detailed guidance on troubleshooting, best practices, and responsible use.

---

**Version:** 1.0  
**Date:** June 6, 2025  
**Author:** Bilel Graine  
**License:** Use only with proper authorization for legitimate security testing and research

