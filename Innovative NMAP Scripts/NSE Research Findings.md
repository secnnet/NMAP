# Nmap NSE Research Findings

## NSE Script Structure

Based on research of the official Nmap documentation, NSE scripts follow this structure:

### 1. Script Header (Metadata)
- **description**: Paragraph describing what the script does
- **categories**: Script categories (safe, default, intrusive, etc.)
- **dependencies**: Other scripts this depends on
- **author**: Script author information
- **license**: Licensing information
- **NSEDoc tags**: @usage, @args, @output documentation

### 2. The Rule Function
- Lua method that decides whether to skip or execute the script
- Based on host/port information and scan results
- Returns true/false to determine if action should run

### 3. The Action Function
- Contains the actual script functionality
- Performs the network operations and analysis
- Returns results to be displayed

## Script Categories
- **safe**: Scripts that are unlikely to crash services or consume significant resources
- **default**: Scripts that run by default with -sC option
- **intrusive**: Scripts that might crash services or consume significant resources
- **malware**: Scripts that detect malware
- **vuln**: Scripts that check for vulnerabilities
- **discovery**: Scripts that try to discover more information about the network
- **auth**: Scripts that deal with authentication
- **brute**: Scripts that use brute force attacks
- **dos**: Scripts that may cause denial of service

## Key NSE Libraries Available
- nmap: Core Nmap functionality
- stdnse: Standard NSE library functions
- shortport: Common port checking functions
- http: HTTP client functionality
- smtp: SMTP protocol functions
- ssh: SSH protocol functions
- ssl: SSL/TLS functionality
- dns: DNS resolution functions
- json: JSON parsing
- base64: Base64 encoding/decoding

## Current Script Gaps Identified
1. **Modern Cloud Services**: Limited detection of cloud-specific services and configurations
2. **Container Technologies**: Minimal Docker/Kubernetes detection capabilities
3. **IoT Device Fingerprinting**: Basic IoT device identification
4. **Modern Web Frameworks**: Limited detection of current web technologies
5. **API Endpoint Discovery**: Minimal REST/GraphQL API detection
6. **Cryptocurrency Services**: No blockchain/crypto service detection
7. **Modern Authentication**: Limited OAuth/SAML/JWT detection
8. **Edge Computing**: No edge computing service detection
9. **Serverless Functions**: No serverless platform detection
10. **Modern Databases**: Limited NoSQL and modern database detection

