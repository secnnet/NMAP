# Innovative Nmap Scripts Collection

## About This Project

Hey there! I'm Bilel Graine, and I've been working in cybersecurity for several years now. During my time conducting penetration tests and security assessments, I kept running into the same frustrating problem: the existing Nmap scripts just weren't keeping up with modern technology stacks.

You know how it is - you're scanning a target and you can tell there's a React app running, or you suspect there's a Docker container behind that web service, but the standard NSE scripts come up empty. That's exactly why I decided to build this collection.

## What I've Built

I've developed 6 completely new NSE scripts that focus on the technologies we actually encounter in the field today. These aren't just minor tweaks to existing scripts - they're built from the ground up to detect and analyze modern infrastructure that traditional tools miss.

### The Scripts

**Cloud Metadata Detection** - This one's been a game-changer for me. I can't tell you how many times I've found SSRF vulnerabilities that expose AWS metadata services. This script automates that entire process and extracts detailed instance information.

**Container Detection** - Finally, a proper way to identify Docker and Kubernetes deployments! This script can spot containerized apps, extract configuration details, and even identify security misconfigurations.

**Modern Web Tech Detection** - No more guessing whether that's a React, Vue, or Angular app. This script identifies all the modern frontend frameworks, backend technologies, and even the build tools used.

**IoT Device Detection** - I've spent way too much time manually identifying IP cameras and IoT devices during assessments. This script automates the whole process and includes security checks for default credentials and common vulnerabilities.

**Cryptocurrency Service Detection** - With crypto becoming mainstream, I needed a way to identify blockchain nodes, mining pools, and exchange platforms. This script covers all the major cryptocurrencies and services.

**Network Behavior Analysis** - This is probably my favorite. Instead of just looking at static responses, it analyzes how services behave over time to identify load balancers, CDNs, and rate limiting mechanisms.

## Why I Built These

Look, I'm not trying to reinvent the wheel here. The existing NSE scripts are great for what they do, but they were built for a different era. When I'm doing a pentest in 2025, I need to understand:

- Is this running in AWS, Azure, or GCP?
- Are there containers I should be aware of?
- What modern frameworks are being used?
- Are there IoT devices on this network?
- Is there any crypto-related infrastructure?
- How is the traffic being managed and distributed?

The standard scripts just don't answer these questions effectively.

## Real-World Testing

I've been using these scripts in actual engagements for months now, and they've consistently provided valuable intelligence that I wouldn't have gotten otherwise. Just last week, the cloud metadata script helped me identify an SSRF vulnerability that led to full AWS account compromise.

The IoT detection script has been particularly useful for compliance assessments - being able to quickly inventory all the IP cameras and smart devices on a network saves hours of manual work.

## Technical Approach

Each script is designed with real-world constraints in mind:

- **Minimal network footprint** - I know how important it is not to trigger security alerts
- **Configurable timing** - You can adjust timeouts and delays based on your target environment
- **Comprehensive error handling** - No crashes or hanging connections
- **Detailed output** - You get actionable intelligence, not just "service detected"

I've also included extensive documentation because I know how frustrating it is when you find a tool but can't figure out how to use it effectively.

## Responsible Use

I need to be clear about this - these scripts are powerful, and with power comes responsibility. I've built them for legitimate security testing and research only. Always make sure you have proper authorization before scanning any systems.

I've included comprehensive guidance on legal and ethical considerations because I've seen too many good security professionals get into trouble by not understanding the boundaries.

## What's Next

This is just the beginning. I'm constantly encountering new technologies and deployment patterns that need better detection capabilities. I'm planning to add support for:

- Edge computing platforms
- AI/ML service detection
- Advanced cloud-native security controls
- Emerging IoT protocols

If you're using these scripts and have ideas for improvements or new capabilities, I'd love to hear from you.

## Getting Started

The README file has all the installation and usage instructions you need. The comprehensive documentation covers everything from basic usage to advanced deployment scenarios.

I've tried to make everything as straightforward as possible, but if you run into issues, the troubleshooting section should help you get sorted.

---

**Bilel Graine**  
*Cybersecurity Professional & Tool Developer*  
*June 2025*

*"Building the reconnaissance tools that modern security professionals actually need."*

