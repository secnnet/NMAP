# GitHub Security Content Research Findings

## GitHub Acceptable Use Policies - Key Security-Related Restrictions

### Prohibited Content and Activities:

**User Safety Violations:**
- Unlawful or promotes unlawful activities
- False, inaccurate, or intentionally deceptive information likely to adversely affect public interest (including health, safety, election integrity)
- Harassment or abuse of individuals or groups
- Threats or incitement of violence
- Gratuitous depiction or glorification of violence

**Site Access and Safety:**
- Content that directly supports unlawful active attack or malware campaigns causing technical harms
- Using platform to deliver malicious executables or as attack infrastructure
- Organizing denial of service attacks or managing command and control servers
- Attempting to disrupt or gain unauthorized access to services, devices, data, accounts, or networks

**Important Exception:**
- Activities permitted under bug bounty programs (like GitHub Bug Bounty program) are NOT considered "unauthorized" but must only affect the organization whose bug bounty program authorized the activity

**Intellectual Property Restrictions:**
- Cannot share unauthorized product licensing keys or software for bypassing licensing checks
- Cannot impersonate entities or misrepresent identity/purpose
- Cannot violate third party privacy by posting personal information without consent




## GitHub Security Policies and Coordinated Disclosure

### Security Policy Framework:
- Repositories should have a SECURITY.md file in root, docs, or .github folder
- Security policies provide instructions for reporting vulnerabilities
- GitHub automatically creates a link to security policy when issues are created
- Can create default security policies for organizations or personal accounts

### Two Vulnerability Reporting Processes:

**1. Standard Process:**
- Vulnerability reporters contact maintainers using security policy contact info
- Maintainers create draft repository advisory if required
- Public issue can be created asking for security contact if no policy exists

**2. Private Vulnerability Reporting:**
- Reporters disclose details directly to maintainers
- Done by proposing a draft repository advisory
- Provides private communication channel

### Best Practices for Vulnerability Reporters:
- Report vulnerabilities privately to maintainers first
- Avoid public disclosure without giving maintainers chance to remediate
- Don't bypass maintainers
- Don't disclose before fixed version is available
- Don't expect compensation where no bounty program exists
- Clearly state disclosure policy terms and timelines
- Public disclosure acceptable after reasonable time if no response

### Best Practices for Maintainers:
- Clearly indicate how/where to receive vulnerability reports
- Treat vulnerabilities as security issues, not simple bugs
- Acknowledge receipt quickly even if no immediate resources available
- Involve vulnerability reporter in verification process
- Take reporter's concerns and advice into consideration
- Always acknowledge the vulnerability reporter when crediting discovery
- Publish fix as soon as possible
- Make wider ecosystem aware of issue and remediation
- Explicitly mark commits/releases as security fixes

### GitHub Security Advisories:
- Allow maintainers to privately discuss and fix vulnerabilities
- Enable collaboration on fixes before public disclosure
- Make it easier for community to update dependencies
- Help research impact of security vulnerabilities


## GitHub Security Research Best Practices

### GitHub Security Lab Approach:
- Uses OpenSSF Criticality Score to identify high-impact targets (0-1 scale, >0.8 considered critical)
- Focuses on projects with high dependency usage and community impact
- Leverages GitHub's integrated security research tools

### Security Research Workflow:
1. **Target Identification:**
   - Use GitHub Code Search to find specific patterns/vulnerabilities across repositories
   - Consider dependency network impact (number of dependent projects)
   - Evaluate project activity, stars, contributors, and maintenance status
   - Use OpenSSF Criticality Score for prioritization

2. **Research Environment Setup:**
   - Fork target repository for isolated research
   - Use GitHub Codespaces for clean, temporary research environments
   - Set up CodeQL workflows for automated vulnerability detection
   - Remove existing workflows to avoid unwanted executions

3. **Vulnerability Discovery:**
   - Use CodeQL for semantic and dataflow analysis
   - Leverage code scanning for automated security checks
   - Query code as data using CodeQL's query language
   - Run Multi-repository Variant Analysis for scale research

4. **Verification and Testing:**
   - Use Codespaces for safe vulnerability verification
   - Test exploits in isolated environments
   - Document proof-of-concept responsibly

5. **Responsible Disclosure:**
   - Use Private Vulnerability Reporting (PVR) for initial contact
   - Follow coordinated disclosure timelines
   - Create draft security advisories for collaboration
   - Request CVE when appropriate for broader impact

### Tools and Features for Security Research:
- **GitHub Code Search:** Find vulnerability patterns across repositories
- **CodeQL:** Static analysis and semantic code querying
- **GitHub Codespaces:** Isolated research environments
- **Private Vulnerability Reporting:** Secure communication channel
- **Security Advisories:** Collaborative vulnerability management
- **Dependency Network:** Impact assessment
- **GitHub Actions:** Automated security scanning workflows


## OWASP Vulnerability Disclosure Guidelines

### Core Principles for Security Researchers:
- **Legal Compliance:** Ensure all testing is legal and authorized
- **Privacy Respect:** Respect privacy of others and redact personal data
- **Reasonable Contact Efforts:** Make reasonable efforts to contact security teams
- **Sufficient Detail:** Provide enough details for verification and reproduction
- **No Payment Demands:** Don't demand payment outside established bug bounty programs

### Core Principles for Organizations:
- **Clear Reporting Methods:** Provide clear, secure vulnerability reporting channels
- **Clear Scope:** Establish clear scope and terms for bug bounty programs
- **Reasonable Response Times:** Respond to reports in reasonable timeline
- **Open Communication:** Communicate openly with researchers
- **No Legal Threats:** Don't threaten legal action against researchers
- **CVE Requests:** Request CVEs where appropriate
- **Clear Advisories:** Publish clear security advisories and changelogs
- **Rewards and Credit:** Offer appropriate rewards and credit

### Three Disclosure Models:

**1. Private Disclosure:**
- Vulnerability reported privately to organization
- Organization decides whether to publish details
- Main problem: If vendor is unresponsive, details may never be public
- Most bug bounty programs require this model

**2. Full Disclosure:**
- Full details made public immediately upon discovery
- Often includes exploit code before patches available
- Very controversial and seen as irresponsible
- Should only be used as last resort when other methods fail

**3. Responsible/Coordinated Disclosure (Recommended):**
- Initial report made privately
- Full details published once patch is available
- Often includes deadline for organization response
- Google Project Zero uses 90-day disclosure timeline
- Balances security with public awareness

### Finding Contact Information:
- Bug bounty platforms (BugCrowd, HackerOne, huntr.dev, Open Bug Bounty)
- security.txt file at /.well-known/security.txt (RFC 9116)
- Issue tracking systems
- Generic emails (security@, abuse@)
- Contact Us pages
- Social media platforms
- Phone contact
- Community outreach
- National/sector CERTs for assistance

### Initial Report Requirements:
- Sufficient vulnerability details for understanding and reproduction
- HTTP requests/responses, HTML snippets, screenshots
- Redacted personal data
- Proof of concept code (if available)
- Impact assessment
- References and further reading
- Clear, simple language for non-security staff
- Mitigation recommendations (when confident)
- Disclosure timeline if planning to publish later


## Examples of Well-Regarded Security Repositories on GitHub

### Educational and Research-Focused Repositories:

**1. Awesome Security Lists:**
- **awesome-security** (13.2k stars): Comprehensive collection of security tools, libraries, documents, and resources
- **awesome-threat-intelligence**: Curated list of threat intelligence resources
- **awesome-vulnerability-research**: Resources about vulnerability research and exploit development

**2. Payload and Testing Collections:**
- **sql-injection-payload-list** (5.5k stars): Comprehensive SQL injection payloads for testing
- **command-injection-payload-list** (3.3k stars): Command injection payloads for various operating systems
- **rfi-lfi-payload-list**: Remote/Local File Inclusion payloads for web application testing

**3. Security Tools and Frameworks:**
- **OWASP Projects**: Official OWASP repositories with security standards and guidelines
- **Metasploit Framework**: Penetration testing and exploit development framework
- **OpenVAS**: Vulnerability scanning and management solution
- **Nmap**: Network discovery and security auditing utility

**4. Vulnerability Disclosure and Bug Bounty:**
- **disclose.io**: Open-source vulnerability disclosure and bug bounty program database
- **subdomain-takeover**: Vulnerability checker for subdomain takeover issues

### Characteristics of Well-Regarded Security Repositories:

**Content Quality:**
- Clear documentation and README files
- Proper categorization and organization
- Regular updates and maintenance
- Community contributions and collaboration
- Educational value and practical applicability

**Responsible Disclosure Focus:**
- Emphasis on ethical security research
- Clear guidelines for responsible use
- Educational rather than malicious intent
- Proper attribution and credit to researchers
- Compliance with legal and ethical standards

**Community Engagement:**
- Active issue tracking and discussion
- Pull request reviews and collaboration
- Clear contribution guidelines
- Responsive maintainers
- Educational resources and documentation

**Technical Standards:**
- Well-structured code and documentation
- Proper version control practices
- Clear licensing (typically open source)
- Comprehensive testing and validation
- Cross-platform compatibility where applicable

### Repository Categories Worth Sharing:

**1. Educational Resources:**
- Security learning materials and tutorials
- Vulnerability research methodologies
- Best practices and guidelines
- Case studies and real-world examples

**2. Security Tools and Utilities:**
- Open source security scanning tools
- Penetration testing frameworks
- Vulnerability assessment utilities
- Security automation scripts

**3. Reference Materials:**
- Payload collections for testing purposes
- Security checklists and standards
- Compliance frameworks and guidelines
- Threat intelligence feeds and indicators

**4. Research and Analysis:**
- Vulnerability research findings (responsibly disclosed)
- Security analysis of popular software
- Proof-of-concept demonstrations (educational)
- Security conference presentations and papers

