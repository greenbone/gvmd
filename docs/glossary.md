## Glossary

| Term                             | Definition                                                                                                                                               |
|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Target**                       | A collection of hosts (IPs, domains, or ranges) that you want to scan. It also includes scan-related options like excluded hosts and alive test methods. |
| **Asset**                        | A long-term representation of a host. It combines data from multiple scans and keeps history like last seen time, severity counts, and identifiers.      |
| **Task**                         | A scan definition that links a target, scan configuration, and schedule. It controls how and when scans are executed.                                    |
| **Scan**                         | A single execution of a task. It runs vulnerability tests against the target and produces results.                                                       |
| **Result**                       | A single finding from a scan, such as a detected vulnerability or informational message.                                                                 |
| **Host Detail**                  | Additional structured information about a host discovered during a scan (e.g., OS, services, applications, ports).                                       |
| **Host**                         | A single machine (IP address or hostname) within a target that is scanned individually.                                                                  |
| **Port**                         | A network port (TCP/UDP) on a host that can be scanned for open services or vulnerabilities.                                                             |
| **Credential**                   | Authentication data (e.g., username/password, SSH key, SNMP, Kerberos) used to perform deeper, authenticated scans.                                      |
| **Scan Config**                  | A predefined set of vulnerability tests (VTs) and settings that define what checks are executed during a scan.                                           |
| **Preference**                   | Scanner settings that adjust how specific tests or the scanner behave.                                                                                   |
| **Scanner**                      | The application that performs the actual vulnerability checks (e.g., OpenVAS, openvasd, agent-controller, container-scanning, sensors).                  |
| **Scanner Type**                 | The communication type or implementation of the scanner (e.g., ospd-openvas, openvasd, agent-controller, container-scanning, sensors).                   |
| **Alive Test**                   | A method used before scanning to check if a host is reachable (e.g., ICMP ping, TCP connect).                                                            |
| **Report**                       | The stored output of a scan, including all results, summaries, and metadata.                                                                             |
| **Compliance Report**            | A report focused on compliance checks against policies or standards (e.g., CIS benchmarks).                                                              |
| **Schedule**                     | A configuration that defines when a task runs automatically in a specific period of time.                                                                |
| **Audit**                        |                                                                                                                                                          |
| **Owner**                        | The user who created a resource. Ownership is used for access control.                                                                                   |
| **Vulnerability**                | A weakness in a system, software, or configuration that could be exploited to cause harm (e.g., unauthorized access, data loss).                         |
| **Exploit**                      | A method or piece of code that takes advantage of a vulnerability to perform an attack (e.g., gaining access, running commands, or causing damage).      |
| **Detection**                    | The process of identifying a vulnerability, service, or system property during a scan.                                                                   |
| **NVT / VT**                     | A single vulnerability test that checks for a specific issue or misconfiguration.                                                                        |
| **NVT Family**                   | A logical group of related vulnerability tests.                                                                                                          |
| **VT Metadata**                  | Information about a test (OID, name, severity, references like CVE/CPE).                                                                                 |
| **QoD**                          | Quality of Detection (0–100%). Indicates how reliable a finding is. Higher means more confidence.                                                        |
| **Score**                        | A numeric value used to measure or rate something based on defined criteria.                                                                             |
| **CVSS**                         | A standardized score (0.0–10.0) representing how severe a vulnerability is based on impact and exploit.                                                  |
| **EPSS**                         | A score that estimates the likelihood that a vulnerability will be exploited in the real world.                                                          |
| **Severity**                     | A simplified category derived from scores (Low, Medium, High, Critical).                                                                                 |
| **Threat**                       | Another representation of risk level, often aligned with severity.                                                                                       |
| **CVE**                          | A unique public identifier for a known vulnerability (e.g., CVE-2024-12345).                                                                             |
| **CPE**                          | A standardized way to identify software, hardware, or operating systems.                                                                                 |
| **SBOM**                         | Software Bill of Materials. A structured list of all components (libraries, packages, dependencies) inside an application or container image.            |
| **SCAP Data**                    | Standardized security data used for automated vulnerability and compliance checks.                                                                       |
| **CERT Advisory**                | Security advisories published by organizations about vulnerabilities or threats.                                                                         |
| **Closed CVE**                   | A vulnerability that is resolved, mitigated, or no longer relevant for a host.                                                                           |
| **Feed**                         | External data source that provides updated VTs, CVEs, and security information.                                                                          |
| **Feed Status**                  | The current state of the feed (e.g., up-to-date, outdated, syncing).                                                                                     |
| **Report Formats**               | Output formats for reports (e.g., XML, PDF, JSON).                                                                                                       |
| **Data Object**                  | Any stored entity in the system (e.g., report, task, asset).                                                                                             |
| **Report Config**                | Settings that control how reports are generated and formatted.                                                                                           |
| **Report Host**                  | A host entry inside a report, including its findings.                                                                                                    |
| **Host Asset**                   | The asset representation of a host, maintained across multiple scans.                                                                                    |
| **User**                         | A system account that interacts with the platform.                                                                                                       |
| **Role**                         | A collection of permissions assigned to users.                                                                                                           |
| **Permission**                   | A rule defining allowed actions.                                                                                                                         |
| **Group**                        |                                                                                                                                                          |
| **Alert**                        | A notification triggered by events (e.g., scan finished, high severity found).                                                                           |
| **Access Token**                 | A short-lived credential used to authenticate API requests.                                                                                              |
| **Agent**                        | A lightweight component installed on hosts to assist scanning or data collection.                                                                        |
| **Agent Controller**             | A service that manages and communicates with multiple agents.                                                                                            |
| **Agent Controller Scan Config** | Scan settings used specifically for agent-based scanning as default.                                                                                     |
| **Agent Group**                  | A logical grouping of agents.                                                                                                                            |
| **Agent Installer**              | Tool or package used to deploy agents.                                                                                                                   |
| **Port List**                    | A predefined set of ports to scan.                                                                                                                       |
| **Container Scanning**           | Scanning container images (e.g., Docker) for vulnerabilities.                                                                                            |
| **OCI Image Target**             | A container image defined as a scan target.                                                                                                              |
| **OCI Image**                    | A container image following OCI standards (e.g., Docker image).                                                                                          |
| **Sensor**                       | A scanner that works on specific network.                                                                                                                |
| **Master**                       | The main scanner of the system.                                                                                                                          |
| **Feed Key**                     | A key used to authenticate and download feed data.                                                                                                       |
| **Remediation Ticket**           | A task or issue created to fix a detected vulnerability.                                                                                                 |
| **Policy**                       | A set of rules defining security or compliance requirements.                                                                                             |
| **Override**                     | A manual adjustment to a finding (e.g., marking it as false positive).                                                                                   |
| **Note**                         | A comment added to a result or resource.                                                                                                                 |
| **Tag**                          | A label used to organize and categorize resources.                                                                                                       |
| **Filter**                       | A query rule used to search or limit data (e.g., severity > 7).                                                                                          |
| **User Setting**                 | Preferences specific to a user account.                                                                                                                  |
| **Resource / Entity Type**       | A category of objects (e.g., task, report, asset).                                                                                                       |
| **TLS Certificate**              | A TLS/SSL certificate discovered during a scan on a host or service (e.g., HTTPS).                                                                       |
| **Operating System**             | The OS detected on a host (e.g., Linux, Windows).                                                                                                        |
| **Security Information**         | General security-related data collected or processed by the system.                                                                                      |
| **Feed Owner**                   | The user responsible for maintaining the feed.                                                                                                           |
| **Agent Owner**                  | The user  responsible for an agent.                                                                                                                      |
| **Admin**                        | A user with elevated permissions.                                                                                                                        |
| **Super Admin**                  | A user with full system control.                                                                                                                         |
| **Feature Flag**                 | A toggle used to enable or disable features without redeploying.                                                                                         |
| **Performance Report**           | A report showing system or scan performance metrics.                                                                                                     |
| **GXR Report**                   | A specialized report format used within the system.                                                                                                      |
| **Pheme**                        | An internal or system-specific component for report.                                                                                                     |
| **Authentication Method**        | The way users log in (password, jwt, LDAP, RADIUS, etc.).                                                                                                |
| **Trashcan**                     | A temporary storage for deleted resources before permanent removal.                                                                                      |
| **Alert Condition**              | A rule that defines when an alert should trigger.                                                                                                        |
| **Alert Event**                  | The event that activates an alert.                                                                                                                       |
| **Alert Method**                 | The delivery method (email, webhook, etc.).                                                                                                              |
| **LDAP**                         | Directory-based authentication system.                                                                                                                   |
| **RADIUS**                       | Network-based authentication protocol.                                                                                                                   |
| **Aggregate**                    | Combined or summarized data (e.g., counts, averages).                                                                                                    |
| **Dashboard**                    | A visual overview of key metrics and data.                                                                                                               |
| **Task Wizard**                  | A guided UI to help users create tasks easily.                                                                                                           |
| **Integration Config**           | Settings used to connect with external systems (e.g., openvas security intelligence).                                                                    |
| **Asset Snapshot**               | A saved state of assets at a specific point in time after completed scans.                                                                               |
| **Asset Key**                    | A unique identifier used to track an asset across scans.                                                                                                 |
| **Start Scan**                   | Action to begin a scan.                                                                                                                                  |
| **Stop Scan**                    | Action to stop a running scan.                                                                                                                           |
| **Resume Scan**                  | Action to continue a paused scan.                                                                                                                        |
