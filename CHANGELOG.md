# Changelog

All notable changes to **Linux Digital Detective** are documented in this file.

The format follows the general principles of [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-10-07

### Added

- Linux DFIR case management
- Case creation, listing, and lifecycle management
- Evidence collection and registration
- SHA-256 evidence integrity verification
- Evidence manifest management
- Evidence metadata handling
- Linux authentication log parsing
- SSH log parsing
- `sudo` log parsing
- Syslog parsing
- Bash history parsing
- Web access log parsing
- Unified evidence parser routing
- Event normalization
- Investigation timeline generation
- SSH brute-force detection
- Successful-login-after-brute-force detection
- Privilege escalation detection
- Suspicious command detection
- Network activity detection
- Persistence mechanism detection
- Multi-source event correlation
- Attack-chain reconstruction
- Investigation risk scoring
- Severity assessment
- Investigation story generation
- MITRE ATT&CK technique mapping
- JSON investigation reports
- CSV findings reports
- HTML investigation reports
- Interactive Flask DFIR dashboard
- Case investigation workflow
- Evidence inspection interface
- Timeline investigation interface
- Findings interface
- Reconstructed attack-path interface
- Risk assessment interface
- Risk score interface
- Investigation story interface
- MITRE ATT&CK interface
- Report interface
- Six reproducible investigation cases
- Automated Python test suite
- GitHub Actions CI workflow
- Project security policy
- Contribution guidelines
- Code of conduct
- MIT License

### Investigation Cases

- `CASE-0001` — SSH Compromise Investigation
- `CASE-0002` — SSH Brute-Force Investigation
- `CASE-0003` — Privilege Escalation Investigation
- `CASE-0004` — Persistence Mechanism Investigation
- `CASE-0005` — Web Server Compromise
- `CASE-0006` — Multi-Stage Linux Intrusion

### Validation

- 150 automated tests passing
- Evidence hashing tests
- Parser tests
- Detection tests
- Timeline tests
- Correlation tests
- Investigation tests
- Reporting tests
- Case-management tests

## [Unreleased]

### Planned

- Additional Linux artifact parsers
- Expanded detection rules
- Sigma rule integration
- YARA integration
- IOC extraction
- Network/PCAP evidence correlation
- Automated evidence acquisition
- Advanced timeline filtering
- Expanded MITRE ATT&CK coverage
- Case export/import
- Analyst investigation notes
- Additional dashboard visualizations

[1.0.0]: .
