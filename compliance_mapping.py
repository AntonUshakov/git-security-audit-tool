"""
Compliance Mapping to International Standards

Maps GitHub security checks to SOC 2 Trust Services Criteria,
NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022 Annex A and CIS Controls v8.1.1.

These mappings are an aid to evidence gathering, not a certification.
A passing check is one input to a control; it does not by itself
satisfy that control for an auditor.
"""

COMPLIANCE_MAPPING = {
    '2FA Enforcement': {
        "soc2": {"control": 'CC6.1', "title": 'Logical Access Security',
                  "description": "SOC 2 Trust Services Criteria CC6.1"},
        "nist": {"controls": ['IA-2(1)', 'AC-2(1)'], "titles": ['IA-2(1)', 'AC-2(1)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.16', 'A.8.5'], "titles": ['Identity management', 'Secure authentication'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.3', "title": 'Require MFA for Externally-Exposed Applications',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'SSO Configuration': {
        "soc2": {"control": 'CC6.1', "title": 'Logical Access Security',
                  "description": "SOC 2 Trust Services Criteria CC6.1"},
        "nist": {"controls": ['IA-2', 'IA-8'], "titles": ['IA-2', 'IA-8'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.16', 'A.5.17'], "titles": ['Identity management', 'Authentication information'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.7', "title": 'Centralize Access Control',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Default Repository Permission': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6', 'AC-3'], "titles": ['AC-6', 'AC-3'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.5.18'], "titles": ['Access control', 'Access rights'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.8', "title": 'Define and Maintain Role-Based Access Control',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Member Repository Creation': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6(1)', 'CM-5'], "titles": ['AC-6(1)', 'CM-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.4'], "titles": ['Access control', 'Access to source code'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.8', "title": 'Define and Maintain Role-Based Access Control',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Audit Logging': {
        "soc2": {"control": 'CC7.2', "title": 'System Monitoring',
                  "description": "SOC 2 Trust Services Criteria CC7.2"},
        "nist": {"controls": ['AU-2', 'AU-6'], "titles": ['AU-2', 'AU-6'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.15', 'A.8.16'], "titles": ['Logging', 'Monitoring activities'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '8.2', "title": 'Collect Audit Logs',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Repository Visibility': {
        "soc2": {"control": 'CC6.6', "title": 'Boundary Protection',
                  "description": "SOC 2 Trust Services Criteria CC6.6"},
        "nist": {"controls": ['AC-3', 'SC-7'], "titles": ['AC-3', 'SC-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.12', 'A.8.3'], "titles": ['Classification of information', 'Information access restriction'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.3', "title": 'Configure Data Access Control Lists',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Branch Protection Rules': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3', 'CM-5'], "titles": ['CM-3', 'CM-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.8.4'], "titles": ['Change management', 'Access to source code'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Pull Request Reviews': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3(1)', 'SA-11'], "titles": ['CM-3(1)', 'SA-11'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.8.25'], "titles": ['Change management', 'Secure development life cycle'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Status Checks Before Merge': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['SA-11', 'CM-4'], "titles": ['SA-11', 'CM-4'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.29', 'A.8.32'], "titles": ['Security testing in development and acceptance', 'Change management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.12', "title": 'Implement Code-Level Security Checks',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Commit Signing': {
        "soc2": {"control": 'CC6.8', "title": 'Integrity of Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['SI-7', 'SC-13'], "titles": ['SI-7', 'SC-13'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.24', 'A.8.26'], "titles": ['Use of cryptography', 'Application security requirements'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.4', "title": 'Establish and Manage an Inventory of Third-Party Software Components',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Dismiss Stale PR Reviews': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3(1)'], "titles": ['CM-3(1)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32'], "titles": ['Change management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Code Owner Reviews': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3(1)', 'AC-5'], "titles": ['CM-3(1)', 'AC-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.5.3'], "titles": ['Change management', 'Segregation of duties'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Admin Bypass Prevention': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6(2)', 'CM-5(1)'], "titles": ['AC-6(2)', 'CM-5(1)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.32'], "titles": ['Access control', 'Change management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '5.4', "title": 'Restrict Administrator Privileges to Dedicated Administrator Accounts',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Linear History Required': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3', 'AU-10'], "titles": ['CM-3', 'AU-10'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.8.15'], "titles": ['Change management', 'Logging'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Force Push Protection': {
        "soc2": {"control": 'CC6.8', "title": 'Integrity of Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['SI-7', 'CM-5'], "titles": ['SI-7', 'CM-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.8.4'], "titles": ['Change management', 'Access to source code'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Branch Deletion Protection': {
        "soc2": {"control": 'A1.2', "title": 'Availability - Backup and Recovery',
                  "description": "SOC 2 Trust Services Criteria A1.2"},
        "nist": {"controls": ['CP-9', 'SI-7'], "titles": ['CP-9', 'SI-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.13', 'A.8.32'], "titles": ['Information backup', 'Change management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '11.1', "title": 'Establish and Maintain a Data Recovery Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Secrets Scanning': {
        "soc2": {"control": 'CC6.1', "title": 'Logical Access Security',
                  "description": "SOC 2 Trust Services Criteria CC6.1"},
        "nist": {"controls": ['IA-5', 'SI-4'], "titles": ['IA-5', 'SI-4'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.12', 'A.5.17'], "titles": ['Data leakage prevention', 'Authentication information'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.1', "title": 'Establish and Maintain a Data Management Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Push Protection': {
        "soc2": {"control": 'CC6.1', "title": 'Logical Access Security',
                  "description": "SOC 2 Trust Services Criteria CC6.1"},
        "nist": {"controls": ['IA-5', 'SI-10'], "titles": ['IA-5', 'SI-10'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.12', 'A.8.28'], "titles": ['Data leakage prevention', 'Secure coding'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.1', "title": 'Establish and Maintain a Data Management Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Dependency Scanning': {
        "soc2": {"control": 'CC7.1', "title": 'Vulnerability Management',
                  "description": "SOC 2 Trust Services Criteria CC7.1"},
        "nist": {"controls": ['RA-5', 'SI-2'], "titles": ['RA-5', 'SI-2'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.8', 'A.5.21'], "titles": ['Management of technical vulnerabilities', 'Managing information security in the ICT supply chain'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '7.5', "title": 'Perform Automated Vulnerability Scans of Internal Enterprise Assets',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'SECURITY.md File': {
        "soc2": {"control": 'CC2.2', "title": 'Internal Communication',
                  "description": "SOC 2 Trust Services Criteria CC2.2"},
        "nist": {"controls": ['IR-6', 'SI-5'], "titles": ['IR-6', 'SI-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.6.8', 'A.5.24'], "titles": ['Information security event reporting', 'Incident management planning and preparation'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '17.1', "title": 'Designate Personnel to Manage Incident Handling',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'CODEOWNERS File': {
        "soc2": {"control": 'CC1.3', "title": 'Organizational Structure',
                  "description": "SOC 2 Trust Services Criteria CC1.3"},
        "nist": {"controls": ['AC-5', 'CM-9'], "titles": ['AC-5', 'CM-9'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.2', 'A.5.3'], "titles": ['Information security roles and responsibilities', 'Segregation of duties'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    '.gitignore Configuration': {
        "soc2": {"control": 'CC6.1', "title": 'Logical Access Security',
                  "description": "SOC 2 Trust Services Criteria CC6.1"},
        "nist": {"controls": ['SC-28', 'IA-5'], "titles": ['SC-28', 'IA-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.12', 'A.5.10'], "titles": ['Data leakage prevention', 'Acceptable use of information'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.1', "title": 'Establish and Maintain a Data Management Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Repository Activity': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['CM-8', 'AC-2(3)'], "titles": ['CM-8', 'AC-2(3)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.9', 'A.8.9'], "titles": ['Inventory of information and other associated assets', 'Configuration management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '1.1', "title": 'Establish and Maintain Detailed Enterprise Asset Inventory',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Actions Allowed Actions Policy': {
        "soc2": {"control": 'CC6.8', "title": 'Prevention of Unauthorized Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['CM-7(5)', 'SA-12'], "titles": ['CM-7(5)', 'SA-12'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.19', 'A.5.21'], "titles": ['Installation of software on operational systems', 'Managing information security in the ICT supply chain'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '2.5', "title": 'Allowlist Authorized Software',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Actions Default Token Permissions': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6', 'AC-6(1)'], "titles": ['AC-6', 'AC-6(1)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.2'], "titles": ['Access control', 'Privileged access rights'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '5.4', "title": 'Restrict Administrator Privileges to Dedicated Administrator Accounts',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Actions Pull Request Approval': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['AC-5', 'CM-3(1)'], "titles": ['AC-5', 'CM-3(1)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.3', 'A.8.32'], "titles": ['Segregation of duties', 'Change management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.1', "title": 'Establish and Maintain a Secure Application Development Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Workflow Token Permissions': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6', 'SC-2'], "titles": ['AC-6', 'SC-2'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.2'], "titles": ['Access control', 'Privileged access rights'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.3', "title": 'Configure Data Access Control Lists',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Action Version Pinning': {
        "soc2": {"control": 'CC6.8', "title": 'Integrity of Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['SA-12', 'SI-7', 'CM-14'], "titles": ['SA-12', 'SI-7', 'CM-14'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.21', 'A.8.28'], "titles": ['Managing information security in the ICT supply chain', 'Secure coding'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.4', "title": 'Establish and Manage an Inventory of Third-Party Software Components',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Workflow Permissions Declared': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6(1)', 'CM-7'], "titles": ['AC-6(1)', 'CM-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.9'], "titles": ['Access control', 'Configuration management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '4.1', "title": 'Establish and Maintain a Secure Configuration Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Untrusted Workflow Triggers': {
        "soc2": {"control": 'CC6.6', "title": 'Boundary Protection',
                  "description": "SOC 2 Trust Services Criteria CC6.6"},
        "nist": {"controls": ['SI-10', 'SC-18'], "titles": ['SI-10', 'SC-18'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.28', 'A.8.26'], "titles": ['Secure coding', 'Application security requirements'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.11', "title": 'Leverage Vetted Modules or Services for Application Security Components',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Self-Hosted Runner Exposure': {
        "soc2": {"control": 'CC6.6', "title": 'Boundary Protection',
                  "description": "SOC 2 Trust Services Criteria CC6.6"},
        "nist": {"controls": ['SC-7', 'AC-4'], "titles": ['SC-7', 'AC-4'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.22', 'A.8.20'], "titles": ['Segregation of networks', 'Networks security'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '12.2', "title": 'Establish and Maintain a Secure Network Architecture',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Build Provenance Attestation': {
        "soc2": {"control": 'CC6.8', "title": 'Integrity of Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['SA-12', 'SR-4', 'SI-7'], "titles": ['SA-12', 'SR-4', 'SI-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.21', 'A.8.24'], "titles": ['Managing information security in the ICT supply chain', 'Use of cryptography'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.4', "title": 'Establish and Manage an Inventory of Third-Party Software Components',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Repository Actions Policy': {
        "soc2": {"control": 'CC6.8', "title": 'Prevention of Unauthorized Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['CM-7(5)', 'SR-3'], "titles": ['CM-7(5)', 'SR-3'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.19', 'A.5.21'], "titles": ['Installation of software on operational systems', 'Managing information security in the ICT supply chain'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '2.5', "title": 'Allowlist Authorized Software',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Action SHA Pinning Policy': {
        "soc2": {"control": 'CC6.8', "title": 'Integrity of Software',
                  "description": "SOC 2 Trust Services Criteria CC6.8"},
        "nist": {"controls": ['CM-14', 'SI-7', 'SR-4'], "titles": ['CM-14', 'SI-7', 'SR-4'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.19', 'A.8.24'], "titles": ['Installation of software on operational systems', 'Use of cryptography'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '16.4', "title": 'Establish and Manage an Inventory of Third-Party Software Components',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Fork Pull Request Workflows': {
        "soc2": {"control": 'CC6.6', "title": 'Boundary Protection',
                  "description": "SOC 2 Trust Services Criteria CC6.6"},
        "nist": {"controls": ['AC-4', 'SC-7'], "titles": ['AC-4', 'SC-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.20', 'A.5.14'], "titles": ['Networks security', 'Information transfer'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '3.3', "title": 'Configure Data Access Control Lists',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Ruleset Enforcement Status': {
        "soc2": {"control": 'CC8.1', "title": 'Change Management',
                  "description": "SOC 2 Trust Services Criteria CC8.1"},
        "nist": {"controls": ['CM-3', 'CM-6'], "titles": ['CM-3', 'CM-6'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.32', 'A.8.9'], "titles": ['Change management', 'Configuration management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '4.1', "title": 'Establish and Maintain a Secure Configuration Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Organization Owner Count': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6(5)', 'AC-2(7)'], "titles": ['AC-6(5)', 'AC-2(7)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.15', 'A.8.2'], "titles": ['Access control', 'Privileged access rights'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '5.4', "title": 'Restrict Administrator Privileges to Dedicated Administrator Accounts',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Direct Collaborator Grants': {
        "soc2": {"control": 'CC6.2', "title": 'Registration and Authorization of Users',
                  "description": "SOC 2 Trust Services Criteria CC6.2"},
        "nist": {"controls": ['AC-2', 'AC-2(3)'], "titles": ['AC-2', 'AC-2(3)'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.18', 'A.5.16'], "titles": ['Access rights', 'Identity management'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.1', "title": 'Establish an Access Granting Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Outside Collaborator Access': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-2(1)', 'PS-7'], "titles": ['AC-2(1)', 'PS-7'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.5.19', 'A.5.18'], "titles": ['Information security in supplier relationships', 'Access rights'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '6.2', "title": 'Establish an Access Revoking Process',
                     "description": "CIS Critical Security Controls v8.1"},
    },
    'Repository Admin Concentration': {
        "soc2": {"control": 'CC6.3', "title": 'Least Privilege Access',
                  "description": "SOC 2 Trust Services Criteria CC6.3"},
        "nist": {"controls": ['AC-6(5)', 'AC-5'], "titles": ['AC-6(5)', 'AC-5'],
                  "references": "NIST SP 800-53 Rev. 5"},
        "iso27001": {"controls": ['A.8.2', 'A.5.3'], "titles": ['Privileged access rights', 'Segregation of duties'],
                      "references": "ISO/IEC 27001:2022 Annex A"},
        "cis_csc": {"control": '5.4', "title": 'Restrict Administrator Privileges to Dedicated Administrator Accounts',
                     "description": "CIS Critical Security Controls v8.1"},
    },
}

def get_check_compliance(check_name: str) -> dict:
    """Get compliance mapping for a specific check"""
    return COMPLIANCE_MAPPING.get(check_name, {})

def calculate_compliance_scores(audit_results: dict) -> dict:
    """Calculate compliance scores by standard"""
    checks = audit_results.get("checks", {})
    
    # Initialize scoring buckets
    scores = {
        "soc2": {"passed": 0, "total": 0, "controls": set()},
        "nist": {"passed": 0, "total": 0, "controls": set()},
        "iso27001": {"passed": 0, "total": 0, "controls": set()},
        "cis_csc": {"passed": 0, "total": 0, "controls": set()}
    }
    
    # Collect all repository checks
    all_checks = {}
    
    # Organization checks
    if "organization" in checks:
        for check_name, result in checks["organization"].get("details", {}).items():
            all_checks[check_name] = result
    
    # Repository checks
    if "repositories" in checks:
        for repo_name, repo_checks in checks["repositories"].items():
            for check_name, result in repo_checks.get("details", {}).items():
                # Keep track of unique checks
                if check_name not in all_checks:
                    all_checks[check_name] = result
    
    # Map checks to standards
    for check_name, result in all_checks.items():
        mapping = COMPLIANCE_MAPPING.get(check_name, {})
        status = result.get("status", "pass" if result.get("passed") else "fail")
        if status in ("unknown", "not_applicable"):
            # Not evaluated: excluded from the denominator, not a gap.
            continue
        passed = status == "pass"
        
        # SOC2
        if "soc2" in mapping:
            scores["soc2"]["total"] += 1
            scores["soc2"]["controls"].add(mapping["soc2"]["control"])
            if passed:
                scores["soc2"]["passed"] += 1
        
        # NIST
        if "nist" in mapping:
            for control in mapping["nist"].get("controls", []):
                scores["nist"]["total"] += 1
                scores["nist"]["controls"].add(control)
                if passed:
                    scores["nist"]["passed"] += 1
        
        # ISO27001
        if "iso27001" in mapping:
            for control in mapping["iso27001"].get("controls", []):
                scores["iso27001"]["total"] += 1
                scores["iso27001"]["controls"].add(control)
                if passed:
                    scores["iso27001"]["passed"] += 1
        
        # CIS CSC
        if "cis_csc" in mapping:
            scores["cis_csc"]["total"] += 1
            scores["cis_csc"]["controls"].add(mapping["cis_csc"]["control"])
            if passed:
                scores["cis_csc"]["passed"] += 1
    
    # Calculate percentages
    result = {}
    for standard, data in scores.items():
        total = data["total"]
        passed = data["passed"]
        percentage = (passed / total * 100) if total > 0 else 0
        
        result[standard] = {
            "passed": passed,
            "total": total,
            "percentage": round(percentage, 2),
            "controls_covered": len(data["controls"]),
            "controls": sorted(list(data["controls"]))
        }
    
    return result

def get_compliance_gaps(audit_results: dict) -> dict:
    """Identify compliance gaps for each standard"""
    checks = audit_results.get("checks", {})
    gaps = {
        "soc2": [],
        "nist": [],
        "iso27001": [],
        "cis_csc": []
    }
    
    # Collect failed checks
    failed_checks = {}
    
    if "organization" in checks:
        for check_name, result in checks["organization"].get("details", {}).items():
            if not result.get("passed", False):
                failed_checks[check_name] = result
    
    if "repositories" in checks:
        for repo_name, repo_checks in checks["repositories"].items():
            for check_name, result in repo_checks.get("details", {}).items():
                if check_name not in failed_checks and not result.get("passed", False):
                    failed_checks[check_name] = result
    
    # Map failed checks to standards
    for check_name, result in failed_checks.items():
        mapping = COMPLIANCE_MAPPING.get(check_name, {})
        message = result.get("message", "")
        
        if "soc2" in mapping:
            gaps["soc2"].append({
                "check": check_name,
                "control": mapping["soc2"]["control"],
                "title": mapping["soc2"]["title"],
                "message": message,
                "requirement": mapping["soc2"]["description"]
            })
        
        if "nist" in mapping:
            for control in mapping["nist"].get("controls", []):
                gaps["nist"].append({
                    "check": check_name,
                    "control": control,
                    "title": mapping["nist"].get("titles", [""])[0],
                    "message": message,
                    "requirement": "NIST SP 800-53 Rev. 5"
                })
        
        if "iso27001" in mapping:
            for control in mapping["iso27001"].get("controls", []):
                gaps["iso27001"].append({
                    "check": check_name,
                    "control": control,
                    "title": mapping["iso27001"].get("titles", [""])[0],
                    "message": message,
                    "requirement": "ISO/IEC 27001:2022"
                })
        
        if "cis_csc" in mapping:
            gaps["cis_csc"].append({
                "check": check_name,
                "control": mapping["cis_csc"]["control"],
                "title": mapping["cis_csc"]["title"],
                "message": message,
                "requirement": mapping["cis_csc"]["description"]
            })
    
    return gaps

def get_risk_level_for_standard(score: float) -> tuple:
    """Get risk level and color for compliance score"""
    if score >= 90:
        return "LOW RISK", "#10b981"
    elif score >= 70:
        return "MEDIUM RISK", "#f59e0b"
    elif score >= 50:
        return "HIGH RISK", "#f97316"
    else:
        return "CRITICAL RISK", "#ef4444"


# ---------------------------------------------------------------------------
# Standard scoping
# ---------------------------------------------------------------------------

STANDARDS = {
    "soc2": {
        "key": "soc2",
        "name": "SOC 2 Trust Services Criteria",
        "reference": "AICPA Trust Services Criteria (2017, with 2022 points of focus)",
        "control_label": "Criterion",
    },
    "nist": {
        "key": "nist",
        "name": "NIST SP 800-53 Rev. 5",
        "reference": "NIST Special Publication 800-53 Revision 5",
        "control_label": "Control",
    },
    "iso27001": {
        "key": "iso27001",
        "name": "ISO/IEC 27001:2022",
        "reference": "ISO/IEC 27001:2022 Annex A",
        "control_label": "Annex A control",
    },
    "cis": {
        "key": "cis_csc",
        "name": "CIS Controls v8.1",
        "reference": "CIS Critical Security Controls v8.1",
        "control_label": "Safeguard",
    },
}


def resolve_standard(name):
    """Accept 'soc2', 'SOC2', 'iso', 'cis_csc' and so on."""
    if not name or str(name).lower() in ("all", "none"):
        return None
    key = str(name).lower().replace("-", "").replace(" ", "").replace("_", "")
    aliases = {
        "soc2": "soc2", "soc": "soc2",
        "nist": "nist", "nist80053": "nist", "sp80053": "nist",
        "iso": "iso27001", "iso27001": "iso27001", "isoiec27001": "iso27001",
        "cis": "cis", "ciscsc": "cis", "cscontrols": "cis", "cis8": "cis",
    }
    resolved = aliases.get(key)
    if resolved is None:
        raise ValueError(
            f"Unknown standard {name!r}. Expected one of: "
            f"{', '.join(sorted(STANDARDS))} or 'all'."
        )
    return STANDARDS[resolved]


def checks_for_standard(standard):
    """
    Which checks belong to a standard.

    Derived from COMPLIANCE_MAPPING rather than maintained as a second list.
    A hand-kept list per standard is a second source of truth and drifts from
    the mapping the moment a check is renamed.
    """
    if standard is None:
        return set(COMPLIANCE_MAPPING)
    field = standard["key"]
    return {
        name for name, mapping in COMPLIANCE_MAPPING.items()
        if mapping.get(field)
    }


def controls_for_check(check_name, standard):
    """The control identifiers a single check maps to, for one standard."""
    mapping = COMPLIANCE_MAPPING.get(check_name, {}).get(standard["key"], {})
    if not mapping:
        return []
    if "control" in mapping:
        return [mapping["control"]]
    return list(mapping.get("controls", []))


def scope_results_to_standard(audit_results, standard):
    """
    Return a copy of the results containing only checks in scope for one
    standard, with the summary recomputed over that subset.

    A SOC 2 report that silently scores NIST controls is not a SOC 2 report.
    The score must describe the control set named on the cover.
    """
    import copy

    if standard is None:
        return audit_results

    in_scope = checks_for_standard(standard)
    scoped = copy.deepcopy(audit_results)
    passed = failed = unknown = not_applicable = 0

    def prune(bucket):
        nonlocal passed, failed, unknown, not_applicable
        details = bucket.get("details", {})
        kept = {k: v for k, v in details.items() if k in in_scope}
        bucket["details"] = kept
        counts = {"pass": 0, "fail": 0, "unknown": 0, "not_applicable": 0}
        for result in kept.values():
            status = result.get(
                "status", "pass" if result.get("passed") else "fail"
            )
            counts[status] = counts.get(status, 0) + 1
        bucket["total"] = len(kept)
        bucket["passed"] = counts["pass"]
        bucket["failed"] = counts["fail"]
        bucket["unknown"] = counts["unknown"]
        bucket["not_applicable"] = counts["not_applicable"]
        passed += counts["pass"]
        failed += counts["fail"]
        unknown += counts["unknown"]
        not_applicable += counts["not_applicable"]

    checks = scoped.get("checks", {})
    if "organization" in checks:
        prune(checks["organization"])
    for repo_checks in checks.get("repositories", {}).values():
        prune(repo_checks)

    evaluated = passed + failed
    total = evaluated + unknown + not_applicable
    score = round(passed / evaluated * 100, 2) if evaluated else 0.0
    coverage = round(evaluated / total * 100, 2) if total else 0.0

    scoped["summary"] = {
        "total_checks": total,
        "evaluated_checks": evaluated,
        "passed_checks": passed,
        "failed_checks": failed,
        "unknown_checks": unknown,
        "not_applicable_checks": not_applicable,
        "compliance_score": score,
        "coverage_percent": coverage,
        "low_coverage": coverage < 60.0,
        "risk_level": _risk_level(score) if evaluated else "UNSCORED",
    }
    scoped["standard"] = standard
    return scoped


def _risk_level(score: float) -> str:
    if score >= 90:
        return "LOW RISK"
    if score >= 70:
        return "MEDIUM RISK"
    if score >= 50:
        return "HIGH RISK"
    return "CRITICAL RISK"


# ---------------------------------------------------------------------------
# Control guidance
# ---------------------------------------------------------------------------
#
# What each control verifies, and what to do when it fails. Kept beside the
# framework mapping so a report can state the requirement, the finding and the
# remediation in one row — which is the form an auditor and an engineer can
# both act on.

CONTROL_GUIDANCE = {
    '2FA Enforcement': {
        "verifies": 'Whether the organization requires two-factor authentication for membership.',
        "remediation": "Enable 'Require two-factor authentication' under Organization settings > Authentication security. Existing members without 2FA are removed, so notify them first.",
    },
    'SSO Configuration': {
        "verifies": 'Whether SAML single sign-on governs access. Not exposed by the REST API.',
        "remediation": 'Verify manually under Organization settings > Authentication security. Requires GitHub Enterprise Cloud.',
    },
    'Default Repository Permission': {
        "verifies": 'The base permission every organization member holds on every repository.',
        "remediation": "Set the base permission to 'Read' or 'None' and grant write access through teams on the repositories that need it.",
    },
    'Member Repository Creation': {
        "verifies": 'Whether any member can create repositories outside the audited perimeter.',
        "remediation": 'Restrict repository creation to owners under Organization settings > Member privileges.',
    },
    'Audit Logging': {
        "verifies": 'Whether the organization audit log is accessible for review.',
        "remediation": 'Requires GitHub Enterprise Cloud. Export the audit log on a schedule and retain it in line with your retention policy.',
    },
    'Repository Visibility': {
        "verifies": "Whether the repository's visibility matches the sensitivity its name implies.",
        "remediation": 'Make the repository private, or rename it if the name overstates the sensitivity of its contents.',
    },
    'Branch Protection Rules': {
        "verifies": 'Whether the default branch is governed by branch protection or a ruleset.',
        "remediation": 'Create a ruleset targeting the default branch under Settings > Rules, and set Enforcement status to Active.',
    },
    'Pull Request Reviews': {
        "verifies": 'Whether changes require review before merging.',
        "remediation": "Enable 'Require a pull request before merging' with at least one required approval.",
    },
    'Status Checks Before Merge': {
        "verifies": 'Whether automated checks must pass before a merge.',
        "remediation": "Enable 'Require status checks to pass' and select the checks that must succeed.",
    },
    'Commit Signing': {
        "verifies": 'Whether commits must carry a verified signature.',
        "remediation": "Enable 'Require signed commits' and have contributors configure GPG, SSH or S/MIME signing.",
    },
    'Dismiss Stale PR Reviews': {
        "verifies": 'Whether an approval survives new commits pushed after it.',
        "remediation": "Enable 'Dismiss stale pull request approvals when new commits are pushed'.",
    },
    'Code Owner Reviews': {
        "verifies": 'Whether a designated owner must review changes to the code they own.',
        "remediation": "Add a CODEOWNERS file and enable 'Require review from Code Owners'.",
    },
    'Admin Bypass Prevention': {
        "verifies": 'Whether administrators are bound by the same rules as everyone else.',
        "remediation": "Remove roles from the ruleset bypass list, or enable 'Do not allow bypassing the above settings' on classic protection.",
    },
    'Linear History Required': {
        "verifies": 'Whether merge commits are permitted on the protected branch.',
        "remediation": "Enable 'Require linear history' and use squash or rebase merges.",
    },
    'Force Push Protection': {
        "verifies": 'Whether history can be rewritten on the protected branch.',
        "remediation": "Enable 'Block force pushes'.",
    },
    'Branch Deletion Protection': {
        "verifies": 'Whether the protected branch can be deleted.',
        "remediation": "Enable 'Restrict deletions'.",
    },
    'Secrets Scanning': {
        "verifies": 'Whether committed credentials are detected automatically.',
        "remediation": 'Enable Secret scanning under Settings > Advanced Security. Private repositories require GitHub Secret Protection.',
    },
    'Push Protection': {
        "verifies": 'Whether a push containing a detected secret is blocked before it lands.',
        "remediation": 'Enable Push protection alongside secret scanning. Detection after the fact still requires the credential to be rotated.',
    },
    'Dependency Scanning': {
        "verifies": 'Whether known-vulnerable dependencies raise alerts.',
        "remediation": 'Enable Dependabot alerts under Settings > Advanced Security, and Dependabot security updates to receive fixes automatically.',
    },
    'SECURITY.md File': {
        "verifies": 'Whether a documented vulnerability reporting path exists.',
        "remediation": 'Add SECURITY.md at the repository root or in .github/, naming a contact and a response expectation.',
    },
    'CODEOWNERS File': {
        "verifies": 'Whether review responsibility is assigned to named owners.',
        "remediation": 'Add a CODEOWNERS file mapping paths to the teams or individuals accountable for them.',
    },
    '.gitignore Configuration': {
        "verifies": 'Whether common credential file patterns are excluded from commits.',
        "remediation": 'Add patterns such as .env, *.pem, *.key and credentials to .gitignore. This prevents accidents, not deliberate commits.',
    },
    'Repository Activity': {
        "verifies": 'Whether the repository is still maintained, since access grants persist regardless.',
        "remediation": 'Archive the repository if it is retired. Archiving makes it read-only while preserving history and removes it from active scope.',
    },
    'Actions Allowed Actions Policy': {
        "verifies": 'Which third-party actions may run across the organization.',
        "remediation": "Set the policy to 'Allow select actions' and maintain an allowlist, or restrict to actions owned by the organization.",
    },
    'Actions Default Token Permissions': {
        "verifies": 'The default scope of GITHUB_TOKEN for every workflow in the organization.',
        "remediation": 'Set the default workflow permissions to read-only and grant additional scopes per workflow in YAML.',
    },
    'Actions Pull Request Approval': {
        "verifies": 'Whether a workflow can approve a pull request, defeating required review.',
        "remediation": "Disable 'Allow GitHub Actions to create and approve pull requests'.",
    },
    'Workflow Token Permissions': {
        "verifies": "The default scope of GITHUB_TOKEN for this repository's workflows.",
        "remediation": 'Set the repository default to read-only and declare additional scopes per workflow.',
    },
    'Action Version Pinning': {
        "verifies": 'Whether third-party actions are referenced by an immutable commit SHA.',
        "remediation": 'Replace tag references with the full 40-character commit SHA. A tag can be repointed by whoever controls the action repository.',
    },
    'Workflow Permissions Declared': {
        "verifies": 'Whether each workflow states the token scopes it needs.',
        "remediation": 'Add a top-level permissions: block to every workflow, granting only the scopes that workflow uses.',
    },
    'Untrusted Workflow Triggers': {
        "verifies": 'Whether untrusted pull request code runs with access to repository secrets.',
        "remediation": 'Avoid checking out the pull request ref under pull_request_target. Split into an untrusted build and a separate privileged step.',
    },
    'Self-Hosted Runner Exposure': {
        "verifies": "Whether a fork's pull request can execute code on your own infrastructure.",
        "remediation": 'Use GitHub-hosted runners for public repositories, or ephemeral self-hosted runners destroyed after each job.',
    },
    'Build Provenance Attestation': {
        "verifies": 'Whether published artifacts can be traced back to this repository and workflow.',
        "remediation": 'Add actions/attest-build-provenance to publishing workflows and grant id-token: write and attestations: write.',
    },
    'Repository Actions Policy': {
        "verifies": 'Which actions may run in this repository.',
        "remediation": 'Restrict to selected actions or to actions owned by this account under Settings > Actions > General.',
    },
    'Action SHA Pinning Policy': {
        "verifies": 'Whether the platform itself refuses to run an unpinned action.',
        "remediation": "Enable 'Require actions to be pinned to a full-length commit SHA'. This enforces pinning rather than relying on review to catch it.",
    },
    'Fork Pull Request Workflows': {
        "verifies": 'Whether workflows run for fork pull requests, and who must approve first.',
        "remediation": 'On private repositories, disable fork pull request workflows. On public ones, require approval for all external contributors.',
    },
    'Ruleset Enforcement Status': {
        "verifies": 'Whether the rulesets that exist are actually being enforced.',
        "remediation": 'Set Enforcement status to Active on every ruleset. The creation form defaults to Disabled, so a ruleset can look configured and enforce nothing.',
    },
    'Organization Owner Count': {
        "verifies": 'How many accounts hold standing privilege over the entire organization.',
        "remediation": 'Keep two to five owners: more than one for continuity, few enough to justify individually. Downgrade the rest to Member.',
    },
    'Direct Collaborator Grants': {
        "verifies": 'Whether access is granted through teams, or directly to individuals.',
        "remediation": 'Move direct grants into teams. A direct grant appears in no team roster and survives a team-based access review.',
    },
    'Outside Collaborator Access': {
        "verifies": 'Which external parties hold standing access, and at what level.',
        "remediation": 'Confirm each outside collaborator is still engaged, reduce to the lowest level that works, and record a review date.',
    },
    'Repository Admin Concentration': {
        "verifies": 'How many principals can change settings, rotate secrets and delete the repository.',
        "remediation": 'Downgrade admins who do not administer the repository to Maintain, which permits everything except settings and deletion.',
    },
}


def guidance_for(check_name):
    return CONTROL_GUIDANCE.get(check_name, {"verifies": "", "remediation": ""})
