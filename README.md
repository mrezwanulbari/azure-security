# Azure Security — Cloud Security Frameworks & Sentinel SIEM

![Azure](https://img.shields.io/badge/Azure-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Sentinel-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> Enterprise Azure security architectures, Microsoft Sentinel analytics rules, Defender configurations, Azure Policy definitions, KQL detection queries, and compliance automation aligned with NIST 800-53, CIS Benchmarks, and the Microsoft Cloud Security Benchmark (MCSB).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Repository Structure](#repository-structure)
- [Microsoft Sentinel](#microsoft-sentinel)
- [Microsoft Defender for Cloud](#microsoft-defender-for-cloud)
- [Azure Policy & Governance](#azure-policy--governance)
- [Identity Security (Entra ID)](#identity-security-entra-id)
- [Network Security](#network-security)
- [KQL Detection Queries](#kql-detection-queries)
- [Sigma Detection Rules](#sigma-detection-rules)
- [Compliance Automation](#compliance-automation)
- [Incident Response](#incident-response)
- [Contributing](#contributing)

---

## Overview

This repository provides a comprehensive Azure security framework covering identity protection, threat detection with Microsoft Sentinel, cloud workload protection with Defender, governance with Azure Policy, and compliance automation for enterprise and government cloud environments.

### Security Domains

| Domain | Azure Services | Focus Area |
|---|---|---|
| **Identity & Access** | Entra ID, PIM, Conditional Access | Zero Trust identity, MFA, privileged access |
| **Threat Detection** | Microsoft Sentinel, Defender XDR | SIEM/SOAR, analytics rules, automation |
| **Workload Protection** | Defender for Cloud, Servers, Storage | CSPM, CWP, vulnerability management |
| **Governance** | Azure Policy, Blueprints, Management Groups | Compliance, guardrails, resource governance |
| **Network Security** | NSGs, Azure Firewall, WAF, DDoS Protection | Segmentation, filtering, DDoS mitigation |
| **Data Protection** | Key Vault, Information Protection, Purview | Encryption, classification, DLP |
| **Monitoring** | Monitor, Log Analytics, Workbooks | Centralized logging, alerting, visualization |

---

## Architecture

### Azure Security Reference Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Azure Management Groups                       │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │               Root Management Group                        │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐   │  │
│  │  │ Azure Policy│  │  RBAC      │  │ Microsoft Defender │   │  │
│  │  │ (Org-wide) │  │ (Inherited)│  │ for Cloud (Org)    │   │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────┐  ┌────────────────────────────────┐  │
│  │  Security Subscription │  │   Logging Subscription         │  │
│  │  ┌──────────────────┐  │  │  ┌────────────────────────┐   │  │
│  │  │ Microsoft Sentinel│  │  │  │ Log Analytics Workspace│   │  │
│  │  │ (Unified SIEM)   │  │  │  │ (Central)              │   │  │
│  │  │                  │  │  │  │                        │   │  │
│  │  │ • Analytics Rules│  │  │  │ • Activity Logs        │   │  │
│  │  │ • Playbooks      │  │  │  │ • Diagnostic Logs      │   │  │
│  │  │ • Workbooks      │  │  │  │ • Security Events      │   │  │
│  │  │ • Hunting Queries│  │  │  │ • NSG Flow Logs        │   │  │
│  │  │ • Data Connectors│  │  │  │ • Entra ID Logs        │   │  │
│  │  └──────────────────┘  │  │  └────────────────────────┘   │  │
│  └───────────────────────┘  └────────────────────────────────┘  │
│                                                                  │
│  ┌───────────────────────┐  ┌────────────────────────────────┐  │
│  │  Production Sub       │  │   Development Sub              │  │
│  │  ┌──────┐ ┌────────┐  │  │  ┌──────┐ ┌────────┐          │  │
│  │  │ VNets│ │Defender │  │  │  │ VNets│ │ Key    │          │  │
│  │  │ VMs  │ │for Cloud│  │  │  │ AKS  │ │ Vault  │          │  │
│  │  │ AKS  │ │ (CSPM)  │  │  │  │ SQL  │ │        │          │  │
│  │  │ SQL  │ │         │  │  │  │      │ │        │          │  │
│  │  └──────┘ └────────┘  │  │  └──────┘ └────────┘          │  │
│  └───────────────────────┘  └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
azure-security/
├── README.md
├── sentinel/
│   ├── analytics-rules/
│   │   ├── identity/
│   │   │   ├── brute-force-entra-id.yaml
│   │   │   ├── mfa-bypass-detection.yaml
│   │   │   ├── suspicious-service-principal.yaml
│   │   │   └── privileged-role-assignment.yaml
│   │   ├── cloud-infrastructure/
│   │   │   ├── nsg-rule-modification.yaml
│   │   │   ├── key-vault-access-anomaly.yaml
│   │   │   ├── storage-account-public-access.yaml
│   │   │   └── vm-extension-installed.yaml
│   │   └── threat-intelligence/
│   │       ├── ti-map-ip-to-signin.yaml
│   │       └── ti-map-domain-to-dns.yaml
│   ├── hunting-queries/
│   │   ├── identity-hunting.kql
│   │   ├── network-hunting.kql
│   │   ├── persistence-hunting.kql
│   │   └── lateral-movement-hunting.kql
│   ├── playbooks/
│   │   ├── isolate-compromised-vm/
│   │   │   └── azuredeploy.json
│   │   ├── block-ip-on-firewall/
│   │   │   └── azuredeploy.json
│   │   └── disable-compromised-user/
│   │       └── azuredeploy.json
│   ├── workbooks/
│   │   ├── security-operations-overview.json
│   │   └── identity-security-posture.json
│   └── data-connectors/
│       └── connector-setup-guide.md
├── defender/
│   ├── configurations/
│   │   ├── defender-for-servers.md
│   │   ├── defender-for-storage.md
│   │   ├── defender-for-sql.md
│   │   └── defender-for-containers.md
│   ├── security-recommendations/
│   │   └── high-priority-recommendations.md
│   └── docs/
│       └── cspm-implementation.md
├── policies/
│   ├── custom-policies/
│   │   ├── deny-public-ip.json
│   │   ├── require-nsg-on-subnet.json
│   │   ├── enforce-tls-minimum.json
│   │   ├── require-key-vault-soft-delete.json
│   │   └── deny-unmanaged-disk.json
│   ├── initiatives/
│   │   ├── security-baseline-initiative.json
│   │   └── logging-initiative.json
│   └── docs/
│       └── policy-governance-guide.md
├── identity/
│   ├── conditional-access/
│   │   ├── require-mfa-all-users.json
│   │   ├── block-legacy-auth.json
│   │   ├── require-compliant-device.json
│   │   └── named-locations.json
│   ├── pim/
│   │   └── pim-role-settings.md
│   └── docs/
│       └── zero-trust-identity-guide.md
├── network/
│   ├── nsg-rules/
│   │   ├── baseline-nsg-rules.json
│   │   └── application-nsg-rules.json
│   ├── azure-firewall/
│   │   └── firewall-policy-rules.json
│   └── docs/
│       └── network-segmentation-guide.md
├── sigma-rules/
│   ├── azure-ad/
│   │   ├── azure-ad-mfa-disabled.yml
│   │   ├── azure-ad-suspicious-signin.yml
│   │   ├── azure-ad-app-registration.yml
│   │   └── azure-ad-pim-activation.yml
│   ├── azure-activity/
│   │   ├── azure-nsg-deleted.yml
│   │   ├── azure-keyvault-secret-read.yml
│   │   └── azure-resource-group-deleted.yml
│   └── office365/
│       ├── o365-mailbox-forwarding.yml
│       └── o365-admin-role-assigned.yml
├── compliance/
│   ├── cis-benchmark/
│   │   └── cis-azure-checks.md
│   ├── nist-800-53/
│   │   └── nist-control-mapping.md
│   └── mcsb/
│       └── mcsb-assessment-guide.md
├── incident-response/
│   ├── playbooks/
│   │   ├── compromised-entra-id-account.md
│   │   ├── compromised-vm.md
│   │   ├── data-exfiltration-storage.md
│   │   └── ransomware-response.md
│   └── kql/
│       ├── investigation-queries.kql
│       └── forensic-timeline.kql
└── docs/
    ├── security-architecture.md
    ├── logging-strategy.md
    ├── sentinel-deployment-guide.md
    └── zero-trust-framework.md
```

---

## Microsoft Sentinel

### Analytics Rules

#### Brute Force Against Entra ID

```yaml
# sentinel/analytics-rules/identity/brute-force-entra-id.yaml
name: Brute Force Attack Against Entra ID
description: |
  Detects multiple failed sign-in attempts from a single IP address
  followed by a successful sign-in, indicating a potential brute
  force attack against Azure Active Directory.
severity: High
queryFrequency: PT5M
queryPeriod: PT1H
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
  - CredentialAccess
  - InitialAccess
relevantTechniques:
  - T1110
  - T1078
query: |
  let failureThreshold = 10;
  let timeWindow = 1h;
  SigninLogs
  | where TimeGenerated >= ago(timeWindow)
  | where ResultType != "0"  // Failed logins
  | summarize
      FailureCount = count(),
      FailedAccounts = make_set(UserPrincipalName),
      FirstFailure = min(TimeGenerated),
      LastFailure = max(TimeGenerated)
    by IPAddress, Location = tostring(LocationDetails.city)
  | where FailureCount >= failureThreshold
  | join kind=inner (
      SigninLogs
      | where TimeGenerated >= ago(timeWindow)
      | where ResultType == "0"  // Successful login
      | project
          SuccessTime = TimeGenerated,
          IPAddress,
          SuccessAccount = UserPrincipalName,
          AppDisplayName,
          DeviceDetail
    ) on IPAddress
  | where SuccessTime > LastFailure
  | project
      IPAddress,
      Location,
      FailureCount,
      FailedAccounts,
      SuccessAccount,
      AppDisplayName,
      FirstFailure,
      LastFailure,
      SuccessTime,
      TimeToSuccess = datetime_diff('minute', SuccessTime, LastFailure)
entityMappings:
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: SuccessAccount
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IPAddress
```

#### Suspicious Service Principal Activity

```yaml
# sentinel/analytics-rules/identity/suspicious-service-principal.yaml
name: Suspicious Service Principal Credential Addition
description: |
  Detects when new credentials (password or certificate) are added
  to a service principal, which could indicate an attacker establishing
  persistence via application-level access.
severity: Medium
queryFrequency: PT1H
queryPeriod: PT1H
triggerOperator: GreaterThan
triggerThreshold: 0
tactics:
  - Persistence
  - PrivilegeEscalation
relevantTechniques:
  - T1098.001
query: |
  AuditLogs
  | where OperationName has_any (
      "Add service principal credentials",
      "Update application – Certificates and secrets management"
    )
  | where Result == "success"
  | extend
      Actor = tostring(InitiatedBy.user.userPrincipalName),
      ActorIP = tostring(InitiatedBy.user.ipAddress),
      TargetApp = tostring(TargetResources[0].displayName),
      TargetAppId = tostring(TargetResources[0].id)
  | project
      TimeGenerated,
      Actor,
      ActorIP,
      OperationName,
      TargetApp,
      TargetAppId,
      Result
```

---

## KQL Detection Queries

### Identity Hunting Queries

```kql
// === Detect Impossible Travel ===
// Identifies sign-ins from geographically distant locations
// within a short time frame
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress,
    Latitude = tostring(LocationDetails.geoCoordinates.latitude),
    Longitude = tostring(LocationDetails.geoCoordinates.longitude),
    City = tostring(LocationDetails.city),
    Country = tostring(LocationDetails.countryOrRegion)
| sort by UserPrincipalName, TimeGenerated asc
| extend
    PrevTime = prev(TimeGenerated, 1),
    PrevLat = todouble(prev(Latitude, 1)),
    PrevLon = todouble(prev(Longitude, 1)),
    PrevCity = prev(City, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend
    TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime),
    Distance = geo_distance_2points(
        todouble(Longitude), todouble(Latitude),
        PrevLon, PrevLat
    ) / 1000  // Convert to km
| where TimeDiffMinutes < 120 and Distance > 500
| project
    UserPrincipalName,
    PreviousLocation = strcat(PrevCity, " (", PrevLat, ",", PrevLon, ")"),
    CurrentLocation = strcat(City, " (", Latitude, ",", Longitude, ")"),
    DistanceKm = round(Distance, 0),
    TimeDiffMinutes,
    SpeedKmH = round(Distance / (TimeDiffMinutes / 60.0), 0)

// === Detect OAuth Application Consent Grants ===
// Identifies when users grant consent to OAuth applications,
// which could be an OAuth phishing attack
AuditLogs
| where TimeGenerated >= ago(7d)
| where OperationName == "Consent to application"
| extend
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    AppName = tostring(TargetResources[0].displayName),
    AppId = tostring(TargetResources[0].id),
    Permissions = tostring(TargetResources[0].modifiedProperties)
| project
    TimeGenerated,
    Actor,
    AppName,
    AppId,
    Permissions,
    Result

// === Detect Privileged Role Assignments ===
// Tracks Global Admin, Security Admin, and other high-privilege role
// assignments in Entra ID
AuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName has "Add member to role"
| extend
    Actor = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleName = tostring(parse_json(
        tostring(TargetResources[0].modifiedProperties)
    )[1].newValue)
| where RoleName has_any (
    "Global Administrator",
    "Security Administrator",
    "Privileged Role Administrator",
    "Exchange Administrator",
    "SharePoint Administrator"
  )
| project TimeGenerated, Actor, TargetUser, RoleName, Result
```

### Network Hunting Queries

```kql
// === Detect Data Exfiltration via Storage ===
// Identifies unusually high data downloads from Azure Storage
StorageBlobLogs
| where TimeGenerated >= ago(24h)
| where OperationName == "GetBlob"
| where StatusCode == 200
| summarize
    TotalBytesRead = sum(ResponseBodySize),
    BlobCount = count(),
    DistinctContainers = dcount(ObjectKey)
  by CallerIpAddress, AccountName, bin(TimeGenerated, 1h)
| where TotalBytesRead > 1073741824  // > 1 GB
| extend TotalGB = round(TotalBytesRead / 1073741824.0, 2)
| sort by TotalBytesRead desc

// === Detect NSG Rule Changes ===
// Monitors for network security group modifications
AzureActivity
| where TimeGenerated >= ago(24h)
| where OperationNameValue has_any (
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE"
  )
| where ActivityStatusValue == "Success"
| extend
    Actor = Caller,
    NSGName = tostring(parse_json(Properties).resource),
    RuleName = tostring(parse_json(Properties).entity)
| project TimeGenerated, Actor, OperationNameValue, NSGName,
    RuleName, CallerIpAddress, SubscriptionId
```

---

## Sigma Detection Rules

### Azure AD MFA Disabled

```yaml
title: Azure AD MFA Registration or Requirement Disabled
id: e1f2a3b4-c5d6-7890-ef12-345678901234
status: stable
level: high
description: |
    Detects when MFA registration is disabled for a user or when
    Conditional Access policies requiring MFA are modified or disabled.
    This is a critical security control change that may indicate
    an attacker weakening authentication requirements.
author: Shakil Md. Rezwanul Bari
date: 2024/01/15
references:
    - https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates
    - https://attack.mitre.org/techniques/T1556/006/
logsource:
    product: azure
    service: auditlogs
detection:
    selection_mfa_disabled:
        OperationName:
            - 'Disable Strong Authentication'
            - 'Delete strong authentication phone app detail'
            - 'User disabled security info'
    selection_ca_modified:
        OperationName:
            - 'Update conditional access policy'
            - 'Delete conditional access policy'
    condition: selection_mfa_disabled or selection_ca_modified
falsepositives:
    - Authorized administrative changes during MFA migration
    - Help desk MFA reset for locked-out users
tags:
    - attack.persistence
    - attack.defense_evasion
    - attack.t1556.006
```

### Azure AD Suspicious Sign-in

```yaml
title: Azure AD Sign-in from Anonymous or Tor Network
id: f2a3b4c5-d6e7-8901-f234-567890123456
status: stable
level: high
description: |
    Detects sign-in attempts from anonymous proxy networks (Tor, VPN)
    which may indicate credential abuse or unauthorized access attempts.
author: Shakil Md. Rezwanul Bari
date: 2024/01/15
logsource:
    product: azure
    service: signinlogs
detection:
    selection:
        RiskDetail|contains:
            - 'anonymizedIPAddress'
            - 'maliciousIPAddress'
    selection_risk_level:
        RiskLevelDuringSignIn:
            - high
            - medium
    condition: selection or selection_risk_level
falsepositives:
    - Users legitimately using VPN for privacy
    - Researchers or security team testing from Tor
tags:
    - attack.initial_access
    - attack.t1078
    - attack.t1090.003
```

---

## Azure Policy

### Custom Policy: Deny Public IP Addresses

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Network/publicIPAddresses"
        },
        {
          "not": {
            "field": "tags['exception']",
            "equals": "approved-public-ip"
          }
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  },
  "parameters": {},
  "displayName": "Deny Public IP Address Creation",
  "description": "Prevents creation of public IP addresses unless explicitly tagged as approved. This enforces private-only network architectures."
}
```

### Custom Policy: Enforce TLS 1.2 Minimum

```json
{
  "mode": "All",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "in": [
            "Microsoft.Web/sites",
            "Microsoft.Storage/storageAccounts",
            "Microsoft.Sql/servers"
          ]
        },
        {
          "field": "Microsoft.Web/sites/siteConfig.minTlsVersion",
          "notEquals": "1.2"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  },
  "displayName": "Enforce TLS 1.2 Minimum Version",
  "description": "Ensures all web apps, storage accounts, and SQL servers use TLS 1.2 or higher."
}
```

---

## Incident Response

### Compromised Entra ID Account Playbook

```
┌───────────────────────────────────────────────┐
│        PHASE 1: DETECTION & TRIAGE            │
│  1. Alert from Sentinel/Identity Protection   │
│  2. Review sign-in logs for anomalous access  │
│  3. Identify affected account scope           │
│  4. Assess data access and privilege level     │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────▼───────────────────────────┐
│        PHASE 2: CONTAINMENT                   │
│  1. Reset user password immediately           │
│  2. Revoke all refresh tokens                 │
│  3. Disable account if necessary              │
│  4. Block source IP in Conditional Access     │
│  5. Remove OAuth app consents (if phished)    │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────▼───────────────────────────┐
│        PHASE 3: INVESTIGATION                 │
│  1. Query Entra ID audit logs (90 days)       │
│  2. Review mailbox rules (forwarding, etc.)   │
│  3. Check for new app registrations           │
│  4. Review file access in SharePoint/OneDrive │
│  5. Check for lateral movement (new sessions) │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────▼───────────────────────────┐
│        PHASE 4: REMEDIATION                   │
│  1. Re-enable account with fresh credentials  │
│  2. Re-register MFA devices                   │
│  3. Remove malicious inbox rules              │
│  4. Revoke unauthorized app consents          │
│  5. Update Conditional Access policies        │
└───────────────────┬───────────────────────────┘
                    │
┌───────────────────▼───────────────────────────┐
│        PHASE 5: LESSONS LEARNED               │
│  1. Document timeline and root cause          │
│  2. Update Sentinel analytics rules           │
│  3. Review and strengthen CA policies         │
│  4. Conduct user security awareness training  │
└───────────────────────────────────────────────┘
```

### Investigation KQL Queries

```kql
// === Full Account Activity Timeline ===
// Use when investigating a compromised account
let compromisedUser = "user@company.com";
let investigationWindow = 7d;
union
  (SigninLogs
  | where TimeGenerated >= ago(investigationWindow)
  | where UserPrincipalName == compromisedUser
  | project TimeGenerated, Activity="SignIn",
      Detail=strcat(AppDisplayName, " - ", ResultDescription),
      IPAddress, Location=tostring(LocationDetails.city)),
  (AuditLogs
  | where TimeGenerated >= ago(investigationWindow)
  | where InitiatedBy.user.userPrincipalName == compromisedUser
  | project TimeGenerated, Activity=OperationName,
      Detail=tostring(TargetResources[0].displayName),
      IPAddress=tostring(InitiatedBy.user.ipAddress),
      Location=""),
  (OfficeActivity
  | where TimeGenerated >= ago(investigationWindow)
  | where UserId == compromisedUser
  | project TimeGenerated, Activity=Operation,
      Detail=OfficeObjectId, IPAddress=ClientIP, Location="")
| sort by TimeGenerated desc
```

---

## Compliance

### CIS Azure Foundations Benchmark — Key Controls

| CIS Control | Description | Azure Service | Status Check |
|---|---|---|---|
| 1.1.1 | Ensure MFA is enabled for all privileged users | Entra ID | Conditional Access Policy |
| 1.1.2 | Ensure MFA is enabled for all users | Entra ID + Security Defaults | CA Policy or Security Defaults |
| 1.2.1 | Ensure Conditional Access policies don't allow legacy auth | Entra ID CA | Block legacy authentication |
| 2.1.1 | Ensure Defender for Cloud is set to On for Servers | Defender for Cloud | Pricing tier = Standard |
| 3.1 | Ensure Storage Account access is restricted | Storage Accounts | Disable public blob access |
| 4.1.1 | Ensure auditing is set to On for SQL Servers | Azure SQL | Server-level auditing enabled |
| 5.1.1 | Ensure diagnostic logs are enabled for all services | Azure Monitor | Diagnostic settings configured |
| 6.1 | Ensure NSG Flow Logs are enabled | Network Watcher | Flow logs to Log Analytics |
| 7.1 | Ensure VMs use managed disks | Compute | No unmanaged disks |
| 9.1 | Ensure App Service uses HTTPS | App Service | HTTPS Only = On |

---

## Contributing

Contributions are welcome! Please submit pull requests for any improvements.

## License

This project is licensed under the MIT License.

---

> **Maintained by [Shakil Md. Rezwanul Bari](https://github.com/mrezwanulbari)** — Cybersecurity & Cloud Security Engineer focused on enterprise security operations and critical infrastructure protection.
