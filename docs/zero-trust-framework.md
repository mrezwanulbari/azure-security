# Azure Zero Trust Security Framework

## Core Principles

Zero Trust is built on three fundamental principles:

1. **Verify Explicitly** — Always authenticate and authorize based on all available data points
2. **Use Least Privilege Access** — Limit user access with Just-In-Time (JIT) and Just-Enough-Access (JEA)
3. **Assume Breach** — Minimize blast radius, segment access, verify end-to-end encryption

## Zero Trust Architecture in Azure

### Identity Pillar
| Control | Azure Service | Implementation |
|---|---|---|
| MFA for all users | Entra ID + Conditional Access | CA policy: Require MFA for all cloud apps |
| Risk-based authentication | Entra ID Protection | Sign-in risk and user risk policies |
| Privileged access management | PIM | Time-limited role activation with approval |
| Session management | Conditional Access | Sign-in frequency and persistent browser controls |

### Network Pillar
| Control | Azure Service | Implementation |
|---|---|---|
| Micro-segmentation | NSGs + ASGs | Application-level security groups |
| Network filtering | Azure Firewall | L3-L7 filtering with threat intelligence |
| DDoS protection | DDoS Protection | Standard tier for all public endpoints |
| Private connectivity | Private Link | Private endpoints for all PaaS services |

### Data Pillar
| Control | Azure Service | Implementation |
|---|---|---|
| Encryption at rest | Key Vault + CMK | Customer-managed keys for sensitive data |
| Encryption in transit | TLS 1.2+ | Enforce minimum TLS version |
| Data classification | Purview | Automated data discovery and classification |
| Data loss prevention | Information Protection | Sensitivity labels and DLP policies |

## Implementation Roadmap

### Phase 1: Foundation (Months 1-2)
- Enable Security Defaults or Conditional Access
- Deploy Defender for Cloud (Free tier)
- Enable diagnostic logging to Log Analytics
- Implement NSGs on all subnets

### Phase 2: Identity (Months 3-4)
- Deploy Conditional Access policies (MFA, device compliance)
- Enable PIM for privileged roles
- Configure Entra ID Protection risk policies
- Block legacy authentication

### Phase 3: Detection (Months 5-6)
- Deploy Microsoft Sentinel
- Configure data connectors
- Implement analytics rules and hunting queries
- Build SOC workbooks and dashboards

### Phase 4: Advanced (Months 7-12)
- Implement Private Link for PaaS services
- Deploy Azure Firewall with threat intelligence
- Enable Defender for Cloud (Standard tier)
- Continuous improvement and threat hunting
