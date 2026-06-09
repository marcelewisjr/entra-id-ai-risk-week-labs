# Microsoft Entra ID – AI Risk Week Lab Portfolio

**Source:** Microsoft AI Skills Fest – AI Risk Week Playlist (2026)  
**Environment:** Microsoft Entra admin center (live tenant labs)  
**Frameworks Referenced:** NIST SP 800-53, Microsoft Zero Trust, NIST CSF  
**Certification Alignment:** SC-300 (Microsoft Identity and Access Administrator)

---

## Overview

This repository documents hands-on lab work completed as part of the Microsoft AI Skills Fest AI Risk Week playlist. Each lab covers a distinct area of Microsoft Entra ID identity and access management — from foundational security defaults to AI agent governance. All configurations were performed in a live Entra tenant environment.

These labs map directly to real-world IAM and identity security operations, and align with SC-300 exam objectives across identity protection, Conditional Access, and identity governance domains.

---

## Labs Completed

| # | Lab | Key Concepts |
|---|-----|-------------|
| 1 | User Risk Policy | Identity Protection, risk thresholds, password remediation |
| 2 | Sign-In Risk Policy | Risk-based CA, MFA enforcement |
| 3 | MFA Registration Policy | Pre-enrollment, SSPR alignment |
| 4 | Microsoft Graph + Identity Protection API | App registration, OAuth, PowerShell |
| 5 | Security Defaults | Baseline security, CA prerequisites |
| 6 | Conditional Access – Deep Dive | Policy scenarios, trusted locations, device compliance, TOU |
| 7 | Conditional Access – Hands-On Policy + Testing | Policy creation, validation, report-only mode |
| 8 | Approved Client App Policies (MAM/CA) | Mobile app management, BYOD, Intune APP |
| 9 | Authentication Session Controls | Sign-in frequency, session management |
| 10 | AI Agent Identity Management | Entra Agent ID, agent governance, audit logs |

---

## Lab 1 – User Risk Policy

**Location:** Entra admin center → Identity → Protection → Identity Protection → User Risk Policy

User risk reflects the probability that a given identity has been compromised, based on signals like leaked credentials, anomalous behavior, or threat intelligence feeds.

**Configuration:**
| Setting | Value |
|---|---|
| Scope | All users |
| Risk threshold | High |
| Enforcement control | Require password change |
| Policy state | On |

**Why this matters:** Setting the threshold to High ensures only high-confidence compromise signals trigger remediation, reducing friction for legitimate users while automatically enforcing credential rotation on flagged accounts. Paired with SSPR, users self-remediate without a helpdesk ticket.

**NIST 800-53 Mappings:**
- `IA-5` – Authenticator Management (forced credential rotation on compromise signal)
- `AC-7` – Unsuccessful Logon Attempts (risk-based access enforcement)
- `SI-4` – System Monitoring (automated threat signal processing)

---

## Lab 2 – Sign-In Risk Policy

**Location:** Entra admin center → Identity → Protection → Identity Protection → Sign-In Risk Policy

Sign-in risk reflects the probability that a specific authentication attempt is not from the legitimate account owner — based on signals like impossible travel, anonymous IP, unfamiliar location, or malware-linked IPs.

**Configuration:**
| Setting | Value |
|---|---|
| Scope | All users |
| Risk threshold | High |
| Enforcement control | Require MFA |
| Policy state | On |

**Why MFA over Block:** A risky sign-in doesn't always mean compromise — it may be a legitimate user on a VPN or traveling. Requiring MFA lets the real user prove their identity in real time rather than being locked out entirely. Block is reserved for scenarios where even MFA can't be trusted.

**NIST 800-53 Mappings:**
- `IA-2(1)` – MFA for Privileged Accounts
- `IA-2(2)` – MFA for Non-Privileged Accounts
- `AC-17` – Remote Access (enforcing MFA on anomalous remote sessions)

---

## Lab 3 – MFA Registration Policy

**Location:** Entra admin center → Identity → Protection → Identity Protection → MFA Registration Policy

This policy ensures all users are pre-enrolled for MFA before a risk event ever occurs. Without it, users who have never registered for MFA will be locked out when a sign-in risk policy fires and demands an MFA challenge they can't complete.

**Configuration:**
| Setting | Value |
|---|---|
| Scope | All users |
| Control | Require Microsoft Entra MFA registration (fixed) |
| Policy state | Enabled |

**Key distinction from Sign-In Risk Policy:**
- Sign-In Risk Policy *enforces* MFA when a threat is detected
- MFA Registration Policy ensures users are *capable* of responding to that enforcement

**NIST 800-53 Mappings:**
- `IA-2` – Identification and Authentication
- `IA-5` – Authenticator Management (lifecycle enrollment)

---

## Lab 4 – Microsoft Graph + Identity Protection API

**Location:** Microsoft Entra admin center → App registrations + Microsoft Graph API

This lab covers programmatic access to Identity Protection risk data via Microsoft Graph, enabling automated reporting, SIEM integration, and custom risk workflows beyond what the portal provides.

### Steps Completed

**1. App Registration**
- Registered a new application in Entra ID
- Captured the Application (client) ID and tenant domain

**2. API Permissions Configured**
| Permission | Type | Purpose |
|---|---|---|
| `IdentityRiskEvent.Read.All` | Application | Read all risk detection events |
| `IdentityRiskyUser.Read.All` | Application | Read all risky user records |

- Granted admin consent for the tenant

**3. Client Secret**
- Generated a client secret with a defined expiration window
- Secret used for OAuth client credentials flow authentication

**4. PowerShell Authentication + API Query**

```powershell
$ClientID     = "<your client ID>"
$ClientSecret = "<your client secret>"
$tenantdomain = "<your tenant>.onmicrosoft.com"
$loginURL     = "https://login.microsoft.com"
$resource     = "https://graph.microsoft.com"

$body  = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body

if ($oauth.access_token -ne $null) {
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
    $url = "https://graph.microsoft.com/v1.0/identityProtection/riskDetections"
    $myReport = (Invoke-WebRequest -UseBasicParsing -Headers $headerParams -Uri $url)
    foreach ($event in ($myReport.Content | ConvertFrom-Json).value) {
        Write-Output $event
    }
}
```

**Useful API Queries:**

```http
# Get all offline risk detections
GET https://graph.microsoft.com/v1.0/identityProtection/riskDetections?$filter=detectionTimingType eq 'offline'

# Get users who passed MFA challenge triggered by risky sign-in policy
GET https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskDetail eq 'userPassedMFADrivenByRiskBasedPolicy'
```

**Production note:** In production, replace client secrets with managed identities for Azure resources. Storing secrets in code is a security anti-pattern.

**NIST 800-53 Mappings:**
- `AU-6` – Audit Review and Reporting (programmatic access to risk events)
- `SI-4` – System Monitoring (automated risk detection querying)
- `AC-2` – Account Management (risky user monitoring)

---

## Lab 5 – Security Defaults

**Location:** Entra admin center → Identity → Properties → Manage Security Defaults

Security Defaults are Microsoft's baseline identity security settings, enabled by default on new tenants. They enforce MFA registration for all users, block legacy authentication, and require MFA for privileged actions.

**Key operational note:** Security Defaults and Conditional Access are **mutually exclusive**. Conditional Access must be disabled at Security Defaults first before custom CA policies can be applied. This is a common misconfiguration point in smaller environments that have grown into enterprise CA needs.

| Mode | When to use |
|---|---|
| Security Defaults ON | Small orgs with no CA licensing or expertise |
| Security Defaults OFF + CA | Organizations requiring granular, risk-based access control |

**NIST 800-53 Mappings:**
- `IA-2` – Identification and Authentication (MFA enforcement)
- `AC-6` – Least Privilege (blocking legacy auth protocols)

---

## Lab 6 – Conditional Access – Policy Scenarios

**Location:** Entra admin center → Protection → Conditional Access

Conditional Access is the Zero Trust policy engine of Microsoft Entra ID. Policies evaluate signals (user, device, location, risk) and enforce access controls (allow, block, MFA, device compliance) in real time.

### Scenarios Covered

**Sign-In Risk-Based CA**
Policies that trigger MFA or block access based on Identity Protection risk scores. Requires Entra ID Premium P2.

**User Risk-Based CA**
Policies that enforce password change when a user's cumulative risk level crosses a threshold.

**Restrict MFA Registration to Trusted Locations**
Prevents users from registering for MFA or SSPR outside of known trusted networks — closes a common social engineering vector where an attacker registers their own MFA device.

**Block Access by Geographic Location**
Named locations defined by IP ranges or country/region, used to block traffic from regions where the organization has no legitimate users.

**Require Intune-Compliant Devices**
Enforces that devices accessing M365 resources meet Intune compliance policies (PIN, encryption, OS version, no jailbreak) before granting access.

**Terms of Use Enforcement**
Integrates Identity Governance TOU with CA to require users to accept updated terms before accessing cloud apps.

**Break-Glass Account Exclusions**
All CA policies should exclude emergency access accounts to prevent tenant-wide lockout. Also covers service principals and AI agent identities that require uninterrupted access.

**Best Practice – Report-Only Mode**
All new CA policies should be deployed in report-only mode first. Monitor sign-in logs to validate expected behavior before switching to enforcement.

**NIST 800-53 Mappings:**
- `AC-17` – Remote Access
- `AC-20` – Use of External Information Systems
- `IA-3` – Device Identification and Authentication
- `SC-7` – Boundary Protection (geo-blocking)

---

## Lab 7 – Conditional Access – Hands-On Policy Creation and Testing

**Lab:** Created and validated a live Conditional Access policy end-to-end.

**Policy configured:**
| Setting | Value |
|---|---|
| Name | Test app conditional access |
| Scope | Administrator account |
| Target app | My Apps (myapps.microsoft.com) |
| Condition | Any location |
| Control | Block access |
| State | On (then disabled after testing) |

**Validation method:** Attempted to access myapps.microsoft.com in a separate browser tab — confirmed access was blocked by the policy. Policy then disabled after validation.

**Why this matters:** Testing CA policies before broad deployment prevents unintended lockouts. This end-to-end cycle — configure, enforce, validate, disable — mirrors production change management practice.

---

## Lab 8 – Approved Client App Policies and Intune App Protection

**Location:** Entra admin center → Conditional Access + Microsoft Intune

### Scenario 1 – Require Approved Client Apps for M365 (Mobile)
Configured CA policies requiring users on Android and iOS to access M365 services only through Microsoft-approved apps (Outlook, Teams, OneDrive). Covered both modern authentication clients and Exchange ActiveSync (EAS) clients in separate policies.

### Scenario 2 – Restrict Exchange Online and SharePoint to Approved Apps
Extended the approved client app requirement to cover SharePoint Online in addition to Exchange Online, with the same Android/iOS and EAS policy structure.

### Intune App Protection Policies (MAM)
Mobile Application Management (MAM) protects corporate data at the app level, independent of device enrollment status. Key capability: protects data on personal BYOD devices without requiring MDM enrollment.

**MAM enforcement examples:**
- Require PIN to open app in work context
- Block copy/paste between corporate and personal apps
- Prevent saving corporate data to personal storage
- Wipe corporate data from app without touching personal data

**NIST 800-53 Mappings:**
- `AC-19` – Access Control for Mobile Devices
- `SC-28` – Protection of Information at Rest (app-level data protection)
- `AC-3` – Access Enforcement (approved app controls)

---

## Lab 9 – Authentication Session Controls

**Location:** Entra admin center → Protection → Conditional Access → Session controls

Session controls govern behavior *after* access is granted — how long a session persists, whether tokens can be reused, and how frequently users must re-authenticate.

**Policy configured:**
| Setting | Value |
|---|---|
| Name | Sign in frequency |
| Scope | Administrator account |
| Target app | Office 365 |
| Session control | Sign-in frequency |
| Value | 30 days |
| State | Report-only |

**Key distinction:** Grant controls determine *whether* someone gets access. Session controls determine *how long* that access persists before re-verification is required. For privileged users or sensitive apps, shorter sign-in frequency reduces the window for session token theft.

**NIST 800-53 Mappings:**
- `AC-12` – Session Termination
- `AC-11` – Session Lock
- `IA-11` – Re-Authentication

---

## Lab 10 – AI Agent Identity Management (Entra Agent ID)

**Location:** Entra admin center → Identity → All agent identities

Entra Agent ID enables organizations to manage AI agent identities the same way they manage human and service principal identities — with governance, audit logging, and Conditional Access policy support.

### Scenarios Covered

**Find All Agents of a Specific Type**
Filter by Agent Blueprint ID to view all agent instances created from a specific blueprint (e.g., all "Contoso Sales Agents").

**Disable All Agents from a Blueprint**
Bulk disable agent identities via filtered selection, or disable the parent blueprint to prevent all its agent identities from authenticating.

**Review Recently Created Agents**
Filter by Created On → Last 7 days to audit new agent provisioning activity across the tenant.

**Audit Agent Activity**
Access sign-in logs and audit logs directly from an agent identity's detail pane to review authentication events and actions performed.

**Why this matters:** AI agents authenticate to services, access data, and perform actions autonomously. Without identity governance applied to agents, they represent an unmonitored attack surface. Entra Agent ID brings the same Zero Trust controls used for human identities to AI workloads.

**NIST 800-53 Mappings:**
- `AC-2` – Account Management (agent identity lifecycle)
- `AU-2` – Audit Events (agent sign-in and activity logging)
- `CM-8` – System Component Inventory (agent blueprint tracking)
- `IA-2` – Identification and Authentication (agent authentication governance)

---

## Skills Demonstrated

- Microsoft Entra ID / Azure Active Directory
- Identity Protection (User Risk, Sign-In Risk, MFA Registration policies)
- Conditional Access policy design, testing, and lifecycle management
- Microsoft Graph API integration (app registration, OAuth, PowerShell)
- Intune Mobile Application Management (MAM/APP)
- Authentication session management
- AI agent identity governance (Entra Agent ID)
- Zero Trust architecture principles
- NIST SP 800-53 control mapping
- IAM security operations

---

## Certification Alignment

| SC-300 Domain | Labs Covered |
|---|---|
| Implement and manage Entra ID identities | Labs 1–3, 10 |
| Implement authentication and access management | Labs 1–9 |
| Plan and implement identity governance | Labs 5, 6, 10 |
| Implement access management for Azure resources | Labs 6–8 |

---

## Related Repositories

- [IAM-Compliance-Audit-Toolkit](https://github.com/marcelewisjr/IAM-Compliance-Audit-Toolkit)
- [Intune-Endpoint-Management-Lab](https://github.com/marcelewisjr/Intune-Endpoint-Management-Lab)

---

*Marc Lewis Jr. | Systems & Identity Administrator | [LinkedIn](https://linkedin.com/in/marcelewisjr) | [GitHub](https://github.com/marcelewisjr)*
