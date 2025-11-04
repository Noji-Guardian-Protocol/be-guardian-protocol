# Guardian Protocol - HIPAA Compliance Security Monitoring

## Overview

Guardian Protocol is a comprehensive security monitoring system designed to ensure HIPAA compliance by detecting and analyzing security violations across multiple domains. The system processes security signals from various collectors and extracts behavioral features for threat detection and compliance monitoring.

## Architecture

The system consists of:
- **FeatureExtractionEngine**: Processes security signals and extracts behavioral features
- **BehavioralFeatures**: Data model containing all security metrics and violations
- **SignalEventLog**: Input data structure from security collectors
- **Windows Collectors**: Platform-specific data collection agents

## Security Feature Categories

### 1. Unauthorized Software Installation Detection

**Purpose**: Identifies installation of unsigned, unapproved, or externally sourced software that could compromise ePHI systems.

**HIPAA Compliance**: §164.308(a)(1) Security Management Process, §164.312(c)(1) Integrity Controls

**Features Extracted**:
- `UnsignedSoftwareInstalled`: Boolean flag for unsigned software detection
- `ExternalRepositoryUsed`: Boolean flag for non-corporate repository usage
- `UnapprovedPackageCount`: Count of unapproved package installations
- `DigitalSignatureViolation`: Boolean flag for signature verification failures
- `CorporatePolicyBypass`: Boolean flag for policy circumvention attempts
- `UnauthorizedRepositoryCount`: Count of unauthorized repository access

**Expected Windows Collector Signals**:
```json
{
  "Security": "UNSIGNED SOFTWARE",
  "Details": "Detected installation of unsigned executable: malware.exe"
}
{
  "Security": "EXTERNAL REPOSITORY",
  "Details": "Package installed from unauthorized source: github.com/malicious/repo"
}
{
  "Security": "SIGNATURE VIOLATION",
  "Details": "Digital signature verification failed for: suspicious.msi"
}
{
  "Security": "POLICY BYPASS",
  "Details": "Software installation policy bypassed via registry modification"
}
{
  "Security": "UNAPPROVED PACKAGE",
  "Details": "Installation of non-whitelisted package: unauthorized-tool.exe"
}
{
  "Security": "UNAUTHORIZED REPOSITORY",
  "Details": "Access to blocked repository: untrusted-packages.com"
}
```

### 2. Automated Update Compliance Monitoring

**Purpose**: Ensures systems receive timely security updates to prevent exploitation of known vulnerabilities.

**HIPAA Compliance**: §164.308(a)(1) Security Management Process, §164.312(c)(1) Integrity Controls

**Features Extracted**:
- `AutomaticUpdatesDisabled`: Boolean flag for disabled update services
- `MissedScheduledUpdates`: Boolean flag for missed update schedules
- `DaysWithoutSecurityUpdates`: Integer count of days without updates
- `CriticalPatchesPending`: Count of pending critical patches
- `UpdateServiceFailure`: Boolean flag for update service failures
- `OutdatedSoftwareDetected`: Boolean flag for vulnerable software versions

**Expected Windows Collector Signals**:
```json
{
  "Security": "UPDATES DISABLED",
  "Details": "Windows Update service disabled by user or policy"
}
{
  "Security": "MISSED SCHEDULED UPDATE",
  "Details": "Scheduled update at 06:00 failed to execute"
}
{
  "Security": "UPDATE SERVICE FAILURE",
  "Details": "Windows Update service crashed during patch installation"
}
{
  "Security": "OUTDATED SOFTWARE",
  "Details": "Critical vulnerability detected in Adobe Reader v10.1.2"
}
{
  "Security": "DAYS WITHOUT UPDATES",
  "VpnConnectionCount": 15,
  "Details": "System has not received updates for 15 days"
}
{
  "Security": "CRITICAL PATCH PENDING",
  "Details": "KB5012345 security update pending installation"
}
```

### 3. Unauthorized Data Sharing Detection

**Purpose**: Identifies attempts to share sensitive data through non-corporate channels.

**HIPAA Compliance**: §164.312(e)(1) Transmission Security, §164.312(a)(1) Access Control

**Features Extracted**:
- `PersonalEmailSharingDetected`: Boolean flag for personal email usage
- `UnauthorizedCloudUpload`: Boolean flag for unauthorized cloud uploads
- `PublicFileSharingUsed`: Boolean flag for public file-sharing services
- `UnapprovedDataTransmissionCount`: Count of unauthorized transmissions
- `DlpPolicyViolation`: Boolean flag for DLP policy violations
- `SensitiveDataExfiltrationAttempts`: Count of data exfiltration attempts

**Expected Windows Collector Signals**:
```json
{
  "Security": "PERSONAL EMAIL SHARING",
  "Details": "Sensitive document sent via Gmail to external recipient"
}
{
  "Security": "UNAUTHORIZED CLOUD UPLOAD",
  "Details": "File upload detected to personal Dropbox account"
}
{
  "Security": "PUBLIC FILE SHARING",
  "Details": "Document shared via WeTransfer public link"
}
{
  "Security": "DLP POLICY VIOLATION",
  "Details": "Attempted transmission of ePHI data blocked by DLP"
}
{
  "Security": "UNAPPROVED DATA TRANSMISSION",
  "Details": "Data sent to non-whitelisted domain: personal-site.com"
}
{
  "Security": "SENSITIVE DATA EXFILTRATION",
  "Details": "Large file transfer to external FTP server detected"
}
```

### 4. Unauthorized Cloud Storage Monitoring

**Purpose**: Detects storage of corporate data in personal or unapproved cloud services.

**HIPAA Compliance**: §164.312(e)(1) Transmission Security, §164.312(a)(1) Access Control

**Features Extracted**:
- `PersonalCloudStorageUsed`: Boolean flag for personal cloud storage usage
- `UnapprovedCloudServiceDetected`: Boolean flag for non-corporate cloud services
- `UnencryptedCloudStorageAccess`: Boolean flag for unencrypted storage access
- `PersonalCloudSyncCount`: Count of personal cloud synchronization events
- `UnapprovedCloudUploadCount`: Count of uploads to unauthorized services
- `CloudStoragePolicyViolation`: Boolean flag for cloud storage policy violations

**Expected Windows Collector Signals**:
```json
{
  "Security": "PERSONAL CLOUD STORAGE",
  "Details": "OneDrive personal account sync detected on corporate device"
}
{
  "Security": "UNAPPROVED CLOUD SERVICE",
  "Details": "Google Drive client installed and authenticated"
}
{
  "Security": "UNENCRYPTED CLOUD STORAGE",
  "Details": "File uploaded to cloud service without encryption"
}
{
  "Security": "CLOUD STORAGE POLICY VIOLATION",
  "Details": "Violation of corporate cloud storage policy detected"
}
{
  "Security": "PERSONAL CLOUD SYNC",
  "Details": "Personal iCloud sync activity detected"
}
{
  "Security": "UNAPPROVED CLOUD UPLOAD",
  "Details": "File uploaded to unauthorized Box.com account"
}
```

## Implementation Details

### Signal Processing Flow

1. **Signal Collection**: Windows collectors gather security events and format them as `SignalEventLog` objects
2. **Feature Extraction**: `FeatureExtractionEngine` processes signals and extracts behavioral features
3. **Compliance Analysis**: Features are analyzed against HIPAA requirements
4. **Output Generation**: Results are exported to CSV and optionally sent to Service Bus

### Key Processing Methods

- `ProcessUnauthorizedSoftwareFeatures()`: Analyzes software installation violations
- `ProcessAutomatedUpdateFeatures()`: Monitors update compliance status
- `ProcessUnauthorizedDataSharingFeatures()`: Detects unauthorized data sharing
- `ProcessUnauthorizedCloudStorageFeatures()`: Monitors cloud storage usage

### Data Model

The `BehavioralFeatures` class contains all extracted security metrics and supports:
- CSV export with comprehensive headers
- JSON serialization for Service Bus transmission
- Real-time feature extraction and analysis

## Windows Collector Requirements

### Expected Signal Format

```json
{
  "Timestamp": 1640995200000,
  "Security": "SECURITY_INDICATOR_STRING",
  "VpnConnectionCount": 0,
  "Details": "Human-readable description of the security event"
}
```

### Security Indicator Strings

Collectors must use specific security indicator strings for proper feature extraction:

**Software Installation**:
- `UNSIGNED SOFTWARE`
- `EXTERNAL REPOSITORY`
- `SIGNATURE VIOLATION`
- `POLICY BYPASS`
- `UNAPPROVED PACKAGE`
- `UNAUTHORIZED REPOSITORY`

**Update Compliance**:
- `UPDATES DISABLED`
- `MISSED SCHEDULED UPDATE`
- `UPDATE SERVICE FAILURE`
- `OUTDATED SOFTWARE`
- `DAYS WITHOUT UPDATES`
- `CRITICAL PATCH PENDING`

**Data Sharing**:
- `PERSONAL EMAIL SHARING`
- `UNAUTHORIZED CLOUD UPLOAD`
- `PUBLIC FILE SHARING`
- `DLP POLICY VIOLATION`
- `UNAPPROVED DATA TRANSMISSION`
- `SENSITIVE DATA EXFILTRATION`

**Cloud Storage**:
- `PERSONAL CLOUD STORAGE`
- `UNAPPROVED CLOUD SERVICE`
- `UNENCRYPTED CLOUD STORAGE`
- `CLOUD STORAGE POLICY VIOLATION`
- `PERSONAL CLOUD SYNC`
- `UNAPPROVED CLOUD UPLOAD`

## MITRE ATT&CK Mapping

The system addresses multiple MITRE ATT&CK techniques:

- **T1204**: User Execution (Malicious File)
- **T1027**: Obfuscated Files or Information
- **T1190**: Exploit Public-Facing Application
- **T1068**: Exploitation for Privilege Escalation
- **T1567**: Exfiltration Over Web Services
- **T1074**: Data Staged
- **T1530**: Data from Cloud Storage

## Deployment

1. Install Windows collectors on target endpoints
2. Configure collectors to send signals to the FeatureExtractionEngine
3. Set up CSV output path and optional Service Bus connection
4. Monitor extracted features for HIPAA compliance violations

## Monitoring and Alerting

The system provides real-time monitoring capabilities:
- Boolean flags for immediate violation detection
- Count metrics for trend analysis
- CSV export for historical analysis
- Service Bus integration for real-time alerting

## Compliance Reporting

Generated features support HIPAA compliance reporting for:
- §164.308(a)(1) Security Management Process
- §164.312(a)(1) Access Control
- §164.312(c)(1) Integrity Controls
- §164.312(e)(1) Transmission Security