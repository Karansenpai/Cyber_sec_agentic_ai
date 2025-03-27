# 🛡️ Monitored Attack Types & Security Events

## 1. Network-Based Attacks
### Port Scanning
- Multiple connections to different ports from a single source
- Detection threshold: 10 unique ports within 5 minutes
- Severity: Medium

### Data Exfiltration
- Unusually large outbound data transfers
- Detection threshold: 10MB+ in 15 minutes
- Severity: High

### Suspicious Network Traffic
- Unusual protocols or destinations
- Abnormal data transfer patterns
- Unexpected port usage

## 2. System-Level Attacks
### Process Chain Attacks
- Suspicious process execution patterns
- Example: cmd.exe → powershell.exe → download activities
- Time window: 15 minutes
- Severity: High

### Unauthorized Access
- Failed login attempts
- Access to restricted resources
- Unusual authentication patterns
- User agent anomalies

### System Resource Abuse
- High CPU Usage
- Memory Leaks
- Low Disk Space
- Potential DoS indicators

## 3. Malware & Threats
### Malware Detection
- Suspicious file activities
- Known malware signatures
- Unusual system modifications
- Binary execution patterns

### Command & Control (C2)
- Suspicious outbound connections
- Periodic beaconing patterns
- Known C2 protocol indicators

## 4. Advanced Persistent Threats (APT)
### Multi-Stage Attacks
- Correlation between:
  - Initial anomaly detection
  - Subsequent system alerts
  - Time window: 30 minutes
  - Severity: High

### Persistence Mechanisms
- Registry modifications
- Scheduled task creation
- Service installations
- Startup folder modifications

## 5. Real-time Monitoring & Alert Types
### Severity Levels
- CRITICAL: Immediate response required
- HIGH: Rapid response needed
- MEDIUM: Investigation required
- LOW: Monitoring and logging

### Alert Categories
1. **Network Logs**
   - Protocol information
   - Source/destination IPs and ports
   - Traffic volume metrics
   - Connection durations
   - User agents

2. **System Alerts**
   - Severity levels
   - Alert types
   - Affected systems
   - Timestamps
   - Detection source

3. **User Events**
   - Authentication attempts
   - Access patterns
   - User activities
   - Device information
   - Location data

## 6. Automated Response Actions
### Immediate Actions
- IP blocking for malicious sources
- Endpoint quarantine
- Process termination
- Account lockdown

### Investigative Actions
- Forensic data collection
- Traffic capture initiation
- Memory dumping
- Log aggregation

## 7. AI-Driven Detection
### Anomaly Types
- Behavioral anomalies
- Statistical outliers
- Pattern deviations
- Temporal anomalies

### Learning Mechanisms
- Feedback loop integration
- Model retraining triggers
- Drift detection
- Pattern adaptation

## 8. Compliance & Reporting
### Event Logging
- Full event context
- Attack timeline
- Response actions taken
- Resolution status

### Metrics Tracked
- Detection rates
- False positive rates
- Response times
- Resolution times
- System health indicators

---

This document is continuously updated as new attack patterns are identified and detection mechanisms are enhanced.