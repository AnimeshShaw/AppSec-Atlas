# Incident Response Checklist

## Phase 1: Identification
- [ ] Alert received and triaged (determine if genuine incident or false positive)
- [ ] Incident severity classified: Critical / High / Medium / Low
- [ ] Incident type identified: breach, ransomware, insider threat, account compromise, DDoS, etc.
- [ ] Incident Response lead assigned
- [ ] Incident tracking ticket opened
- [ ] Initial stakeholders notified (security lead, CISO, legal if applicable)

## Phase 2: Containment
- [ ] Affected systems identified
- [ ] Snapshots/forensic images taken of affected systems BEFORE remediation
- [ ] Affected accounts disabled or credentials rotated
- [ ] Network isolation applied if necessary (disconnect compromised systems)
- [ ] Malicious IPs/domains blocked at perimeter
- [ ] Evidence preserved (logs, memory dumps, disk images)
- [ ] Chain of custody documented for all evidence

## Phase 3: Investigation
- [ ] Timeline of events reconstructed
- [ ] Attack vector identified (how did the attacker get in?)
- [ ] Scope of compromise determined (what systems/data were affected?)
- [ ] All attacker footholds identified
- [ ] Indicators of Compromise (IOCs) extracted
- [ ] Lateral movement traced

## Phase 4: Eradication
- [ ] All malware, backdoors, and unauthorized accounts removed
- [ ] Compromised credentials rotated across all systems
- [ ] Vulnerability that was exploited patched
- [ ] IOCs shared with threat intelligence platforms
- [ ] Systems verified clean before restoration

## Phase 5: Recovery
- [ ] Systems restored from clean backups or rebuilt from scratch
- [ ] Restored systems monitored closely for recurrence
- [ ] Services gradually restored with increased monitoring
- [ ] Stakeholders notified of recovery progress

## Phase 6: Lessons Learned
- [ ] Post-incident review scheduled within 2 weeks
- [ ] Root cause documented
- [ ] Timeline documented
- [ ] What worked well identified
- [ ] What needs improvement identified
- [ ] Action items assigned with owners and deadlines
- [ ] Regulatory notification completed if required (GDPR 72hr, etc.)
- [ ] Incident report finalized and stored
