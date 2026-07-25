# 04 - Defensive Awareness and Simulation

Technical controls will inevitably fail. When a phishing email reaches an inbox, the employee is the final line of defense. Security awareness training must transition from annual compliance checkboxes to continuous, engaging, and practical simulations.

## Designing Ethical Phishing Simulations

The goal of a phishing simulation is to educate, not to punish. Poorly designed campaigns can erode trust between employees and the security team.

### Principles of Ethical Campaigns
1.  **Do not use sensitive internal events:** Avoid leveraging bonuses, layoffs, or HR complaints as lures. This creates unnecessary anxiety and resentment.
2.  **Vary the difficulty:** Use a mix of simple, obvious phishing emails and highly sophisticated spear-phishing attempts to measure different levels of awareness.
3.  **Provide immediate feedback:** When a user clicks a simulated link, immediately present a brief, constructive training moment explaining the red flags they missed.
4.  **Focus on positive reinforcement:** Reward users who consistently report phishing attempts.

## GoPhish Platform Setup

[GoPhish](https://getgophish.com/) is a powerful open-source phishing framework used for organizational assessments.

### Basic Workflow
1.  **Sending Profiles:** Configure SMTP settings to send emails. You will typically need to whitelist the GoPhish IP address in your corporate mail gateway (e.g., Microsoft Defender for Office 365) so simulations aren't blocked.
2.  **Landing Pages:** Create the fake login pages. GoPhish allows you to clone existing websites easily.
3.  **Email Templates:** Design the phishing lures. Use tracking pixels to monitor who opens the email.
4.  **Users & Groups:** Import target lists (often synced via LDAP/Active Directory).
5.  **Campaigns:** Launch the simulation and monitor results in real-time.

## Employee Security Awareness Metrics

Tracking the right metrics is crucial for measuring the effectiveness of the training program.

*   **Click Rate:** The percentage of users who clicked the malicious link. (Important, but not the most critical).
*   **Credential Submission Rate:** The percentage of users who entered data into the landing page. (High risk).
*   **Report Rate:** The percentage of users who used the "Report Phishing" button. **This is the most critical metric.** A high report rate means the security team gets early warning of real attacks.
*   **Time to First Report (TTFR):** How quickly the first user reported the campaign after launch. Faster TTFR enables quicker incident response.

## Report-Phishing Button Integration

Providing users with a simple way to report suspicious emails is essential.
*   **Implementation:** Deploy add-ins for Outlook or Google Workspace (e.g., PhishER, KnowBe4 Phish Alert Button, or native Microsoft Report Message add-in).
*   **Workflow:** When clicked, the email is packaged as an `.eml` file (preserving headers) and sent to a designated security inbox or automated analysis platform (SOAR).
*   **Feedback Loop:** Automatically thank the user for reporting and provide status updates if possible.
