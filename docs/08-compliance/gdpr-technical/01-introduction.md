# Introduction to GDPR for Engineers

The General Data Protection Regulation (GDPR) is a comprehensive privacy law that took effect on May 25, 2018. For engineers, GDPR is not just a compliance checklist—it's a fundamental shift in how we architect systems, handle data, and build software.

## Key Definitions

### Personal Data (PII)
Under GDPR (Article 4), personal data is *any* information relating to an identified or identifiable natural person. 
* **Direct Identifiers:** Name, email, phone number, SSN, passport number.
* **Indirect Identifiers:** IP addresses, cookie IDs, location data, biometric data, browser user agents.

### Controller vs. Processor
* **Data Controller:** The entity that determines the *purposes and means* of processing personal data. (e.g., Your company building an application).
* **Data Processor:** The entity that processes data *on behalf of* the controller. (e.g., AWS, GCP, Mailchimp, Datadog).

> [!IMPORTANT]
> If you are a Controller, you are responsible for ensuring your Processors are compliant. If you are a Processor, you must only process data according to the Controller's documented instructions.

## Article 32: Security of Processing
Article 32 is the core technical mandate of the GDPR. It requires controllers and processors to implement "appropriate technical and organizational measures to ensure a level of security appropriate to the risk."

This includes:
1. **Pseudonymization and Encryption:** Encrypting data at rest and in transit.
2. **Resilience:** Ensuring ongoing confidentiality, integrity, availability, and resilience of processing systems.
3. **Recovery:** The ability to restore availability and access to personal data in a timely manner after a physical or technical incident.
4. **Testing:** A process for regularly testing, assessing, and evaluating the effectiveness of security measures.

## The Threat Landscape
Failing to implement GDPR technical controls can lead to:
- **Data Breaches:** Exposing plain-text PII to attackers.
- **Regulatory Fines:** Up to €20 million or 4% of total global turnover, whichever is higher.
- **Reputational Damage:** Loss of customer trust.
- **Loss of Business:** Inability to operate in the EU or partner with EU companies.

In the next chapters, we will dive into the specific technical implementations required to meet these mandates.
