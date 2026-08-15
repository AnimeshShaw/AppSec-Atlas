import type { ReactNode } from 'react';
import Link from '@docusaurus/Link';
import styles from './styles.module.css';

interface DomainItem {
  id: string;
  icon: string;
  title: string;
  description: string;
  chaptersCount: string;
  topics: string[];
  link: string;
  badgeClass?: string;
}

const DOMAINS: DomainItem[] = [
  {
    id: 'foundations',
    icon: '🛡️',
    title: 'Foundational Security',
    description: 'Security design patterns, Saltzer-Schroeder principles, AuthN/AuthZ protocols, Post-Quantum Cryptography, and Zero Trust Architecture.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['Post-Quantum Crypto', 'Zero Trust Architecture', 'OAuth2 PKCE', 'FIDO2 / WebAuthn'],
    link: '/docs/foundational/security-design-patterns',
  },
  {
    id: 'web-api',
    icon: '🌐',
    title: 'Web & API Security',
    description: 'OWASP Top 10 deep dives, REST, GraphQL, gRPC security, Modern API Identity (Passkeys/DPoP), Frontend security, and Mobile app defenses.',
    chaptersCount: '8 Guides • 56 Ch.',
    topics: ['Modern API Identity', 'gRPC Protobuf', 'GraphQL Batching', 'XSS & CSP'],
    link: '/docs/web-and-api/web-application-security',
  },
  {
    id: 'cloud-infra',
    icon: '☁️',
    title: 'Cloud & Infrastructure',
    description: 'Cross-Cloud IAM Federation, Kubernetes eBPF Runtime security, Confidential Computing enclaves, and Zero-Day Containment playbooks.',
    chaptersCount: '10 Guides • 70 Ch.',
    topics: ['eBPF Runtime', 'Workload Identity', 'Zero-Day Playbooks', 'Confidential Computing'],
    link: '/docs/cloud-and-infra/cloud-security',
  },
  {
    id: 'ai-ml',
    icon: '🤖',
    title: 'AI & ML Security',
    description: 'Flagship coverage of LLM Prompt Injection, RAG vector poisoning, Agentic AI security, MCP tool safety, and AI Red Teaming.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['Prompt Injection', 'RAG Guardrails', 'MCP Permissions', 'Agentic Security'],
    link: '/docs/ai-ml-security/llm-prompt-injection',
  },
  {
    id: 'offensive',
    icon: '⚔️',
    title: 'Offensive Security',
    description: 'Bug Bounty Hunting methodology, CTF competition tactics, Web & Crypto exploits, Network & Firewall bypasses, and Enterprise Security Assessment.',
    chaptersCount: '5 Guides • 35 Ch.',
    topics: ['Bug Bounty Hunting', 'DAST Pipelines', 'Network Exploits', 'Enterprise Posture'],
    link: '/docs/offensive/bug-bounty',
  },
  {
    id: 'defensive',
    icon: '🛡️',
    title: 'Defensive Security & DFIR',
    description: 'Security Chaos Engineering, Incident Response playbooks, Digital Forensics across Windows/Linux, Malware Analysis, and SOC Threat Hunting.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['Chaos Engineering', 'Memory Forensics', 'YARA Rules', 'SIEM Correlation'],
    link: '/docs/defensive/digital-forensics',
  },
  {
    id: 'specialized',
    icon: '🔌',
    title: 'Specialized Technologies',
    description: 'Software Supply Chain (SLSA 4), Privacy Engineering, Browser Extension MV3, IoT device firmware, and Hardware security mechanisms.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['Supply Chain (SLSA)', 'Privacy Engineering', 'MV3 Scripts', 'Hardware JTAG'],
    link: '/docs/specialized/supply-chain-security',
  },
  {
    id: 'compliance',
    icon: '📋',
    title: 'Compliance & Governance',
    description: 'Technical implementation guidelines for GDPR, NIST CSF, SOC 2 Type II engineering controls, and DevSecOps handbooks.',
    chaptersCount: '4 Guides • 28 Ch.',
    topics: ['SOC 2 Trust Criteria', 'NIST CSF', 'GDPR Engineering', 'DevSecOps'],
    link: '/docs/compliance/gdpr-technical',
  },
  {
    id: 'labs',
    icon: '🧪',
    title: 'Hands-On Labs & PoCs',
    description: '7 deep-dive Vulnerable Application Labs covering SQLi, XSS, SSRF, IDOR, XXE with side-by-side Go/TypeScript/Python remediation.',
    chaptersCount: '3 Guides • 21 Ch.',
    topics: ['Vulnerable App Lab', 'Go Microservices', 'Python Labs', 'TypeScript Fixes'],
    link: '/docs/hands-on/vulnerable-app-lab',
  },
];

export default function HomepageDomains(): ReactNode {
  return (
    <section className={styles.section} aria-labelledby="domains-heading">
      <div className={styles.header}>
        <span className={styles.tagline}>Comprehensive Security Curriculum</span>
        <h2 id="domains-heading" className={styles.title}>
          Explore All 9 Security Domains
        </h2>
        <p className={styles.description}>
          Every domain is built with zero fluff—featuring architectural diagrams, side-by-side vulnerable vs secure code, and runnable hands-on labs.
        </p>
      </div>

      <div className={styles.grid} role="list">
        {DOMAINS.map((domain) => (
          <Link
            key={domain.id}
            to={domain.link}
            className={`glass-card ${styles.domainCard}`}
            role="listitem"
            aria-label={`${domain.title} domain guide with ${domain.chaptersCount}`}>
            <div>
              <div className={styles.domainHeader}>
                <div className={styles.iconWrapper} aria-hidden="true">
                  {domain.icon}
                </div>
                <span className={styles.chapterBadge}>{domain.chaptersCount}</span>
              </div>

              <h3 className={styles.domainTitle}>{domain.title}</h3>
              <p className={styles.domainDescription}>{domain.description}</p>

              <div className={styles.topicsList} aria-label="Key topics covered">
                {domain.topics.map((topic, i) => (
                  <span key={i} className={styles.topicTag}>
                    {topic}
                  </span>
                ))}
              </div>
            </div>

            <div className={styles.arrowLink}>
              <span>Explore Guide</span>
              <span aria-hidden="true">→</span>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
