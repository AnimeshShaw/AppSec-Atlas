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
    description: 'Security design patterns, Saltzer-Schroeder principles, AuthN/AuthZ protocols, modern Cryptography, and Zero Trust Architecture.',
    chaptersCount: '5 Guides • 35 Ch.',
    topics: ['OAuth2 PKCE', 'FIDO2 / WebAuthn', 'Zero Trust PEP/PDP', 'Post-Quantum Crypto'],
    link: '/docs/foundational/security-design-patterns',
  },
  {
    id: 'web-api',
    icon: '🌐',
    title: 'Web & API Security',
    description: 'OWASP Top 10 deep dives, REST, GraphQL, gRPC security, CORS/SOP mechanics, Frontend security, and Mobile app defenses.',
    chaptersCount: '8 Guides • 56 Ch.',
    topics: ['BOLA / BFLA', 'gRPC Protobuf', 'GraphQL Batching', 'XSS & CSP'],
    link: '/docs/web-and-api/web-application-security',
  },
  {
    id: 'cloud-infra',
    icon: '☁️',
    title: 'Cloud & DevSecOps',
    description: 'Container & Kubernetes security, Infrastructure as Code checks, Secrets management, and hardened CI/CD pipeline supply chains.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['K8s RBAC', 'Terraform SAST', 'Vault Secrets', 'Cosign OIDC'],
    link: '/docs/cloud-and-infra/cloud-security',
  },
  {
    id: 'ai-ml',
    icon: '🤖',
    title: 'AI & ML Security',
    description: 'Flagship coverage of LLM Prompt Injection, RAG vector poisoning, Agentic AI security, MCP tool safety, and AI Red Teaming.',
    chaptersCount: '6 Guides • 42 Ch.',
    topics: ['Prompt Injection', 'RAG Guardrails', 'MCP Permissions', 'PyRIT / garak'],
    link: '/docs/ai-ml-security/llm-prompt-injection',
  },
  {
    id: 'offensive',
    icon: '⚔️',
    title: 'Offensive Security',
    description: 'CTF competition tactics, Web & Crypto exploits, Network & Firewall bypasses, and Technical Social Engineering defenses.',
    chaptersCount: '4 Guides • 28 Ch.',
    topics: ['Burp Suite Pro', 'Heap Exploitation', 'Wireless Pentest', 'Phishing Defense'],
    link: '/docs/offensive/ctf-guide',
  },
  {
    id: 'defensive',
    icon: '🛡️',
    title: 'Defensive Security & DFIR',
    description: 'Incident Response playbooks, Digital Forensics across Windows/Linux/RAM, Malware Analysis, and SOC Threat Hunting.',
    chaptersCount: '4 Guides • 28 Ch.',
    topics: ['Memory Forensics', 'YARA Rules', 'SIEM Correlation', 'Splunk / KQL'],
    link: '/docs/defensive/digital-forensics',
  },
  {
    id: 'specialized',
    icon: '🔌',
    title: 'Specialized Technologies',
    description: 'Browser Extension Manifest V3 security, IoT & Embedded device firmware auditing, and Hardware security mechanisms.',
    chaptersCount: '2 Guides • 14 Ch.',
    topics: ['MV3 Background Scripts', 'UART / JTAG Auditing', 'Firmware Reverse Eng'],
    link: '/docs/specialized/browser-extension-security',
  },
  {
    id: 'compliance',
    icon: '📋',
    title: 'Compliance & Privacy',
    description: 'Technical implementation guidelines for GDPR, PCI-DSS v4.0, SOC 2 Type II engineering controls, and ISO 27001.',
    chaptersCount: '1 Guide • 7 Ch.',
    topics: ['GDPR Art 32', 'PCI-DSS v4.0 Req 6', 'SOC 2 Trust Criteria'],
    link: '/docs/compliance/gdpr-technical',
  },
  {
    id: 'labs',
    icon: '🧪',
    title: 'Hands-On Labs & PoCs',
    description: 'Self-contained, runnable multi-language vulnerability labs, automated exploit scripts, and complete secure code refactors.',
    chaptersCount: '9 Practical Labs',
    topics: ['Python Labs', 'Node.js Exploits', 'Go Microservices', 'Java Spring Fixes'],
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
