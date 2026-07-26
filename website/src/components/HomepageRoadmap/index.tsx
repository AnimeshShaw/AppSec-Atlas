import type { ReactNode } from 'react';
import Link from '@docusaurus/Link';
import styles from './styles.module.css';

const PATHS = [
  {
    icon: '🚀',
    role: 'Application Security Engineer',
    steps: [
      'Master Security Patterns & OAuth2/OIDC PKCE',
      'Audit Web & API Security (BOLA, GraphQL, gRPC)',
      'Harden CI/CD Supply Chains & Secrets',
      'Execute Multi-Language Vulnerability Labs',
    ],
    link: '/docs/foundational/security-design-patterns',
    btnText: 'Start AppSec Path →',
  },
  {
    icon: '⚡',
    role: 'Cloud Native & DevSecOps Specialist',
    steps: [
      'Implement Zero Trust Architecture (PEP/PDP)',
      'Harden Containers, Kubernetes & SPIFFE/SPIRE',
      'Write IaC Policy-as-Code (Terraform SAST / OPA)',
      'Automate Vault & Cloud Secrets Lifecycle',
    ],
    link: '/docs/cloud-and-infra/cloud-security',
    btnText: 'Start Cloud Path →',
  },
  {
    icon: '🧠',
    role: 'AI & LLM Security Researcher',
    steps: [
      'Master Direct & Indirect LLM Prompt Injections',
      'Defend RAG Vector Stores against Poisoning',
      'Enforce Sandbox Scopes on Agentic MCP Tools',
      'Automate AI Stress Testing with PyRIT & garak',
    ],
    link: '/docs/ai-ml-security/llm-prompt-injection',
    btnText: 'Start AI Security Path →',
  },
];

export default function HomepageRoadmap(): ReactNode {
  return (
    <section className={styles.section} aria-labelledby="roadmap-heading">
      <div className={styles.header}>
        <span className={styles.tagline}>Guided Specialization Tracks</span>
        <h2 id="roadmap-heading" className={styles.title}>
          Tailored Learning Paths
        </h2>
        <p className={styles.subtitle}>
          Whether you are transitioning into AppSec, mastering Cloud Security, or pioneering AI Red Teaming—follow a structured curriculum.
        </p>
      </div>

      <div className={styles.grid}>
        {PATHS.map((path, i) => (
          <div key={i} className={`glass-card ${styles.pathCard}`}>
            <div>
              <div className={styles.pathHeader}>
                <span className={styles.pathIcon} aria-hidden="true">{path.icon}</span>
                <h3 className={styles.pathRole}>{path.role}</h3>
              </div>

              <div className={styles.stepList} role="list">
                {path.steps.map((step, idx) => (
                  <div key={idx} className={styles.stepItem} role="listitem">
                    <span className={styles.stepNumber}>{idx + 1}</span>
                    <span className={styles.stepText}>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <Link className={styles.pathBtn} to={path.link}>
              {path.btnText}
            </Link>
          </div>
        ))}
      </div>
    </section>
  );
}
