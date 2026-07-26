import type { ReactNode } from 'react';
import styles from './styles.module.css';

const PILLARS = [
  {
    icon: '💻',
    title: 'Multi-Language Production Code',
    desc: 'Side-by-side vulnerable ❌ vs secure ✅ code implementations across Python, Node.js, Go, and Java Spring Boot.',
  },
  {
    icon: '📊',
    title: 'Standards & Framework Aligned',
    desc: 'Mapped directly to OWASP Top 10 (Web/API/LLM), NIST AI 100-2, NIST SP 800-207 Zero Trust, and MITRE ATLAS™.',
  },
  {
    icon: '🧪',
    title: 'Self-Contained Runnable Labs',
    desc: 'Includes target microservices, automated exploit PoC harnesses, hardened refactors, and automated verification tests.',
  },
  {
    icon: '🌐',
    title: '100% Free & Open-Source',
    desc: 'Licensed under Creative Commons Attribution 4.0 (CC BY 4.0). Free for individuals, teams, and enterprise training.',
  },
];

export default function HomepagePillars(): ReactNode {
  return (
    <section className={styles.section} aria-labelledby="pillars-heading">
      <div className={styles.container}>
        <div className={styles.header}>
          <h2 id="pillars-heading" className={styles.title}>
            Engineered for Practical Security Impact
          </h2>
          <p className={styles.subtitle}>
            AppSec Atlas skips generic high-level summaries to give software engineers and security architects actionable code and threat models.
          </p>
        </div>

        <div className={styles.grid}>
          {PILLARS.map((pillar, i) => (
            <div key={i} className={`glass-card ${styles.pillarCard}`}>
              <div className={styles.icon} aria-hidden="true">
                {pillar.icon}
              </div>
              <h3 className={styles.pillarTitle}>{pillar.title}</h3>
              <p className={styles.pillarDesc}>{pillar.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
