import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';

import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <img src="img/logo.svg" alt="AppSec Atlas Logo" width="140" style={{marginBottom: '1rem'}} />
        <Heading as="h1" className="hero__title">
          {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons} style={{display: 'flex', gap: '1rem', justifyContent: 'center', marginTop: '1.5rem'}}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/00-getting-started">
            🗺️ Explore Guides
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            to="/docs/04-ai-ml-security/llm-prompt-injection">
            🤖 LLM Security Guide
          </Link>
          <Link
            className="button button--outline button--light button--lg"
            href="https://github.com/AnimeshShaw/AppSec-Atlas">
            ⭐ GitHub (AnimeshShaw)
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} — Open Source Security Knowledge Base`}
      description="The world's most comprehensive open-source security knowledge base — 45 guides across 9 domains. From application security to AI/LLM security.">
      <HomepageHeader />
      <main style={{padding: '3rem 1rem', maxWidth: '1100px', margin: '0 auto'}}>
        <section style={{textAlign: 'center', marginBottom: '3rem'}}>
          <h2>Map the Entire Security Landscape. One Repo. Zero Excuses.</h2>
          <p style={{fontSize: '1.15rem', color: '#94A3B8', maxWidth: '800px', margin: '0 auto'}}>
            AppSec Atlas is a community-driven monorepo covering 45 security guides across 9 domains. Every concept is backed by practical code, real attack scenarios, and concrete mitigations.
          </p>
        </section>

        <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1.5rem'}}>
          <div style={{background: '#1E293B', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155'}}>
            <h3>🤖 AI / ML Security</h3>
            <p>Flagship coverage of Agentic AI, Prompt Injection, RAG security, MCP tool security, and LLM Red Teaming.</p>
            <Link to="/docs/04-ai-ml-security/llm-prompt-injection">Read LLM Security Guide →</Link>
          </div>

          <div style={{background: '#1E293B', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155'}}>
            <h3>🌐 Web & API Security</h3>
            <p>Deep dives into OWASP Top 10, REST, GraphQL, gRPC security, OAuth2, and frontend vulnerability defenses.</p>
            <Link to="/docs/00-getting-started/learning-paths">View Learning Paths →</Link>
          </div>

          <div style={{background: '#1E293B', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155'}}>
            <h3>☁️ Cloud & DevSecOps</h3>
            <p>Container & K8s hardening, CI/CD pipeline security, secrets management, and Infrastructure-as-Code checks.</p>
            <Link to="https://github.com/AnimeshShaw/AppSec-Atlas/tree/main/checklists">View Security Checklists →</Link>
          </div>
        </div>
      </main>
    </Layout>
  );
}
