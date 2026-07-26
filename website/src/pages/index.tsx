import type { ReactNode } from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';

import HomepageHero from '../components/HomepageHero';
import HomepageDomains from '../components/HomepageDomains';
import HomepagePillars from '../components/HomepagePillars';
import HomepageRoadmap from '../components/HomepageRoadmap';

export default function Home(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <Layout
      title={`${siteConfig.title} — The Open Source Security Knowledge Engine`}
      description="AppSec Atlas is the world's most comprehensive open-source security knowledge base — 45 masterclass guides across 9 security domains. From Application Security & Zero Trust to AI/LLM Security & Red Teaming.">
      
      {/* ARIA Landmarks for WCAG Accessibility */}
      <main id="main-content">
        <HomepageHero />
        <HomepageDomains />
        <HomepagePillars />
        <HomepageRoadmap />

        {/* Community & Contribution CTA Section */}
        <section
          aria-labelledby="community-heading"
          style={{
            padding: '5rem 1.5rem',
            textAlign: 'center',
            background: 'radial-gradient(circle at 50% 100%, rgba(99, 102, 241, 0.15) 0%, transparent 60%)',
            borderTop: '1px solid var(--atlas-card-border)',
          }}>
          <div style={{ maxWidth: '800px', margin: '0 auto' }}>
            <span
              style={{
                fontSize: '0.85rem',
                fontWeight: 700,
                color: '#38bdf8',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                marginBottom: '0.5rem',
                display: 'block',
              }}>
              Community Driven & Open Source
            </span>
            
            <h2
              id="community-heading"
              style={{
                fontFamily: 'var(--ifm-heading-font-family)',
                fontSize: 'clamp(2rem, 3.5vw, 2.75rem)',
                fontWeight: 800,
                marginBottom: '1rem',
              }}>
              Contribute to AppSec Atlas
            </h2>

            <p
              style={{
                fontSize: '1.1rem',
                color: '#94a3b8',
                lineHeight: 1.6,
                marginBottom: '2rem',
              }}>
              AppSec Atlas is maintained by engineers, security researchers, and contributors worldwide. 
              Found a bug, want to add a new lab, or refine a guide? Join the community on GitHub & Discord!
            </p>

            <div
              style={{
                display: 'flex',
                gap: '1rem',
                justifyContent: 'center',
                flexWrap: 'wrap',
              }}>
              <Link
                className="button button--primary button--lg"
                href="https://github.com/AnimeshShaw/AppSec-Atlas"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  borderRadius: '12px',
                  fontWeight: 700,
                  background: 'var(--atlas-accent-gradient)',
                  border: 'none',
                }}>
                ⭐ Star & Fork on GitHub
              </Link>

              <Link
                className="button button--secondary button--lg"
                href="https://discord.gg/NHvrkJ5Hg3"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  borderRadius: '12px',
                  fontWeight: 600,
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'var(--atlas-card-border)',
                }}>
                💬 Join Discord Community
              </Link>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}
