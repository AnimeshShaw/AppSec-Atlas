import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';

export default function NotFound(): JSX.Element {
  return (
    <Layout
      title="404 — Security Perimeter Exceeded"
      description="The guide or resource you are looking for does not exist or has moved. Explore the AppSec Atlas knowledge base."
    >
      <main
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '75vh',
          padding: '3rem 1.5rem',
          textAlign: 'center',
        }}
      >
        {/* Glowing 404 number */}
        <div
          style={{
            fontFamily: 'var(--ifm-heading-font-family)',
            fontSize: 'clamp(5.5rem, 16vw, 9.5rem)',
            fontWeight: 900,
            lineHeight: 0.95,
            marginBottom: '1.25rem',
            background: 'var(--atlas-accent-gradient)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
            letterSpacing: '-0.04em',
          }}
        >
          404
        </div>

        <div
          style={{
            fontSize: '0.82rem',
            fontWeight: 700,
            color: '#38bdf8',
            textTransform: 'uppercase',
            letterSpacing: '0.12em',
            marginBottom: '1.25rem',
          }}
        >
          Resource Not Found
        </div>

        <h1
          style={{
            fontFamily: 'var(--ifm-heading-font-family)',
            fontSize: 'clamp(1.6rem, 3.2vw, 2.25rem)',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            marginBottom: '1rem',
            maxWidth: '560px',
          }}
        >
          This route escaped the security perimeter.
        </h1>

        <p
          style={{
            color: 'var(--atlas-text-secondary)',
            fontSize: '1.08rem',
            lineHeight: 1.6,
            maxWidth: '500px',
            marginBottom: '2.5rem',
          }}
        >
          The security guide or lab module you requested may have been renamed or refactored. Let's get you back on track.
        </p>

        <div
          style={{
            display: 'flex',
            gap: '1rem',
            flexWrap: 'wrap',
            justifyContent: 'center',
            marginBottom: '3rem',
          }}
        >
          <Link
            to="/docs/getting-started"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.85rem 1.8rem',
              borderRadius: '12px',
              fontWeight: 700,
              fontSize: '0.95rem',
              color: '#ffffff',
              background: 'var(--atlas-accent-gradient)',
              textDecoration: 'none',
              boxShadow: '0 8px 20px -4px rgba(2, 132, 199, 0.4)',
            }}
          >
            🗺️ Explore All 45 Guides
          </Link>

          <Link
            to="/"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.85rem 1.8rem',
              borderRadius: '12px',
              fontWeight: 600,
              fontSize: '0.95rem',
              color: 'var(--ifm-font-color-base)',
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid var(--atlas-card-border)',
              textDecoration: 'none',
            }}
          >
            ← Back to Homepage
          </Link>
        </div>

        {/* Popular Guide Shortcuts */}
        <div
          style={{
            padding: '1.75rem 2rem',
            borderRadius: '16px',
            border: '1px solid var(--atlas-card-border)',
            background: 'var(--atlas-card-bg)',
            maxWidth: '560px',
            width: '100%',
          }}
        >
          <p
            style={{
              fontSize: '0.78rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--atlas-text-muted)',
              marginBottom: '1.1rem',
            }}
          >
            Popular Security Masterclasses
          </p>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.55rem',
              justifyContent: 'center',
            }}
          >
            {[
              { label: 'OWASP Top 10', to: '/docs/foundational/owasp-top-10' },
              { label: 'LLM Prompt Injection', to: '/docs/ai-ml-security/llm-prompt-injection' },
              { label: 'Agentic AI Security', to: '/docs/ai-ml-security/agentic-ai-security' },
              { label: 'Kubernetes Security', to: '/docs/cloud-and-infra/container-kubernetes' },
              { label: 'API Security', to: '/docs/web-and-api/api-security' },
              { label: 'Zero Trust', to: '/docs/foundational/zero-trust' },
            ].map(({ label, to }) => (
              <Link
                key={to}
                to={to}
                style={{
                  padding: '5px 14px',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  color: 'var(--atlas-text-secondary)',
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid var(--atlas-card-border)',
                  textDecoration: 'none',
                }}
              >
                {label}
              </Link>
            ))}
          </div>
        </div>
      </main>
    </Layout>
  );
}
