import React from 'react';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';

export default function NotFound(): JSX.Element {
  return (
    <Layout
      title="404 — Page Not Found"
      description="The page you're looking for doesn't exist. Navigate back to AppSec Atlas."
    >
      <main
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '70vh',
          padding: '2rem 1.5rem',
          textAlign: 'center',
        }}
      >
        {/* Glowing 404 number */}
        <div
          style={{
            fontFamily: 'var(--ifm-heading-font-family)',
            fontSize: 'clamp(5rem, 15vw, 9rem)',
            fontWeight: 900,
            lineHeight: 1,
            marginBottom: '1rem',
            background: 'linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%)',
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
            fontSize: '0.85rem',
            fontWeight: 700,
            color: '#38bdf8',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
            marginBottom: '1rem',
          }}
        >
          Page Not Found
        </div>

        <h1
          style={{
            fontFamily: 'var(--ifm-heading-font-family)',
            fontSize: 'clamp(1.5rem, 3vw, 2rem)',
            fontWeight: 700,
            marginBottom: '1rem',
            maxWidth: '540px',
          }}
        >
          Looks like this page escaped the security perimeter.
        </h1>

        <p
          style={{
            color: 'var(--atlas-text-secondary, #94a3b8)',
            fontSize: '1.05rem',
            lineHeight: 1.6,
            maxWidth: '480px',
            marginBottom: '2.5rem',
          }}
        >
          The guide or resource you're looking for may have moved, been renamed,
          or doesn't exist yet. Let's get you back on track.
        </p>

        <div
          style={{
            display: 'flex',
            gap: '1rem',
            flexWrap: 'wrap',
            justifyContent: 'center',
          }}
        >
          <Link
            to="/docs/getting-started"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.8rem 1.6rem',
              borderRadius: '10px',
              fontWeight: 700,
              fontSize: '0.95rem',
              color: '#fff',
              background: 'linear-gradient(135deg, #0284c7 0%, #4f46e5 100%)',
              textDecoration: 'none',
              transition: 'transform 0.2s, box-shadow 0.2s',
            }}
          >
            🗺️ Explore All Guides
          </Link>

          <Link
            to="/"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.8rem 1.6rem',
              borderRadius: '10px',
              fontWeight: 600,
              fontSize: '0.95rem',
              color: 'var(--ifm-font-color-base)',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid rgba(255,255,255,0.12)',
              textDecoration: 'none',
            }}
          >
            ← Back to Home
          </Link>
        </div>

        {/* Quick links to popular guides */}
        <div
          style={{
            marginTop: '3rem',
            padding: '1.5rem 2rem',
            borderRadius: '12px',
            border: '1px solid rgba(255,255,255,0.08)',
            background: 'rgba(255,255,255,0.03)',
            maxWidth: '520px',
            width: '100%',
          }}
        >
          <p
            style={{
              fontSize: '0.8rem',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: '#64748b',
              marginBottom: '1rem',
            }}
          >
            Popular Guides
          </p>
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.5rem',
              justifyContent: 'center',
            }}
          >
            {[
              { label: 'OWASP Top 10', to: '/docs/foundational/owasp-top-10' },
              { label: 'LLM Prompt Injection', to: '/docs/ai-ml-security/llm-prompt-injection' },
              { label: 'Kubernetes Security', to: '/docs/cloud-and-infra/container-kubernetes' },
              { label: 'API Security', to: '/docs/web-and-api/api-security' },
              { label: 'Zero Trust', to: '/docs/foundational/zero-trust' },
              { label: 'Agentic AI', to: '/docs/ai-ml-security/agentic-ai-security' },
            ].map(({ label, to }) => (
              <Link
                key={to}
                to={to}
                style={{
                  padding: '4px 12px',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  fontWeight: 500,
                  color: '#94a3b8',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.08)',
                  textDecoration: 'none',
                  transition: 'color 0.15s, border-color 0.15s',
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
