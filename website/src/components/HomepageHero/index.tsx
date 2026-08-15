import React, { useEffect, useRef, useState } from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './styles.module.css';

function useCountUp(target: number, duration = 1800, suffix = '') {
  const [count, setCount] = useState(0);
  const [started, setStarted] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !started) {
          setStarted(true);
        }
      },
      { threshold: 0.3 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [started]);

  useEffect(() => {
    if (!started) return;

    const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) {
      setCount(target);
      return;
    }

    let start = 0;
    const step = target / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= target) {
        setCount(target);
        clearInterval(timer);
      } else {
        setCount(Math.floor(start));
      }
    }, 16);
    return () => clearInterval(timer);
  }, [started, target, duration]);

  return { count, ref };
}

const STATS = [
  { target: 54, suffix: '', label: 'Security Guides' },
  { target: 378, suffix: '+', label: 'Deep-Dive Chapters' },
  { target: 9, suffix: '', label: 'Core Domains' },
  { target: 100, suffix: '%', label: 'Open-Source (CC BY 4.0)' },
];

function StatItem({ target, suffix, label }: { target: number; suffix: string; label: string }) {
  const { count, ref } = useCountUp(target);
  return (
    <div className={styles.statItem} ref={ref}>
      <span className={styles.statValue} aria-live="polite">
        {count}{suffix}
      </span>
      <span className={styles.statLabel}>{label}</span>
    </div>
  );
}

const CODE_EXAMPLES = {
  python: {
    filename: 'guardrail_validator.py',
    lang: 'Python 3.12',
    code: (styles: Record<string, string>) => (
      <>
        <span className={styles.comment}># AppSec Atlas — Multi-Layer Input &amp; LLM Guardrail Verification</span>{'\n'}
        <span className={styles.keyword}>from</span> appsec_atlas.security <span className={styles.keyword}>import</span> Sanitizer, OWASPValidator{'\n'}
        <span className={styles.keyword}>from</span> appsec_atlas.ai_guard <span className={styles.keyword}>import</span> LlamaGuard3Engine{'\n\n'}

        <span className={styles.decorator}>@OWASPValidator</span>(strict_mode=<span className={styles.keyword}>True</span>){'\n'}
        <span className={styles.keyword}>def</span> <span className={styles.function}>verify_agentic_tool_execution</span>(prompt: <span className={styles.string}>str</span>, context: <span className={styles.string}>dict</span>):{'\n'}
        {'    '}<span className={styles.comment}># 1. Sanitize untrusted prompt input against indirect injections</span>{'\n'}
        {'    '}clean_input = Sanitizer.strip_unicode_homoglyphs(prompt){'\n'}
        {'    '}LlamaGuard3Engine.verify_hazard_category(clean_input){'\n\n'}

        {'    '}<span className={styles.comment}># 2. Enforce Least-Privilege Role Boundaries for MCP Agent Tools</span>{'\n'}
        {'    '}<span className={styles.keyword}>if not</span> context.get(<span className={styles.string}>"auth_claims"</span>).has_scope(<span className={styles.string}>"mcp:tool:execute"</span>):{'\n'}
        {'        '}<span className={styles.keyword}>raise</span> PermissionError(<span className={styles.string}>"Unauthorized tool invocation attempt detected"</span>){'\n\n'}

        {'    '}<span className={styles.keyword}>return</span> <span className={styles.string}>"✓ Safe for LLM Execution"</span>
      </>
    ),
  },
  typescript: {
    filename: 'mcpGuard.ts',
    lang: 'TypeScript 5.4',
    code: (styles: Record<string, string>) => (
      <>
        <span className={styles.comment}>// AppSec Atlas — Zero Trust MCP Agent Scope Guard</span>{'\n'}
        <span className={styles.keyword}>import</span> &#123; MCPToolContext, TokenClaims &#125; <span className={styles.keyword}>from</span> <span className={styles.string}>'@appsec-atlas/mcp-auth'</span>;{'\n'}
        <span className={styles.keyword}>import</span> &#123; PromptSanitizer &#125; <span className={styles.keyword}>from</span> <span className={styles.string}>'@appsec-atlas/security'</span>;{'\n\n'}

        <span className={styles.keyword}>export async function</span> <span className={styles.function}>validateAgentCall</span>(input: <span className={styles.string}>string</span>, claims: TokenClaims) &#123;{'\n'}
        {'  '}<span className={styles.comment}>// 1. Sanitize unicode exploits &amp; control codes</span>{'\n'}
        {'  '}<span className={styles.keyword}>const</span> cleanInput = PromptSanitizer.cleanInput(input);{'\n\n'}

        {'  '}<span className={styles.comment}>// 2. Validate JWT Scopes against PDP PDP Engine</span>{'\n'}
        {'  '}<span className={styles.keyword}>if</span> (!claims.scopes.includes(<span className={styles.string}>'mcp:tool:execute'</span>)) &#123;{'\n'}
        {'    '}<span className={styles.keyword}>throw new</span> Error(<span className={styles.string}>'Forbidden: Missing MCP tool authorization scope'</span>);{'\n'}
        {'  '}&#125;{'\n'}
        {'  '}<span className={styles.keyword}>return</span> &#123; status: <span className={styles.string}>'VERIFIED'</span>, payload: cleanInput &#125;;{'\n'}
        &#125;
      </>
    ),
  },
  go: {
    filename: 'guard.go',
    lang: 'Go 1.22',
    code: (styles: Record<string, string>) => (
      <>
        <span className={styles.comment}>// AppSec Atlas — High-Performance Zero Trust Policy PDP</span>{'\n'}
        <span className={styles.keyword}>package</span> main{'\n\n'}
        <span className={styles.keyword}>import</span> ({'\n'}
        {'    '}<span className={styles.string}>"fmt"</span>{'\n'}
        {'    '}<span className={styles.string}>"github.com/appsec-atlas/sdk/security"</span>{'\n'}
        ){'\n\n'}
        <span className={styles.keyword}>func</span> <span className={styles.function}>VerifyToolExecution</span>(prompt <span className={styles.string}>string</span>, scope <span className={styles.string}>string</span>) (<span className={styles.string}>bool</span>, <span className={styles.string}>error</span>) &#123;{'\n'}
        {'    '}<span className={styles.comment}>// 1. Sanitize inputs and verify OAuth2 PKCE PDP token</span>{'\n'}
        {'    '}<span className={styles.keyword}>if</span> !security.HasValidScope(scope, <span className={styles.string}>"mcp:tool:execute"</span>) &#123;{'\n'}
        {'        '}<span className={styles.keyword}>return</span> <span className={styles.keyword}>false</span>, fmt.Errorf(<span className={styles.string}>"unauthorized MCP invocation"</span>){'\n'}
        {'    '}&#125;{'\n'}
        {'    '}<span className={styles.keyword}>return</span> <span className={styles.keyword}>true</span>, <span className={styles.keyword}>nil</span>{'\n'}
        &#125;
      </>
    ),
  },
};

export default function HomepageHero() {
  const { siteConfig } = useDocusaurusContext();
  const [activeTab, setActiveTab] = useState<'python' | 'typescript' | 'go'>('python');

  return (
    <section className={styles.heroSection} aria-labelledby="hero-heading">
      <div className={styles.heroGrid} aria-hidden="true" />

      <div className={styles.container}>
        <div className={styles.topBadge} role="status">
          <span aria-hidden="true">✨</span>
          <span>Open-Source Security Monorepo — 100% Free &amp; Community-Driven</span>
        </div>

        <h1 id="hero-heading" className={styles.heroTitle}>
          Map the Entire Security Landscape.<br />
          <span className="gradient-text">Zero Fluff. Pure Engineering.</span>
        </h1>

        <p className={styles.heroSubtitle}>
          AppSec Atlas is the ultimate open-source security knowledge engine—spanning
          <strong> 54 masterclass guides</strong>, <strong>375+ technical chapters</strong>, multi-language code labs,
          and real-world threat models from Web/API to Agentic AI Security.
        </p>

        {/* Animated Stats Bar */}
        <div className={styles.statsBar} role="region" aria-label="AppSec Atlas Key Statistics">
          {STATS.map((s) => (
            <StatItem key={s.label} target={s.target} suffix={s.suffix} label={s.label} />
          ))}
        </div>

        {/* Call to Action Buttons */}
        <div className={styles.ctaGroup}>
          <Link
            className={styles.primaryBtn}
            to="/docs/getting-started"
            aria-label="Explore all 45 security guides in AppSec Atlas">
            <span aria-hidden="true">🗺️</span> Explore All 45 Guides
          </Link>

          <Link
            className={styles.secondaryBtn}
            to="/docs/ai-ml-security/llm-prompt-injection"
            aria-label="Read Flagship LLM and Agentic AI Security Guide">
            <span aria-hidden="true">🤖</span> AI &amp; LLM Security
          </Link>

          <Link
            className={styles.secondaryBtn}
            href="https://github.com/AnimeshShaw/AppSec-Atlas"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Star AppSec Atlas on GitHub">
            <span aria-hidden="true">⭐</span> Star on GitHub
          </Link>
        </div>

        {/* Interactive Terminal Window Preview Widget */}
        <div className={styles.terminalWrapper} role="region" aria-label="Interactive Code Preview">
          <div className={styles.terminalHeader}>
            <div className={styles.terminalDots} aria-hidden="true">
              <span className={`${styles.dot} ${styles.dotRed}`} />
              <span className={`${styles.dot} ${styles.dotYellow}`} />
              <span className={`${styles.dot} ${styles.dotGreen}`} />
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              {(['python', 'typescript', 'go'] as const).map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    background: activeTab === tab ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                    color: activeTab === tab ? '#38bdf8' : '#8a8f98',
                    border: activeTab === tab ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid transparent',
                    borderRadius: '6px',
                    padding: '2px 10px',
                    fontSize: '0.78rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                    fontFamily: 'var(--ifm-font-family-monospace)',
                    transition: 'all 0.15s ease',
                  }}>
                  {CODE_EXAMPLES[tab].filename}
                </button>
              ))}
            </div>

            <span className={styles.terminalTitle}>{CODE_EXAMPLES[activeTab].lang}</span>
          </div>

          <div className={styles.terminalBody}>
            <pre style={{ margin: 0, background: 'transparent' }}>
              <code>{CODE_EXAMPLES[activeTab].code(styles)}</code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}
