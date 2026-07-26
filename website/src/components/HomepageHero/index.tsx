import React, { useEffect, useRef, useState } from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './styles.module.css';

// Count-up hook using IntersectionObserver — triggers once when element enters viewport
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

    // Respect prefers-reduced-motion
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
  { target: 45, suffix: '', label: 'Security Guides' },
  { target: 300, suffix: '+', label: 'Deep-Dive Chapters' },
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

export default function HomepageHero() {
  const { siteConfig } = useDocusaurusContext();

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
          <strong> 45 masterclass guides</strong>, <strong>300+ technical chapters</strong>, multi-language code labs,
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

        {/* Terminal Preview */}
        <div className={styles.terminalWrapper} role="region" aria-label="Code Preview">
          <div className={styles.terminalHeader}>
            <div className={styles.terminalDots} aria-hidden="true">
              <span className={`${styles.dot} ${styles.dotRed}`} />
              <span className={`${styles.dot} ${styles.dotYellow}`} />
              <span className={`${styles.dot} ${styles.dotGreen}`} />
            </div>
            <span className={styles.terminalTitle}>appsec_atlas_guardrail_validator.py</span>
            <span className={styles.terminalTitle}>Python 3.12</span>
          </div>

          <div className={styles.terminalBody}>
            <pre style={{ margin: 0, background: 'transparent' }}>
              <code>
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
              </code>
            </pre>
          </div>
        </div>
      </div>
    </section>
  );
}
