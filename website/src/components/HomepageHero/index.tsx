import type { ReactNode } from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './styles.module.css';

export default function HomepageHero(): ReactNode {
  const { siteConfig } = useDocusaurusContext();

  return (
    <section className={styles.heroSection} aria-labelledby="hero-heading">
      <div className={styles.heroGrid} aria-hidden="true" />
      
      <div className={styles.container}>
        <div className={styles.topBadge} role="status">
          <span aria-hidden="true">✨</span>
          <span>Open-Source Security Monorepo — 100% Free & Community-Driven</span>
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

        {/* Key Statistics Bar */}
        <div className={styles.statsBar} role="region" aria-label="AppSec Atlas Key Statistics">
          <div className={styles.statItem}>
            <span className={styles.statValue}>45</span>
            <span className={styles.statLabel}>Security Guides</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statValue}>300+</span>
            <span className={styles.statLabel}>Deep-Dive Chapters</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statValue}>9</span>
            <span className={styles.statLabel}>Core Domains</span>
          </div>
          <div className={styles.statItem}>
            <span className={styles.statValue}>100%</span>
            <span className={styles.statLabel}>Open-Source (CC BY 4.0)</span>
          </div>
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
            <span aria-hidden="true">🤖</span> AI & LLM Security
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

        {/* Simulated Code / Terminal Preview Widget */}
        <div className={styles.terminalWrapper} role="region" aria-label="Interactive Code Preview">
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
                <span className={styles.comment}># AppSec Atlas — Multi-Layer Input & LLM Guardrail Verification</span>{'\n'}
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
