import React, {useState} from 'react';
import {useLocation} from '@docusaurus/router';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Head from '@docusaurus/Head';

export default function DocItemFooter(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  const location = useLocation();
  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<'yes' | 'no' | null>(null);

  const pageUrl = `${siteConfig.url}${location.pathname}`;
  const pageTitle = typeof document !== 'undefined' ? document.title : 'AppSec Atlas';

  // TechArticle JSON-LD for each doc page — improves Google rich snippets
  const techArticleSchema = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: pageTitle.replace(' | AppSec Atlas', '').replace(' — AppSec Atlas', ''),
    url: pageUrl,
    inLanguage: 'en',
    isAccessibleForFree: true,
    publisher: {
      '@type': 'Organization',
      name: 'AppSec Atlas',
      logo: {
        '@type': 'ImageObject',
        url: `${siteConfig.url}/img/logo.png`,
      },
    },
    author: {
      '@type': 'Person',
      name: 'Animesh Shaw',
      url: 'https://github.com/AnimeshShaw',
    },
    about: {
      '@type': 'Thing',
      name: 'Application Security',
    },
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(pageUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      const el = document.createElement('textarea');
      el.value = pageUrl;
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const shareLinks = [
    {
      label: '𝕏 Twitter',
      href: `https://twitter.com/intent/tweet?text=${encodeURIComponent(`📖 ${pageTitle}`)}&url=${encodeURIComponent(pageUrl)}&hashtags=AppSec,CyberSecurity,OpenSource`,
      color: '#000000',
    },
    {
      label: 'in LinkedIn',
      href: `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(pageUrl)}`,
      color: '#0A66C2',
    },
    {
      label: '↗ Reddit',
      href: `https://www.reddit.com/submit?url=${encodeURIComponent(pageUrl)}&title=${encodeURIComponent(pageTitle)}`,
      color: '#FF4500',
    },
    {
      label: '✉ Email',
      href: `mailto:?subject=${encodeURIComponent(pageTitle)}&body=${encodeURIComponent(`Check out this AppSec guide: ${pageUrl}`)}`,
      color: '#6B7280',
    },
  ];

  return (
    <>
      <Head>
        <script type="application/ld+json">
          {JSON.stringify(techArticleSchema)}
        </script>
      </Head>

      <div className="atlas-doc-footer-wrapper">
        {/* Interactive "Was this helpful?" Feedback Widget */}
        <div className="atlas-feedback-card">
          <div className="atlas-feedback-header">
            <span className="atlas-feedback-title">Was this guide helpful?</span>
            {feedback === null ? (
              <div className="atlas-feedback-actions">
                <button
                  onClick={() => setFeedback('yes')}
                  className="atlas-feedback-btn atlas-feedback-yes"
                  aria-label="Mark guide as helpful"
                >
                  👍 Yes
                </button>
                <button
                  onClick={() => setFeedback('no')}
                  className="atlas-feedback-btn atlas-feedback-no"
                  aria-label="Mark guide as needs improvement"
                >
                  👎 Needs Work
                </button>
              </div>
            ) : (
              <div className="atlas-feedback-thanks">
                🎉 Thanks for your feedback!{' '}
                {feedback === 'no' && (
                  <a
                    href="https://github.com/AnimeshShaw/AppSec-Atlas/issues/new"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="atlas-feedback-issue-link"
                  >
                    Suggest an edit or issue on GitHub →
                  </a>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Share Bar */}
        <div className="atlas-share-bar">
          <span className="atlas-share-label">Share this guide</span>
          <div className="atlas-share-buttons">
            {shareLinks.map(({label, href, color}) => (
              <a
                key={label}
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                className="atlas-share-btn"
                style={{'--share-color': color} as React.CSSProperties}
                aria-label={`Share on ${label}`}
              >
                {label}
              </a>
            ))}
            <button
              onClick={handleCopy}
              className="atlas-share-btn atlas-share-copy"
              aria-label="Copy link to clipboard"
            >
              {copied ? '✓ Copied!' : '🔗 Copy Link'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
