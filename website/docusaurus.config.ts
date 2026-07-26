import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'AppSec Atlas',
  tagline: 'The World\'s Most Comprehensive Open-Source Application Security Knowledge Base',
  favicon: 'img/favicon.png',

  future: {
    v4: true,
    faster: {
      swcJsLoader: true,
      swcJsMinimizer: true,
      swcHtmlMinimizer: true,
      lightningCssMinimizer: true,
      mdxCrossCompilerCache: true,
    },
  },

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },
  themes: ['@docusaurus/theme-mermaid'],

  url: 'https://appsecatlas.com',
  baseUrl: '/',

  organizationName: 'AnimeshShaw',
  projectName: 'AppSec-Atlas',

  onBrokenLinks: 'warn',

  headTags: [
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.googleapis.com',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preconnect',
        href: 'https://fonts.gstatic.com',
        crossorigin: 'anonymous',
      },
    },
    {
      tagName: 'link',
      attributes: {
        rel: 'preload',
        href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@700;800&display=swap',
        as: 'style',
        onload: "this.onload=null;this.rel='stylesheet'",
      },
    },
    {
      tagName: 'noscript',
      attributes: {},
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'author',
        content: 'Animesh Shaw',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:type',
        content: 'website',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:site_name',
        content: 'AppSec Atlas',
      },
    },
    // SEO: Meta description
    {
      tagName: 'meta',
      attributes: {
        name: 'description',
        content: 'AppSec Atlas — Free, open-source application security knowledge base covering OWASP, web security, API security, cloud security, AI/ML security, DevSecOps, cryptography, penetration testing, and more.',
      },
    },
    // SEO: Keywords
    {
      tagName: 'meta',
      attributes: {
        name: 'keywords',
        content: 'application security, appsec, web security, API security, OWASP Top 10, penetration testing, DevSecOps, cloud security, Kubernetes security, secrets management, LLM security, AI security, prompt injection, agentic AI security, cryptography, post-quantum cryptography, zero trust, JWT security, OAuth security, XSS, CSRF, SSRF, SQL injection, container security, CI/CD security, bug bounty, red teaming, incident response, compliance, GDPR, SOC 2, NIST, mobile security, IoT security, secure coding, threat modeling, STRIDE',
      },
    },
    // SEO: Open Graph
    {
      tagName: 'meta',
      attributes: {
        property: 'og:title',
        content: 'AppSec Atlas — Open-Source Application Security Knowledge Base',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:description',
        content: 'Master application security with 45+ in-depth modules covering OWASP, AI/ML security, cloud security, DevSecOps, and more. Free and open-source.',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:image',
        content: 'https://appsecatlas.com/img/logo.png',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        property: 'og:url',
        content: 'https://appsecatlas.com',
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'twitter:card',
        content: 'summary_large_image',
      },
    },
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: [
    [
      '@docusaurus/plugin-client-redirects',
      {
        createRedirects(existingPath: string) {
          if (existingPath.startsWith('/docs/')) {
            const pathWithoutDocs = existingPath.replace('/docs/', '');
            const categoryMap: Record<string, string> = {
              'getting-started': '00-getting-started',
              'foundational': '01-foundational',
              'web-and-api': '02-web-and-api',
              'cloud-and-infra': '03-cloud-and-infra',
              'ai-ml-security': '04-ai-ml-security',
              'offensive': '05-offensive',
              'defensive': '06-defensive',
              'specialized': '07-specialized',
              'compliance': '08-compliance',
              'hands-on': '09-hands-on',
            };
            for (const [clean, numbered] of Object.entries(categoryMap)) {
              if (pathWithoutDocs.startsWith(clean)) {
                const legacyPath = '/docs/' + pathWithoutDocs.replace(clean, numbered);
                return [legacyPath];
              }
            }
          }
          return undefined;
        },
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../docs',
          routeBasePath: 'docs',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/AnimeshShaw/AppSec-Atlas/tree/main/',
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          editUrl: 'https://github.com/AnimeshShaw/AppSec-Atlas/tree/main/',
        },
        sitemap: {
          lastmod: 'date',
          changefreq: 'weekly',
          priority: 0.5,
          ignorePatterns: ['/tags/**'],
          filename: 'sitemap.xml',
          createSitemapItems: async (params) => {
            const {defaultCreateSitemapItems, ...rest} = params;
            const items = await defaultCreateSitemapItems(rest);
            return items.filter((item) => !item.url.includes('/page/'));
          },
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    mermaid: {
      theme: {light: 'neutral', dark: 'dark'},
    },
    image: 'img/logo.png',
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'AppSec Atlas',
      logo: {
        alt: 'AppSec Atlas Logo',
        src: 'img/logo.png',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: '📚 Guides',
        },
        // Blog hidden until content is published
        // {to: '/blog', label: '📰 Blog', position: 'left'},
        {
          href: 'https://github.com/AnimeshShaw/AppSec-Atlas',
          label: '⭐ GitHub',
          position: 'right',
        },
        {
          href: 'https://discord.gg/NHvrkJ5Hg3',
          label: '💬 Discord',
          position: 'right',
        },
        {
          href: 'https://github.com/sponsors/AnimeshShaw',
          label: '💖 Sponsor',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Foundational Security',
          items: [
            { label: 'Getting Started', to: '/docs/getting-started' },
            { label: 'OWASP Top 10', to: '/docs/foundational/owasp-top-10' },
            { label: 'Cryptography', to: '/docs/foundational/cryptography' },
            { label: 'Auth & Authorization', to: '/docs/foundational/auth-and-authz' },
            { label: 'Secure Coding', to: '/docs/foundational/secure-coding' },
            { label: 'Zero Trust', to: '/docs/foundational/zero-trust' },
          ],
        },
        {
          title: 'Web, API & Cloud',
          items: [
            { label: 'Web App Security', to: '/docs/web-and-api/web-application-security' },
            { label: 'API Security', to: '/docs/web-and-api/api-security' },
            { label: 'Frontend Security', to: '/docs/web-and-api/frontend-security' },
            { label: 'Cloud Security', to: '/docs/cloud-and-infra/cloud-security' },
            { label: 'Container & Kubernetes', to: '/docs/cloud-and-infra/container-kubernetes' },
            { label: 'CI/CD Pipeline Security', to: '/docs/cloud-and-infra/cicd-pipeline-security' },
          ],
        },
        {
          title: 'AI & Offensive Security',
          items: [
            { label: 'LLM Prompt Injection', to: '/docs/ai-ml-security/llm-prompt-injection' },
            { label: 'Agentic AI Security', to: '/docs/ai-ml-security/agentic-ai-security' },
            { label: 'ML Model Security', to: '/docs/ai-ml-security/ml-model-security' },
            { label: 'Penetration Testing', to: '/docs/offensive/penetration-testing' },
            { label: 'Bug Bounty Guide', to: '/docs/offensive/bug-bounty' },
            { label: 'Red Teaming', to: '/docs/ai-ml-security/ai-red-teaming' },
          ],
        },
        {
          title: 'Community & Support',
          items: [
            { label: 'GitHub', href: 'https://github.com/AnimeshShaw/AppSec-Atlas' },
            { label: 'Discord Community', href: 'https://discord.gg/NHvrkJ5Hg3' },
            { label: 'Contribute', href: 'https://github.com/AnimeshShaw/AppSec-Atlas/blob/main/CONTRIBUTING.md' },
            { label: '💖 GitHub Sponsors', href: 'https://github.com/sponsors/AnimeshShaw' },
            { label: '☕ Ko-fi', href: 'https://ko-fi.com/animeshshaw' },
            { label: '🔐 DevCipher Platform', href: 'https://devcipher.dev/' },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Animesh Shaw & AppSec Atlas Contributors. Licensed under <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['python', 'bash', 'json', 'yaml', 'sql', 'docker'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
