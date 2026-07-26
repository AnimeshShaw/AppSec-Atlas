import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'AppSec Atlas',
  tagline: 'The World\'s Most Comprehensive Open-Source Security Knowledge Base',
  favicon: 'img/logo.svg',

  future: {
    v4: true,
  },

  markdown: {
    mermaid: true,
  },
  themes: ['@docusaurus/theme-mermaid'],

  url: 'https://appsecatlas.com',
  baseUrl: '/',

  organizationName: 'AnimeshShaw',
  projectName: 'AppSec-Atlas',

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

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
        rel: 'stylesheet',
        href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@500;600;700;800&display=swap',
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
    image: 'img/logo.svg',
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'AppSec Atlas',
      logo: {
        alt: 'AppSec Atlas Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'tutorialSidebar',
          position: 'left',
          label: '📚 Guides',
        },
        {to: '/blog', label: '📰 Blog', position: 'left'},
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
          title: 'Knowledge Base',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started',
            },
            {
              label: 'AI / ML Security',
              to: '/docs/ai-ml-security/agentic-ai-security',
            },
            {
              label: 'LLM Prompt Injection',
              to: '/docs/ai-ml-security/llm-prompt-injection',
            },
          ],
        },
        {
          title: 'Community & Support',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/AnimeshShaw/AppSec-Atlas',
            },
            {
              label: 'Discord Community',
              href: 'https://discord.gg/NHvrkJ5Hg3',
            },
            {
              label: '💖 GitHub Sponsors',
              href: 'https://github.com/sponsors/AnimeshShaw',
            },
            {
              label: '☕ Buy Me a Coffee (Ko-fi)',
              href: 'https://ko-fi.com/animeshshaw',
            },
          ],
        },
        {
          title: 'Ecosystem & Tools',
          items: [
            {
              label: '🔐 DevCipher Platform',
              href: 'https://devcipher.dev/',
            },
            {
              label: '🤖 Agentic AI Security',
              href: 'https://github.com/AnimeshShaw/agentic-ai-security-guide',
            },
            {
              label: '🛡️ Threat Modelling Basics',
              href: 'https://github.com/AnimeshShaw/threat-modelling-basics',
            },
            {
              label: '⚛️ Quantum-Safe Py',
              href: 'https://github.com/AnimeshShaw/quantum-safe-py',
            },
            {
              label: '🔍 Quantum Safe Auditor',
              href: 'https://github.com/AnimeshShaw/quantum-safe-auditor',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Blog',
              to: '/blog',
            },
            {
              label: 'Contribute',
              href: 'https://github.com/AnimeshShaw/AppSec-Atlas/blob/main/CONTRIBUTING.md',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Animesh Shaw & AppSec Atlas Contributors. Licensed under CC BY 4.0.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['python', 'bash', 'json', 'yaml', 'sql', 'docker'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
