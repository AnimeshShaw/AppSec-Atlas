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

  url: 'https://appsecatlas.com',
  baseUrl: '/',

  organizationName: 'AnimeshShaw',
  projectName: 'AppSec-Atlas',

  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

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
          href: 'https://discord.gg/appsecatlas',
          label: '💬 Discord',
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
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/AnimeshShaw/AppSec-Atlas',
            },
            {
              label: 'Discord',
              href: 'https://discord.gg/appsecatlas',
            },
            {
              label: 'Twitter / X',
              href: 'https://x.com/appsecatlas',
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
