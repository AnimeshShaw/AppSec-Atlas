import React from 'react';
import Head from '@docusaurus/Head';
import {useLocation} from '@docusaurus/router';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';

// Injects JSON-LD structured data on every page
export default function Root({children}: {children: React.ReactNode}) {
  const {siteConfig} = useDocusaurusContext();
  const location = useLocation();
  const url = `${siteConfig.url}${location.pathname}`;

  const websiteSchema = {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    name: 'AppSec Atlas',
    url: 'https://appsecatlas.com',
    description: 'The World\'s Most Comprehensive Open-Source Application Security Knowledge Base',
    potentialAction: {
      '@type': 'SearchAction',
      target: {
        '@type': 'EntryPoint',
        urlTemplate: 'https://appsecatlas.com/search?q={search_term_string}',
      },
      'query-input': 'required name=search_term_string',
    },
  };

  const organizationSchema = {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'AppSec Atlas',
    url: 'https://appsecatlas.com',
    logo: 'https://appsecatlas.com/img/logo.png',
    sameAs: [
      'https://github.com/AnimeshShaw/AppSec-Atlas',
      'https://discord.gg/NHvrkJ5Hg3',
      'https://github.com/sponsors/AnimeshShaw',
    ],
    founder: {
      '@type': 'Person',
      name: 'Animesh Shaw',
      url: 'https://github.com/AnimeshShaw',
    },
  };

  const breadcrumbSchema = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: location.pathname
      .split('/')
      .filter(Boolean)
      .map((segment, index, arr) => ({
        '@type': 'ListItem',
        position: index + 1,
        name: segment
          .replace(/-/g, ' ')
          .replace(/\b\w/g, (c) => c.toUpperCase()),
        item: `${siteConfig.url}/${arr.slice(0, index + 1).join('/')}`,
      })),
  };

  return (
    <>
      <Head>
        <script type="application/ld+json">
          {JSON.stringify(websiteSchema)}
        </script>
        <script type="application/ld+json">
          {JSON.stringify(organizationSchema)}
        </script>
        {location.pathname.startsWith('/docs/') && (
          <script type="application/ld+json">
            {JSON.stringify(breadcrumbSchema)}
          </script>
        )}
        <link rel="canonical" href={url} />
      </Head>
      {children}
    </>
  );
}
