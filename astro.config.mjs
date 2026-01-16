import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import yaml from '@rollup/plugin-yaml';

// https://astro.build/config
export default defineConfig({
  site: 'https://kubernetes-security.cloud',
  integrations: [tailwind(), mdx(), sitemap()],
  markdown: {
    shikiConfig: {
      theme: 'github-dark',
      wrap: true,
      transformers: [
        {
          pre(node) {
            // Add data-language attribute to pre element for CSS targeting
            const lang = this.options.lang || '';
            node.properties['data-language'] = lang;
          }
        }
      ]
    }
  },
  vite: {
    plugins: [yaml()]
  }
});
