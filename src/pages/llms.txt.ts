import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import { features } from '../config/features';

const SITE_URL = 'https://kubernetes-security.cloud';

function toAbsoluteUrl(path: string): string {
  return `${SITE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}

export const GET: APIRoute = async () => {
  const generatedAt = new Date().toISOString();
  const topics = await getCollection('topics');
  const glossary = await getCollection('glossary');
  const attackPaths = features.attackPaths ? await getCollection('attack-paths') : [];

  const sortedTopics = [...topics].sort((a, b) => a.data.title.localeCompare(b.data.title));
  const sortedGlossary = [...glossary].sort((a, b) => a.data.title.localeCompare(b.data.title));
  const sortedAttackPaths = [...attackPaths].sort((a, b) => a.data.title.localeCompare(b.data.title));

  const offensiveTopics = sortedTopics.filter((topic) => topic.data.category === 'offensive');
  const defensiveTopics = sortedTopics.filter((topic) => topic.data.category === 'defensive');
  const fundamentalTopics = sortedTopics.filter((topic) => topic.data.category === 'fundamental');
  const offensivePhases = [...new Set(
    offensiveTopics
      .map((topic) => topic.data.phase ?? topic.data.offensiveType)
      .filter((phase): phase is string => Boolean(phase))
  )].sort();

  const lines: string[] = [
    '# kubernetes-security.cloud',
    '',
    '> Kubernetes security reference: topics (lessons), glossary terms, and optional attack-path diagrams.',
    '',
    `## Generated`,
    `- generatedAt: ${generatedAt}`,
    '',
    '## LLM usage notes',
    '- Prefer `topics.json` for structured topic metadata and filtering.',
    '- For offensive techniques, filter `category=offensive` then group/order by `phase`.',
    '- Use `/topics/<topic-slug>.md` when you need full markdown plus action checklist and commands.',
    '- `phase` is the canonical offensive classification field.',
    '- Glossary entries are HTML pages only (no raw `.md` mirror); fetch the page or use the sitemap.',
    '',
    '## Important URLs',
    `- Topics overview: ${toAbsoluteUrl('/topics')}`,
    `- Glossary overview: ${toAbsoluteUrl('/glossary')}`,
    `- Machine-readable topic index (JSON): ${toAbsoluteUrl('/topics.json')}`,
    `- Raw markdown topic endpoint pattern: ${toAbsoluteUrl('/topics/<topic-slug>.md')}`,
    `- Sitemap: ${toAbsoluteUrl('/sitemap-index.xml')}`,
    ...(features.attackPaths
      ? [`- Attack paths overview: ${toAbsoluteUrl('/attack-paths')}`]
      : []),
    '',
    '## Topic totals',
    `- Total topics: ${sortedTopics.length}`,
    `- Offensive topics: ${offensiveTopics.length}`,
    `- Defensive topics: ${defensiveTopics.length}`,
    `- Fundamental topics: ${fundamentalTopics.length}`,
    '',
    '## Offensive phase index',
    ...offensivePhases.map((phase) => {
      const phaseTopics = offensiveTopics.filter((topic) => (topic.data.phase ?? topic.data.offensiveType) === phase);
      return `- ${phase}: ${phaseTopics.length} topic(s)`;
    }),
    '',
    '## Topic pages',
    ...sortedTopics.map((topic) => {
      const phaseValue = topic.data.phase ?? topic.data.offensiveType ?? 'n/a';
      return `- ${toAbsoluteUrl(`/topics/${topic.slug}`)} | markdown: ${toAbsoluteUrl(`/topics/${topic.slug}.md`)} | category: ${topic.data.category} | phase: ${phaseValue} | ${topic.data.title} | ${topic.data.description}`;
    }),
    '',
    '## Glossary totals',
    `- Total glossary entries: ${sortedGlossary.length}`,
    '',
    '## Glossary pages',
    ...sortedGlossary.map((entry) => {
      return `- ${toAbsoluteUrl(`/glossary/${entry.slug}`)} | category: ${entry.data.category} | ${entry.data.title} | ${entry.data.description}`;
    }),
    ...(features.attackPaths && sortedAttackPaths.length > 0
      ? [
          '',
          '## Attack path pages',
          ...sortedAttackPaths.map((path) => {
            return `- ${toAbsoluteUrl(`/attack-paths/${path.id}`)} | category: ${path.data.category} | ${path.data.title} | ${path.data.description}`;
          }),
        ]
      : []),
    '',
  ];

  return new Response(lines.join('\n'), {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Cache-Control': 'public, max-age=300',
    },
  });
};
