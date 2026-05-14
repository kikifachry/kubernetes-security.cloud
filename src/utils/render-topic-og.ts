import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Resvg } from '@resvg/resvg-js';
import satori from 'satori';
import { TOPIC_OG_HEIGHT, TOPIC_OG_WIDTH } from '../config/topic-og';

const OG_WIDTH = TOPIC_OG_WIDTH;
const OG_HEIGHT = TOPIC_OG_HEIGHT;

/** Body / meta font for OG PNGs (Google Fonts via Fontsource). */
const OG_FONT_FAMILY = 'Inter';

/** Title: Space Grotesk. Description + category/phase labels: DM Sans. Footer: Inter. */
const TITLE_FONT_FAMILY = 'Space Grotesk';
const TITLE_FONT_WEIGHT = 700;
const DESCRIPTION_FONT_FAMILY = 'DM Sans';
const DESCRIPTION_FONT_WEIGHT = 400;
const LABEL_FONT_WEIGHT = 600;

type SatoriNode = {
  type: string;
  props: {
    style?: Record<string, unknown>;
    children?: SatoriNode | SatoriNode[] | string | number | (SatoriNode | string | number | null | undefined)[];
    [key: string]: unknown;
  };
};

const categoryOgStyle: Record<
  string,
  {
    pillBg: string;
    pillText: string;
    accent: string;
    glow: string;
    canvasBg: string;
    stripe: string;
    footerBorder: string;
    descriptionColor: string;
  }
> = {
  offensive: {
    pillBg: 'rgba(220, 38, 38, 0.22)',
    pillText: '#fecaca',
    accent: '#ef4444',
    glow: 'rgba(239, 68, 68, 0.32)',
    canvasBg: '#0c0a0a',
    stripe: 'rgba(248, 113, 113, 0.065)',
    footerBorder: '1px solid rgba(248, 113, 113, 0.28)',
    descriptionColor: '#fecdd3',
  },
  defensive: {
    pillBg: 'rgba(37, 99, 235, 0.28)',
    pillText: '#bfdbfe',
    accent: '#3b82f6',
    glow: 'rgba(59, 130, 246, 0.34)',
    canvasBg: '#020617',
    stripe: 'rgba(56, 189, 248, 0.075)',
    footerBorder: '1px solid rgba(56, 189, 248, 0.3)',
    descriptionColor: '#bae6fd',
  },
  fundamental: {
    pillBg: 'rgba(113, 113, 122, 0.35)',
    pillText: '#e4e4e7',
    accent: '#a78bfa',
    glow: 'rgba(167, 139, 250, 0.22)',
    canvasBg: '#09090b',
    stripe: 'rgba(196, 181, 253, 0.065)',
    footerBorder: '1px solid rgba(167, 139, 250, 0.28)',
    descriptionColor: '#d4d4d8',
  },
};

const defaultCategoryStyle = categoryOgStyle.fundamental;

function normalizeCategory(category: string): 'offensive' | 'defensive' | 'fundamental' {
  if (category === 'offensive' || category === 'defensive' || category === 'fundamental') {
    return category;
  }
  return 'fundamental';
}

/** Full-bleed background stack tuned per topic category (offensive vs defensive vs fundamental). */
function categoryBackgroundImage(category: 'offensive' | 'defensive' | 'fundamental', glow: string): string {
  if (category === 'offensive') {
    return [
      `radial-gradient(ellipse 94% 76% at 100% -6%, ${glow} 0%, transparent 55%)`,
      'radial-gradient(ellipse 64% 52% at -10% 108%, rgba(251, 146, 60, 0.14) 0%, transparent 56%)',
      'radial-gradient(ellipse 54% 46% at 76% 98%, rgba(127, 29, 29, 0.35) 0%, transparent 60%)',
      'linear-gradient(118deg, transparent 34%, rgba(255, 255, 255, 0.045) 46%, transparent 58%)',
      'linear-gradient(158deg, #0a0505 0%, #1a0a0e 28%, #2a1218 52%, #1a0c10 78%, #080505 100%)',
    ].join(', ');
  }
  if (category === 'defensive') {
    return [
      `radial-gradient(ellipse 94% 76% at 100% -6%, ${glow} 0%, transparent 55%)`,
      'radial-gradient(ellipse 66% 54% at -10% 108%, rgba(34, 211, 238, 0.16) 0%, transparent 56%)',
      'radial-gradient(ellipse 56% 46% at 74% 98%, rgba(30, 64, 175, 0.38) 0%, transparent 60%)',
      'linear-gradient(118deg, transparent 34%, rgba(255, 255, 255, 0.05) 46%, transparent 58%)',
      'linear-gradient(162deg, #020617 0%, #082f49 26%, #0c4a6e 52%, #082f49 78%, #020617 100%)',
    ].join(', ');
  }
  return [
    `radial-gradient(ellipse 90% 72% at 100% -5%, ${glow} 0%, transparent 52%)`,
    'radial-gradient(ellipse 58% 48% at -8% 104%, rgba(161, 161, 170, 0.14) 0%, transparent 54%)',
    'radial-gradient(ellipse 52% 42% at 72% 96%, rgba(99, 102, 241, 0.2) 0%, transparent 58%)',
    'linear-gradient(115deg, transparent 36%, rgba(255, 255, 255, 0.04) 48%, transparent 58%)',
    'linear-gradient(162deg, #09090b 0%, #12101f 34%, #1a1530 60%, #0c0c12 100%)',
  ].join(', ');
}

type OgFontEntry = { name: string; data: Buffer; weight: number; style: 'normal' };

type OgFontBundle = {
  fonts: OgFontEntry[];
  titleFontFamily: string;
  titleFontWeight: number;
};

let ogFontBundle: OgFontBundle | null = null;

function getOgFontBundle(): OgFontBundle {
  if (ogFontBundle) return ogFontBundle;

  const cwd = process.cwd();
  const interBase = join(cwd, 'node_modules/@fontsource/inter/files');
  const spaceGroteskBase = join(cwd, 'node_modules/@fontsource/space-grotesk/files');
  const dmSansBase = join(cwd, 'node_modules/@fontsource/dm-sans/files');

  const fonts: OgFontEntry[] = [
    { name: OG_FONT_FAMILY, data: readFileSync(join(interBase, 'inter-latin-400-normal.woff')), weight: 400, style: 'normal' },
    { name: OG_FONT_FAMILY, data: readFileSync(join(interBase, 'inter-latin-600-normal.woff')), weight: 600, style: 'normal' },
    { name: OG_FONT_FAMILY, data: readFileSync(join(interBase, 'inter-latin-700-normal.woff')), weight: 700, style: 'normal' },
    {
      name: DESCRIPTION_FONT_FAMILY,
      data: readFileSync(join(dmSansBase, 'dm-sans-latin-400-normal.woff')),
      weight: DESCRIPTION_FONT_WEIGHT,
      style: 'normal',
    },
    {
      name: DESCRIPTION_FONT_FAMILY,
      data: readFileSync(join(dmSansBase, 'dm-sans-latin-600-normal.woff')),
      weight: LABEL_FONT_WEIGHT,
      style: 'normal',
    },
    {
      name: TITLE_FONT_FAMILY,
      data: readFileSync(join(spaceGroteskBase, 'space-grotesk-latin-700-normal.woff')),
      weight: TITLE_FONT_WEIGHT,
      style: 'normal',
    },
  ];

  ogFontBundle = {
    fonts,
    titleFontFamily: TITLE_FONT_FAMILY,
    titleFontWeight: TITLE_FONT_WEIGHT,
  };
  return ogFontBundle;
}

function formatPhase(phase?: string | null): string | null {
  if (!phase) return null;
  return phase
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function truncate(text: string, max: number): string {
  const t = text.trim();
  if (t.length <= max) return t;
  return `${t.slice(0, max - 1).trimEnd()}…`;
}

function buildTree(input: {
  title: string;
  description: string;
  category: string;
  phase?: string | null;
}): SatoriNode {
  const { titleFontFamily, titleFontWeight } = getOgFontBundle();
  const cat = normalizeCategory(input.category);
  const style = categoryOgStyle[cat] ?? defaultCategoryStyle;
  const phaseLabel = formatPhase(input.phase ?? undefined);

  const headerChildren: (SatoriNode | string)[] = [
    {
      type: 'div',
      props: {
        style: {
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          gap: 14,
          fontFamily: DESCRIPTION_FONT_FAMILY,
        },
        children: [
          {
            type: 'div',
            props: {
              style: {
                backgroundColor: style.pillBg,
                color: style.pillText,
                padding: '10px 18px',
                borderRadius: 10,
                fontSize: 22,
                fontWeight: LABEL_FONT_WEIGHT,
                fontFamily: DESCRIPTION_FONT_FAMILY,
                textTransform: 'capitalize' as const,
              },
              children: input.category,
            },
          },
          ...(phaseLabel
            ? [
                {
                  type: 'div',
                  props: {
                    style: {
                      backgroundColor: 'rgba(255, 255, 255, 0.06)',
                      color: '#d4d4d8',
                      padding: '10px 18px',
                      borderRadius: 10,
                      fontSize: 20,
                      fontWeight: LABEL_FONT_WEIGHT,
                      fontFamily: DESCRIPTION_FONT_FAMILY,
                    },
                    children: phaseLabel,
                  },
                } as SatoriNode,
              ]
            : []),
        ],
      },
    },
  ];

  return {
    type: 'div',
    props: {
      style: {
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        width: `${OG_WIDTH}px`,
        height: `${OG_HEIGHT}px`,
        backgroundColor: style.canvasBg,
        backgroundImage: categoryBackgroundImage(cat, style.glow),
        padding: 56,
        position: 'relative' as const,
      },
      children: [
        {
          type: 'div',
          props: {
            style: {
              position: 'absolute',
              top: 0,
              left: 0,
              width: `${OG_WIDTH}px`,
              height: `${OG_HEIGHT}px`,
              zIndex: 0,
              opacity: 0.45,
              backgroundImage: `repeating-linear-gradient(-12deg, transparent, transparent 104px, ${style.stripe} 104px, ${style.stripe} 105px)`,
            },
          },
        },
        {
          type: 'div',
          props: {
            style: {
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 6,
              zIndex: 2,
              backgroundColor: style.accent,
            },
          },
        },
        {
          type: 'div',
          props: {
            style: {
              display: 'flex',
              flexDirection: 'column',
              flex: 1,
              position: 'relative' as const,
              zIndex: 1,
              paddingTop: 12,
              gap: 28,
            },
            children: [
              ...headerChildren,
              {
                type: 'div',
                props: {
                  style: {
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 20,
                    flex: 1,
                    justifyContent: 'center',
                  },
                  children: [
                    {
                      type: 'div',
                      props: {
                        style: {
                          color: '#fafafa',
                          fontSize: 56,
                          fontWeight: titleFontWeight,
                          lineHeight: 1.08,
                          letterSpacing: -1.4,
                          fontFamily: titleFontFamily,
                          maxWidth: 1080,
                          textShadow:
                            cat === 'offensive'
                              ? '0 2px 28px rgba(0, 0, 0, 0.6), 0 0 40px rgba(239, 68, 68, 0.12)'
                              : cat === 'defensive'
                                ? '0 2px 28px rgba(0, 0, 0, 0.6), 0 0 40px rgba(56, 189, 248, 0.1)'
                                : '0 2px 28px rgba(0, 0, 0, 0.55), 0 0 40px rgba(167, 139, 250, 0.1)',
                        },
                        children: truncate(input.title, 120),
                      },
                    },
                    {
                      type: 'div',
                      props: {
                        style: {
                          color: style.descriptionColor,
                          fontSize: 28,
                          lineHeight: 1.45,
                          letterSpacing: 0.15,
                          fontWeight: DESCRIPTION_FONT_WEIGHT,
                          fontFamily: DESCRIPTION_FONT_FAMILY,
                          maxWidth: 1040,
                        },
                        children: truncate(input.description, 220),
                      },
                    },
                  ],
                },
              },
            ],
          },
        },
        {
          type: 'div',
          props: {
            style: {
              display: 'flex',
              flexDirection: 'row',
              justifyContent: 'flex-end',
              alignItems: 'center',
              position: 'relative' as const,
              zIndex: 1,
              borderTop: style.footerBorder,
              paddingTop: 24,
              marginTop: 8,
            },
            children: [
              {
                type: 'div',
                props: {
                  style: {
                    color: '#a1a1aa',
                    fontSize: 22,
                    fontWeight: 600,
                    fontFamily: OG_FONT_FAMILY,
                  },
                  children: 'kubernetes-security.cloud',
                },
              },
            ],
          },
        },
      ],
    },
  };
}

export async function renderTopicOgPng(input: {
  title: string;
  description: string;
  category: string;
  phase?: string | null;
}): Promise<Uint8Array> {
  const { fonts } = getOgFontBundle();
  const svg = await satori(buildTree(input) as Parameters<typeof satori>[0], {
    width: OG_WIDTH,
    height: OG_HEIGHT,
    fonts: fonts.map((f) => ({
      name: f.name,
      data: f.data,
      weight: f.weight,
      style: f.style,
    })),
  });

  const resvg = new Resvg(svg, {
    fitTo: { mode: 'original' },
    font: { loadSystemFonts: false },
  });
  return resvg.render().asPng();
}
