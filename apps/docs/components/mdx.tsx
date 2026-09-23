import defaultMdxComponents from 'fumadocs-ui/mdx';
import { Accordion, Accordions } from 'fumadocs-ui/components/accordion';
import { File, Files, Folder } from 'fumadocs-ui/components/files';
import { ImageZoom } from 'fumadocs-ui/components/image-zoom';
import { Step, Steps } from 'fumadocs-ui/components/steps';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import { TypeTable } from 'fumadocs-ui/components/type-table';
import * as Twoslash from 'fumadocs-twoslash/ui';
import type { MDXComponents } from 'mdx/types';
import type { ComponentProps } from 'react';
import { Mermaid } from '@/components/mermaid';
import { ApiEndpoint, ApiGroupSummary } from '@/components/api-reference';
import { ApiShape } from '@/components/api-shape';
import { FeatureGrid, Feature } from '@/components/feature-grid';
import { PackageTable } from '@/components/package-table';
import { PackageGraph } from '@/components/package-graph';
import { Term } from '@/components/term';
import { TryInPlayground } from '@/components/try-in-playground';

export function getMDXComponents(components?: MDXComponents) {
  return {
    ...defaultMdxComponents,
    ...Twoslash,
    img: (props: ComponentProps<'img'>) => (
      <ImageZoom {...(props as ComponentProps<typeof ImageZoom>)} />
    ),
    Tabs,
    Tab,
    Steps,
    Step,
    Accordion,
    Accordions,
    Files,
    Folder,
    File,
    TypeTable,
    Mermaid,
    ApiEndpoint,
    ApiGroupSummary,
    ApiShape,
    FeatureGrid,
    Feature,
    PackageTable,
    PackageGraph,
    Term,
    TryInPlayground,
    ...components,
  } satisfies MDXComponents;
}

export const useMDXComponents = getMDXComponents;

declare global {
  type MDXProvidedComponents = ReturnType<typeof getMDXComponents>;
}
