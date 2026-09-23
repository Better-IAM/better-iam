import packages from '@/generated/packages.json';
import { Mermaid } from '@/components/mermaid';

/**
 * The internal dependency graph of the workspace packages, built from their manifests. The umbrella package
 * depends on everything, so it is left out to keep the graph readable.
 */
export function PackageGraph() {
  const id = (name: string) => name.replace('@better-iam/', '').replace(/[^a-z0-9]/gi, '_');
  const label = (name: string) => name.replace('@better-iam/', '');
  const lines = ['flowchart BT'];
  for (const pkg of packages) {
    if (pkg.name === 'better-iam') continue;
    lines.push(`  ${id(pkg.name)}["${label(pkg.name)}"]`);
  }
  for (const pkg of packages) {
    if (pkg.name === 'better-iam') continue;
    for (const dependency of pkg.internalDependencies)
      lines.push(`  ${id(pkg.name)} --> ${id(dependency)}`);
  }
  return <Mermaid chart={lines.join('\n')} />;
}
