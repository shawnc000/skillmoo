/**
 * build-cli — bundle the CLI into a single, dependency-free, publishable file.
 *
 * The CLI (cli/index.ts) reuses the framework-free engine in src/lib/*. esbuild
 * inlines all of it into one Node ESM file with a shebang, so the published
 * `skillmoo` package has ZERO runtime dependencies and `npx skillmoo` just works.
 */
import { build } from 'esbuild'
import { chmodSync, mkdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const outfile = join(root, 'bin', 'skillmoo.mjs')
mkdirSync(dirname(outfile), { recursive: true })

// Single source of truth for the CLI version: this package.json (no drift with npm).
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version
const artifactIndex = JSON.parse(readFileSync(join(root, 'catalog', 'v2', 'index.json'), 'utf8'))
if (artifactIndex.cliVersion !== version) {
  throw new Error(`catalog CLI version ${artifactIndex.cliVersion} does not match package version ${version}`)
}

await build({
  entryPoints: [join(root, 'cli', 'index.ts')],
  outfile,
  bundle: true,
  platform: 'node',
  target: 'node18',
  format: 'esm',
  banner: { js: '#!/usr/bin/env node' },
  legalComments: 'none',
  define: { __CLI_VERSION__: JSON.stringify(version) },
  logLevel: 'info',
})

chmodSync(outfile, 0o755)
console.log('build-cli: bundled cli/index.ts → bin/skillmoo.mjs')
