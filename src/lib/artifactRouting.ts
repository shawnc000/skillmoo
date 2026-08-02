export interface ArtifactRoutingIndex {
  cliVersion: string
  entries: readonly ({
    name: string
    status: 'pilot-ready'
    artifact: { artifactId: string; source: { pinnedUrl: string } }
  } | {
    name: string
    status: 'link-only'
    reason: string
  })[]
}

export interface ArtifactRoute {
  readyByName: Map<string, string>
  pinnedUrlByName: Map<string, string>
  rejectedByName: Map<string, string>
  allReady: boolean
}

export function completePackageRejectedNames(index: ArtifactRoutingIndex): Set<string> {
  return new Set(index.entries.flatMap((entry) => entry.status === 'link-only' && entry.reason === 'full-gate-failed' ? [entry.name] : []))
}

export function filterCompletePackageEligible<T extends { name: string }>(skills: readonly T[], index: ArtifactRoutingIndex): T[] {
  const rejected = completePackageRejectedNames(index)
  return skills.filter((skill) => !rejected.has(skill.name))
}

export function artifactRoute(skillNames: readonly string[], index: ArtifactRoutingIndex): ArtifactRoute {
  const requested = new Set(skillNames)
  const readyByName = new Map<string, string>()
  const pinnedUrlByName = new Map<string, string>()
  const rejectedByName = new Map<string, string>()
  for (const entry of index.entries) {
    if (!requested.has(entry.name)) continue
    if (entry.status === 'pilot-ready') {
      readyByName.set(entry.name, entry.artifact.artifactId)
      pinnedUrlByName.set(entry.name, entry.artifact.source.pinnedUrl)
    } else if (entry.reason === 'full-gate-failed') rejectedByName.set(entry.name, entry.reason)
  }
  return { readyByName, pinnedUrlByName, rejectedByName, allReady: skillNames.length > 0 && readyByName.size === skillNames.length }
}

export function artifactHandoffScript(options: {
  names: readonly string[]
  displayName: string
  language: 'en' | 'zh'
  index: ArtifactRoutingIndex
}): { route: ArtifactRoute; script: string } {
  const route = artifactRoute(options.names, options.index)
  if (!route.allReady) return {
    route,
    script: [
      options.language === 'zh' ? `# ${options.displayName} · 先下载并复核每个完整 Skill 目录，再生成不可变预览` : `# ${options.displayName} · download and review each COMPLETE Skill directory before preparing`,
      'skillmoo setup prepare \\',
      ...options.names.map((name) => `  --source "/absolute/path/to/${name}" \\`),
      '  --target-root ~/.claude/skills \\',
      '  --out ./skillmoo-setup.json',
      '',
      '# Review the JSON plan, then use its exact planId:',
      'skillmoo setup apply --plan ./skillmoo-setup.json --confirm <plan-id>',
    ].join('\n'),
  }
  return {
    route,
    script: [
      options.language === 'zh' ? `# ${options.displayName} · 固定完整产物，只生成安装预览` : `# ${options.displayName} · pinned complete artifacts; prepare only`,
      `npx skillmoo@${options.index.cliVersion} catalog inspect \\`,
      ...options.names.map((name, index) => `  --artifact ${route.readyByName.get(name)}${index === options.names.length - 1 ? '' : ' \\'}`),
      '',
      options.language === 'zh' ? '# 复核来源、摘要、许可证和限制后，再生成不可变安装计划：' : '# After reviewing source, digests, license, and limitations, prepare the immutable setup plan:',
      `npx skillmoo@${options.index.cliVersion} catalog prepare \\`,
      ...options.names.map((name) => `  --artifact ${route.readyByName.get(name)} \\`),
      '  --target-root ~/.claude/skills \\',
      '  --out ./skillmoo-setup.json',
      '',
      '# Review the JSON plan, then use its exact planId:',
      `npx skillmoo@${options.index.cliVersion} setup apply --plan ./skillmoo-setup.json --confirm <plan-id>`,
    ].join('\n'),
  }
}
