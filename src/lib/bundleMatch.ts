/**
 * Goal → smart-match a custom skill combo. PURE + framework-free so it is unit-testable
 * (scripts/eval-bundles.ts locks it) and shared by the homepage BundlesSection.
 *
 * Deterministic keyword/intent match — NO model. Skill text is English, so a Chinese
 * goal can't token-match it directly; INTENT maps zh+en goal phrases to the English
 * DOMAIN tokens that actually appear in skill name/description. (The deep semantic
 * match is the Pro/model tier; this is the honest, free, deterministic version.)
 *
 * THE BUG THIS FIXES: the old matcher searched the seed store ONLY and had no business
 * INTENT rows, so every marketing / SaaS / creator goal — the site's own advertised
 * combos — scored zero in BOTH languages. Fix = search BOTH pools + business/creator
 * INTENT rows below.
 */
import type { StoreSkill } from '@/data/seedSkills'
import { isAutoMatchEligible } from './skillTrust'

const STOP = new Set(['the', 'and', 'for', 'with', 'when', 'use', 'this', 'that', 'your', 'you', 'from', 'into', 'make', 'build', 'want', 'need', 'skill', 'skills', 'using', 'app', 'apps', 'a', 'an', 'to', 'of', 'in', 'on', 'or', 'my'])

/** Latin words ≥3 chars, minus stop-words. (CJK yields nothing here — that is why zh
 *  goals rely on the INTENT table below to produce English tags.) */
export function toks(s: string): Set<string> {
  const out = new Set<string>()
  for (const w of (s.toLowerCase().match(/[a-z]{3,}/g) ?? [])) if (!STOP.has(w)) out.add(w)
  return out
}

export const INTENT: { re: RegExp; tags: string[] }[] = [
  { re: /网站|网页|前端|界面|页面|落地页|\bweb\b|frontend|website|landing|\bui\b/i, tags: ['frontend', 'web', 'design', 'artifact', 'html', 'react', 'component'] },
  { re: /设计|视觉|品牌|配色|主题|排版|design|brand|visual|theme|color|typograph/i, tags: ['design', 'visual', 'brand', 'theme', 'color', 'canvas', 'typography'] },
  { re: /文案|写作|内容|撰写|博客|文章|沟通|writ|content|copy|blog|article|draft|comms|communicat/i, tags: ['writing', 'content', 'draft', 'comms', 'communicate', 'coauthor'] },
  { re: /文档|word|报告|docx|document|report/i, tags: ['docx', 'document', 'word'] },
  { re: /\bpdf\b/i, tags: ['pdf'] },
  { re: /表格|excel|电子表|spreadsheet|数据表|xlsx/i, tags: ['xlsx', 'spreadsheet'] },
  { re: /幻灯|演示文稿|\bppt|slide|presentation|pptx|deck/i, tags: ['pptx', 'slide', 'presentation'] },
  { re: /agent|智能体|代理|多智能体|编排|orchestrat|\bmcp\b|工具调用/i, tags: ['agent', 'mcp', 'tool', 'sdk', 'subagent', 'parallel', 'orchestrat', 'server', 'protocol', 'builder'] },
  { re: /\bapi\b|接口|后端|backend|claude.?api|anthropic/i, tags: ['api', 'sdk', 'backend', 'claude', 'anthropic'] },
  { re: /cloudflare|边缘|worker|wrangler|edge|部署|上线|deploy|ship/i, tags: ['cloudflare', 'worker', 'edge', 'wrangler', 'deploy', 'durable'] },
  { re: /数据库|存储|database|storage|durable|状态|stateful/i, tags: ['durable', 'storage', 'object', 'stateful'] },
  { re: /测试|调试|排错|评审|审查|验收|质量|回归|test|debug|\bqa\b|review|verif/i, tags: ['test', 'review', 'debug', 'verification', 'driven', 'systematic'] },
  { re: /代码评审|合并请求|拉取请求|\bpr\b|pull.?request|code.?review/i, tags: ['code', 'review', 'pull', 'request', 'verification'] },
  { re: /计划|规划|方案|头脑风暴|构思|想法|策划|需求|brainstorm|plan|planning|idea|strateg|requirement/i, tags: ['plan', 'brainstorm', 'planning', 'idea', 'requirement'] },
  { re: /\bgit\b|分支|版本|worktree|branch|提交|commit/i, tags: ['git', 'worktree', 'branch'] },
  { re: /技能|\bskill\b|做技能|写技能/i, tags: ['skill', 'creator'] },
  { re: /安全|漏洞|security|secure|\bsafe\b|vulnerab/i, tags: ['security', 'safe', 'vulnerab'] },
  { re: /艺术|生成艺术|\bart\b|generative|creative.?coding|\bp5\b/i, tags: ['art', 'algorithmic', 'generative', 'canvas'] },
  // --- business / marketing / growth / creator (the curated B+ pool) ---
  // Tags are the ENGLISH tokens that actually appear in those skills' name/description,
  // so a zh business query (营销 / 增长 / 自媒体 …) scores a real hit instead of nothing.
  { re: /营销|推广|市场营销|获客|品牌推广|marketing|promot|campaign/i, tags: ['marketing', 'ideas', 'growth', 'campaign', 'psychology', 'launch'] },
  // narrow business rows carry the broad 'marketing' / 'product' token too, so even a
  // one-word goal (SEO / 邮件 / 路线图) forms a ≥2 combo instead of a lone skill.
  { re: /\bseo\b|搜索引擎优化|自然流量|排名|收录|关键词|ranking|organic/i, tags: ['seo', 'audit', 'ranking', 'technical', 'meta', 'page', 'marketing'] },
  { re: /邮件|邮箱营销|\bedm\b|drip|newsletter|email|nurtur|营销序列/i, tags: ['email', 'sequence', 'drip', 'nurtur', 'campaign', 'lifecycle', 'marketing'] },
  { re: /发布|上线|发售|冷启动|go.?to.?market|\bgtm\b|launch|release|announcement|product.?hunt/i, tags: ['launch', 'strategy', 'release', 'announcement', 'product', 'marketing'] },
  { re: /增长|留存|流失|转化|裂变|复购|growth|retention|churn|conversion|acquisition/i, tags: ['growth', 'retention', 'churn', 'cohort', 'adoption', 'marketing'] },
  { re: /saas|订阅|续费|营收|收入|财务|\barr\b|\bmrr\b|\bltv\b|\bcac\b|\bnrr\b|指标|\bkpi\b|metric|revenue|finance/i, tags: ['saas', 'metrics', 'arr', 'mrr', 'churn', 'ltv', 'cac', 'revenue', 'financial', 'analytics', 'kpis'] },
  { re: /数据分析|产品分析|漏斗|同期群|留存分析|dashboard|analytics|cohort|adoption|funnel/i, tags: ['analytics', 'product', 'cohort', 'retention', 'adoption', 'metric', 'dashboards'] },
  { re: /路线图|产品路线|变更日志|更新日志|发布说明|roadmap|changelog|release.?notes|stakeholder|对外沟通/i, tags: ['roadmap', 'release', 'notes', 'changelogs', 'stakeholder', 'narratives', 'product'] },
  { re: /自媒体|新媒体|内容创作|博主|网红|涨粉|社媒|社交媒体|公众号|小红书|抖音|快手|视频号|creator|influencer|social.?media/i, tags: ['social', 'content', 'media', 'posts', 'creating', 'platforms', 'linkedin', 'twitter', 'instagram', 'tiktok'] },
  { re: /短视频|视频脚本|视频文案|口播|拍视频|\bvlog\b|reel|shorts?|tiktok|油管|youtube|视频内容/i, tags: ['video', 'content', 'scripts', 'youtube', 'reels', 'shorts', 'strategy', 'form'] },
  { re: /文案|带货|种草|标题党?|钩子|\bhook\b|copywrit/i, tags: ['content', 'psychology', 'persuasion', 'marketing', 'social', 'posts'] },
  // e-commerce / comic / music — the pinned external curated skills (see build-curated.ts).
  { re: /电商|网店|店铺|开店|独立站|跨境|选品|上架|商品详情|shopify|ecommerce|e-commerce|online.?store|storefront/i, tags: ['shopify', 'store', 'commerce', 'product', 'taxonomy', 'seo', 'landing', 'ecom'] },
  { re: /漫画|漫剧|条漫|绘本|连环画|manhwa|manga|webtoon|\bcomic|分镜|storyboard|角色设定/i, tags: ['comic', 'manhwa', 'webtoon', 'panel', 'story', 'storyboard', 'art', 'chapter', 'script'] },
  { re: /音乐|作曲|编曲|歌曲|歌词|作词|配乐|混音|\bsuno\b|udio|\bmusic\b|\bsong\b|lyric|melody/i, tags: ['music', 'suno', 'lyric', 'song', 'album', 'audio', 'mastering', 'genres', 'prompts'] },
  // --- NEW DOMAIN ROWS (community A/B gate-pass pool) --------------------------------
  // Every tag below is VERIFIED to appear in ≥1 target skill's name/description; every
  // row was probe-tested (zh + en) to yield a ≥2-skill combo from the expanded pool.
  // --- conversion & funnel ---
  { re: /转化率|转化优化|提高转化|弹窗|表单优化|注册流程|激活率|付费墙|升级弹窗|a\/?b\s*(测试|test)|\bcro\b|conversion|activation|split.?test|multivariate|popup|modal|paywall|signup.?flow|first.?run/i, tags: ['cro', 'conversion', 'conversions', 'optimize', 'popup', 'signup', 'onboarding', 'paywall', 'activation', 'test', 'marketing'] },
  { re: /投放|广告|买量|信息流|投流|\bppc\b|\bsem\b|paid.?(ads?|media|advertis|social)|google.?ads|meta.?ads|facebook.?ads|ad.?(copy|creative|campaign)|advertis/i, tags: ['ads', 'paid', 'advertising', 'creative', 'campaigns', 'headlines', 'marketing'] },
  { re: /冷邮件|开发信|陌生开发|外呼|销售线索|获客邮件|cold.?(email|outreach|call)|outbound|prospect|lead.?gen/i, tags: ['cold', 'outreach', 'emails', 'prospects', 'sales', 'sequence', 'marketing'] },
  { re: /裂变|老带新|转介绍|推荐计划|返佣|联盟营销|referral|affiliate|word.?of.?mouth|refer.?a.?friend/i, tags: ['referral', 'affiliate', 'program', 'incentive', 'growth', 'marketing'] },
  { re: /落地页|着陆页|官网页面|建站|做官网|landing.?page|hero.?section|pricing.?page/i, tags: ['landing', 'pages', 'page', 'hero', 'tailwind', 'react', 'conversion', 'marketing'] },
  { re: /结构化数据|富摘要|站点结构|内链|网站架构|收录问题|schema|structured.?data|json.?ld|rich.?(results|snippets)|sitemap|internal.?link|site.?architecture|url.?structure/i, tags: ['schema', 'structured', 'markup', 'seo', 'site', 'architecture', 'linking', 'audit'] },
  { re: /应用商店|上架app|应用排名|\baso\b|app.?store|google.?play/i, tags: ['aso', 'store', 'keywords', 'rankings', 'metadata', 'visibility', 'optimization'] },
  // --- business & money ---
  { re: /定价|价格策略|涨价|收费方案|货币化|monetiz|pricing|price.?increase|升级付费/i, tags: ['pricing', 'tiers', 'paywall', 'saas', 'value', 'upgrade', 'revenue', 'strategy'] },
  { re: /预测|营收预测|销售预测|业绩预测|forecast|bookings|projection|pipeline.?(forecast|review)/i, tags: ['forecast', 'bookings', 'arr', 'projection', 'pipeline', 'quarterly', 'revenue'] },
  { re: /并购|收购|尽调|估值|融资|投资分析|资本配置|m&a|merger|acquisition|due.?diligence|valuation|invest|fundrais|capital/i, tags: ['acquisition', 'investment', 'valuation', 'diligence', 'capital', 'deal', 'business', 'financial'] },
  { re: /客户成功|客户留存|客户流失|续约|客服体系|customer.?(success|retention|support)|churn|\bnps\b|renewal/i, tags: ['retention', 'customer', 'churn', 'segmentation', 'onboarding', 'activation'] },
  // --- founder / executive (the big community cluster) ---
  { re: /创始人|老板|高管|董事会|投资人汇报|战略会|founder|c.?suite|c.?level|\bceo\b|\bboard\b|executive|chief.?of.?staff|investor.?update/i, tags: ['founder', 'board', 'suite', 'executive', 'chief', 'strategic', 'advisor', 'decision'] },
  { re: /决策|拍板|抉择|艰难决定|取舍|两难|decision|hard.?call|trade.?off|regret/i, tags: ['decision', 'decisions', 'strategic', 'assumptions', 'framework', 'plan', 'options'] },
  { re: /竞品|竞争对手|对标|市场调研|行业分析|competitor|competitive|battlecard|market.?research|positioning/i, tags: ['competitor', 'competitive', 'intelligence', 'positioning', 'research', 'market', 'analysis'] },
  { re: /调研|研究报告|深度研究|查资料|文献|多源|求证|research|investigat|triangulat|literature|evidence/i, tags: ['research', 'sources', 'investigation', 'question', 'analysis', 'competitive'] },
  { re: /出海|国际化|海外市场|跨境扩张|全球化|international|expansion|go.?global|localiz|new.?countr/i, tags: ['international', 'expansion', 'market', 'localization', 'regulatory', 'strategy', 'region'] },
  // --- org & ops ---
  { re: /内部沟通|团队沟通|周报|月报|全员信|公司通讯|状态汇报|internal.?comm|team.?comm|status.?(update|report)|company.?wide|all.?hands|incident.?report/i, tags: ['internal', 'communications', 'updates', 'company', 'status', 'reports', 'newsletters'] },
  { re: /收件箱|邮箱整理|清理邮件|理邮件|inbox|triage/i, tags: ['inbox', 'triage', 'email', 'communications'] },
  { re: /流程管理|运营管理|供应商|采购|\bsop\b|业务流程|降本增效|operations|process.?doc|vendor|procurement|capacity.?plan|runbook/i, tags: ['operations', 'business', 'process', 'internal', 'vendor', 'documentation', 'planning'] },
  { re: /组织变革|变革管理|企业文化|公司文化|价值观|团队文化|change.?management|culture|values|organizational|adkar/i, tags: ['culture', 'change', 'management', 'company', 'values', 'organizational', 'behaviors'] },
  { re: /合规|质量体系|质量管理|医疗器械|体系认证|风险管理|\biso\s?\d|\bqms\b|complian|regulatory|medical.?device|13485|14971|risk.?management/i, tags: ['quality', 'iso', 'compliance', 'regulatory', 'risk', 'management', 'device', 'audit'] },
  // --- craft & process ---
  { re: /挑战我|盘问|压力测试|唱反调|泼冷水|红队|找茬|质疑|stress.?test|devil.?s.?advocate|grill|adversarial|critique|pre.?mortem|premortem|poke.?holes/i, tags: ['stress', 'plan', 'assumptions', 'adversarial', 'review', 'critique', 'grilled', 'weaknesses'] },
  { re: /复盘|事后回顾|事故总结|retrospective|post.?mortem|postmortem|blameless|went.?wrong|5.?whys/i, tags: ['postmortem', 'retrospective', 'decision', 'analysis', 'whys', 'failed'] },
  { re: /幻觉|别编造|不要编造|过度设计|极简代码|代码质量|克制|hallucinat|over.?engineer|yagni|invented?.?api|code.?quality|surgical/i, tags: ['code', 'hallucinations', 'verify', 'simple', 'assumptions', 'apis', 'review'] },
  { re: /上线前|发布前检查|预发检查|生产就绪|pre.?prod|production.?readiness|ship.?gate|release.?checklist|deploy.?audit|before.?deploy/i, tags: ['audit', 'production', 'security', 'deploy', 'codebase', 'observability', 'blocks'] },
  { re: /提示词|提示工程|管理prompt|prompt|评测|评估集|\beval\b|llm.?ops/i, tags: ['prompt', 'prompts', 'eval', 'production', 'versioning', 'registries', 'agent'] },
  { re: /演示视频|产品演示|录屏|讲解视频|产品视频|demo.?video|walkthrough|screencast|product.?tour/i, tags: ['demo', 'video', 'walkthrough', 'product', 'marketing', 'showcase'] },
  { re: /爬虫|抓取|采集数据|数据抽取|scrap|crawl|firecrawl|data.?pipeline/i, tags: ['scraping', 'crawling', 'extraction', 'parsing', 'pipelines', 'data', 'web'] },
]

/** Goal → a set of English domain tags (handles zh via INTENT + any en words typed). */
export function goalTags(goal: string): Set<string> {
  const out = toks(goal) // any English words the user typed
  for (const it of INTENT) if (it.re.test(goal)) for (const t of it.tags) out.add(t)
  return out
}

/** Token-overlap score kept for nearest-kit ranking and backwards compatibility. */
export function score(tags: Set<string>, sk: StoreSkill): number {
  const t = toks(`${sk.name} ${sk.description} ${sk.category}`)
  let hit = 0
  for (const g of tags) {
    if (t.has(g)) { hit++; continue }
    if (g.length >= 5) { const p = g.slice(0, 5); for (const x of t) if (x.length >= 5 && (x.startsWith(p) || g.startsWith(x.slice(0, 5)))) { hit++; break } }
  }
  return hit
}

const NEGATION = /(?:不要|不用|不使用|不需要|无需|无须|避免|排除|禁止|不得)\s*([^，。,.;；]+)|(?:without|avoid|exclude|do\s+not|don't|not\s+use|no)\s+([^,.;]+)/gi
const NEG_STOP = new Set(['run', 'running', 'use', 'using', 'any', 'the', 'a', 'an', 'please', 'skill', 'skills'])

export interface GoalConstraints {
  positive: string
  forbidden: Set<string>
  forbiddenCapabilities: Set<string>
}

/** Extract explicit user exclusions before intent expansion. Negated text must never
 * become a positive retrieval signal (the old matcher did exactly that). */
export function parseGoalConstraints(goal: string): GoalConstraints {
  const forbidden = new Set<string>()
  const forbiddenCapabilities = new Set<string>()
  const spans: [number, number][] = []
  for (const m of goal.matchAll(NEGATION)) {
    const clause = (m[1] ?? m[2] ?? '').trim()
    spans.push([m.index ?? 0, (m.index ?? 0) + m[0].length])
    for (const token of toks(clause)) if (!NEG_STOP.has(token)) forbidden.add(token.replace(/s$/, ''))
    const low = clause.toLowerCase()
    if (/网络|联网|network|internet|egress/.test(low)) forbiddenCapabilities.add('network')
    if (/命令|shell|执行|exec|terminal/.test(low)) forbiddenCapabilities.add('exec')
    if (/安装|install|package/.test(low)) forbiddenCapabilities.add('install')
    if (/密钥|凭证|secret|credential|api.?key/.test(low)) forbiddenCapabilities.add('secret')
    if (/文件|filesystem/.test(low)) forbiddenCapabilities.add('filesystem')
  }
  let positive = goal
  for (const [start, end] of spans.reverse()) positive = positive.slice(0, start) + positive.slice(end)
  return { positive: positive.replace(/\b(?:but|and)\s*$/i, '').trim(), forbidden, forbiddenCapabilities }
}

function searchable(sk: StoreSkill): Set<string> {
  return toks(`${sk.name.replace(/-/g, ' ')} ${sk.description} ${sk.category}`)
}

const CAPABILITY_HINTS: Record<string, RegExp> = {
  network: /\b(?:network|internet|web|browse|browser|search|research|competitive|intelligence|market|fetch|scrap|crawl|http|online|github|cloud)\b|联网|网络|网页|搜索|调研|市场/i,
  exec: /\b(?:shell|terminal|command|execute|exec|subprocess|script)\b|命令|终端|执行/i,
  install: /\b(?:install|package|dependency|npm|pip|brew)\b|安装|依赖|软件包/i,
  secret: /\b(?:secret|credential|api.?key|token|password)\b|密钥|凭证|密码/i,
  filesystem: /\b(?:filesystem|file|directory|folder|write|edit)\b|文件|目录|写入|编辑/i,
}

function inferredCapabilities(skill: StoreSkill): Set<string> {
  const text = `${skill.name} ${skill.description} ${skill.category}`
  return new Set(Object.entries(CAPABILITY_HINTS).filter(([, pattern]) => pattern.test(text)).map(([cap]) => cap))
}

function prefixHit(query: string, candidate: string): boolean {
  if (query === candidate) return true
  if (query.length < 5 || candidate.length < 5) return false
  return query.startsWith(candidate.slice(0, 5)) || candidate.startsWith(query.slice(0, 5))
}

export interface RankedSkill {
  skill: StoreSkill
  score: number
  matched: string[]
}

export interface PlannedSkill extends RankedSkill {
  role: 'core' | 'support'
  stage: 'discover' | 'produce' | 'verify' | 'deliver' | 'general'
  /** Inferred from catalog metadata, not a claim that the package declares an I/O contract. */
  dependsOn: string[]
}

export interface MatchPlan {
  goal: string
  constraints: GoalConstraints
  ranked: RankedSkill[]
  selected: PlannedSkill[]
  coverage: number
  confidence: 'high' | 'medium' | 'low' | 'none'
  abstained: boolean
  compositionVerified: false
}

function inferStage(skill: StoreSkill): PlannedSkill['stage'] {
  const text = `${skill.name} ${skill.category} ${skill.description}`.toLowerCase()
  if (/deploy|launch|release|ship|publish|deliver/.test(text)) return 'deliver'
  if (/review|verify|verification|debug|test|audit|quality/.test(text)) return 'verify'
  if (/research|discover|brainstorm|strategy|planning|plan\b|analysis/.test(text)) return 'discover'
  if (/build|create|design|write|content|frontend|generate|implement/.test(text)) return 'produce'
  return 'general'
}

/** Deterministic hybrid retrieval over the locally available catalog metadata.
 * Literal query terms get the highest weight; bilingual intent expansion is a recall
 * layer; corpus IDF prevents broad tags such as `web` and `design` dominating. */
export function rankGoal(goal: string, pool: StoreSkill[]): { constraints: GoalConstraints; tags: Set<string>; ranked: RankedSkill[] } {
  const constraints = parseGoalConstraints(goal)
  const literal = toks(constraints.positive)
  const tags = goalTags(constraints.positive)
  const docs = pool.map((skill) => ({ skill, terms: searchable(skill) }))
  const df = new Map<string, number>()
  for (const { terms } of docs) for (const term of terms) df.set(term, (df.get(term) ?? 0) + 1)
  const idf = (term: string) => Math.log(1 + (docs.length + 1) / ((df.get(term) ?? 0) + 1))
  const blocked = (terms: Set<string>, skill: StoreSkill) => {
    for (const f of constraints.forbidden) for (const t of terms) if (prefixHit(f, t)) return true
    const capabilities = new Set([...skill.capabilities.map((c) => c.cap), ...inferredCapabilities(skill)])
    if ([...constraints.forbiddenCapabilities].some((cap) => capabilities.has(cap))) return true
    return constraints.forbiddenCapabilities.size > 0 && skill.capabilities.length === 0
  }
  const ranked = docs.flatMap(({ skill, terms }): RankedSkill[] => {
    if (blocked(terms, skill)) return []
    const matched = new Set<string>()
    let value = 0
    for (const q of tags) {
      const hit = [...terms].some((term) => prefixHit(q, term))
      if (!hit) continue
      matched.add(q)
      value += idf(q) * (literal.has(q) ? 4 : 1.15)
    }
    const normalizedName = skill.name.replace(/-/g, ' ').toLowerCase()
    const nameTerms = toks(normalizedName)
    for (const q of literal) if (nameTerms.has(q)) value += idf(q) * 3
    for (const q of tags) if (!literal.has(q) && nameTerms.has(q)) value += idf(q) * 1.5
    if (/搭建|创建|开发|\bbuild\b|\bcreate\b/i.test(constraints.positive) && nameTerms.has('builder')) value += 9
    const unaskedPlatform = ['twitter', 'linkedin', 'tiktok', 'youtube', 'shopify', 'cloudflare']
      .some((platform) => nameTerms.has(platform) && !constraints.positive.toLowerCase().includes(platform))
    if (unaskedPlatform) value -= 7
    const phrase = constraints.positive.toLowerCase()
    if (phrase.includes(normalizedName) || normalizedName.includes(phrase)) value += 5
    if (!matched.size) return []
    value += skill.grade === 'A' ? 0.25 : 0
    return [{ skill, score: Math.round(value * 1000) / 1000, matched: [...matched] }]
  }).sort((a, b) => b.score - a.score || (a.skill.grade === 'A' ? -1 : 1) || a.skill.tokens - b.skill.tokens || a.skill.name.localeCompare(b.skill.name))
  return { constraints, tags, ranked }
}

/** High-precision concepts that must be represented by a plausible core skill. They
 * prevent adjacent vocabulary from hijacking a task (for example a web scraper
 * winning a PDF-extraction query when the trusted pool has no PDF extraction skill). */
function anchorGroups(goal: string): { tags: string[]; minHits: number }[] {
  const groups: { tags: string[]; minHits: number }[] = []
  const add = (re: RegExp, tags: string[], minHits = 1) => { if (re.test(goal)) groups.push({ tags, minHits }) }
  add(/\bpdf\b/i, ['pdf'])
  add(/表格|excel|spreadsheet|xlsx/i, ['xlsx', 'spreadsheet'])
  add(/幻灯|演示文稿|\bppt|slide|presentation|pptx|deck/i, ['pptx', 'slide', 'presentation'])
  add(/shopify/i, ['shopify'])
  add(/漫画|漫剧|manhwa|manga|webtoon|comic/i, ['comic', 'manhwa', 'webtoon'])
  add(/音乐|作曲|编曲|歌曲|歌词|suno|music|song|lyric/i, ['music', 'suno', 'song', 'lyric'])
  add(/\bseo\b|搜索引擎优化/i, ['seo'])
  add(/路线图|roadmap/i, ['roadmap'])
  add(/\barr\b|\bmrr\b|saas.{0,20}(?:指标|metric|churn)/i, ['saas', 'arr', 'mrr'], 2)
  add(/代码评审|合并请求|拉取请求|\bpr\b|pull.?request|code.?review/i, ['code', 'pull', 'request'])
  add(/前端|frontend|react/i, ['frontend', 'react'])
  add(/cloudflare|workers?/i, ['cloudflare', 'worker'])
  add(/\bmcp\b/i, ['mcp'])
  return groups
}

/** Plan a small, conflict-free set. A second/third skill is admitted only when it adds
 * query coverage, so a search never pads a weak answer into a five-skill "combo". */
export function planGoal(goal: string, pool: StoreSkill[], highConflict: Set<string>, max = 3): MatchPlan {
  const g = goal.trim()
  const empty: MatchPlan = { goal: g, constraints: parseGoalConstraints(g), ranked: [], selected: [], coverage: 0, confidence: 'none', abstained: true, compositionVerified: false }
  if (g.length < 2) return empty
  const { constraints, tags, ranked } = rankGoal(g, pool)
  const rowFired = INTENT.some((it) => it.re.test(constraints.positive))
  const best = ranked[0]?.score ?? 0
  const threshold = rowFired ? 1.45 : 5
  if (best < threshold) return { ...empty, constraints, ranked }
  const selected: RankedSkill[] = []
  const covered = new Set<string>()
  const anchors = anchorGroups(constraints.positive)
  for (const group of anchors) {
    if (selected.length >= max) break
    const core = ranked.find((candidate) =>
      candidate.score >= threshold &&
      candidate.matched.length >= 2 &&
      candidate.matched.filter((term) => group.tags.includes(term)).length >= group.minHits &&
      !selected.some((p) => p.skill.name === candidate.skill.name || highConflict.has(`${p.skill.name}|${candidate.skill.name}`)),
    )
    if (!core) return { ...empty, constraints, ranked }
    selected.push(core)
    for (const term of core.matched) covered.add(term)
  }
  if (!rowFired && !anchors.length && !(ranked[0]?.matched.filter((term) => toks(constraints.positive).has(term)).length >= 2)) {
    return { ...empty, constraints, ranked }
  }
  // Precision-first: a broad intent expansion is evidence for ranking, not evidence
  // that the user needs another Skill. Multiple selections come from distinct domain
  // anchors; otherwise the best single Skill wins. Runtime-verified I/O metadata can
  // safely unlock richer DAG expansion later.
  if (!selected.length && ranked[0]) {
    selected.push(ranked[0])
    for (const term of ranked[0].matched) covered.add(term)
  }
  const coverable = [...tags].filter((tag) => ranked.some((r) => r.matched.includes(tag)))
  const coverage = coverable.length ? covered.size / coverable.length : 0
  const confidence = best >= 10 && coverage >= 0.5 ? 'high' : best >= 4 ? 'medium' : 'low'
  const planned: PlannedSkill[] = selected.map((item, index) => {
    const stage = inferStage(item.skill)
    const previous = index ? selected[index - 1] : undefined
    const previousStage = previous ? inferStage(previous.skill) : undefined
    return {
      ...item,
      role: index === 0 ? 'core' : 'support',
      stage,
      dependsOn: previous && previousStage !== stage ? [previous.skill.name] : [],
    }
  })
  return { goal: g, constraints, ranked, selected: planned, coverage, confidence, abstained: planned.length === 0, compositionVerified: false }
}

export function matchGoal(goal: string, pool: StoreSkill[], highConflict: Set<string>, max = 3): StoreSkill[] {
  return planGoal(goal, pool, highConflict, max).selected.map((x) => x.skill)
}

/* ── The match pool ─────────────────────────────────────────────────────────────────
 * Seed + curated (hand-vetted) PLUS the engine-rated community pool under a strict
 * trust filter: grade A/B, safety gate PASSED, low risk, and not a router/redirect
 * stub (whose text would pollute matching). Dedup by name: seed > curated > community.
 * Shared by the homepage BundlesSection AND eval-bundles so the tested pool IS the
 * shipped pool. */
const STUB_RE = /deprecated|redirect|router for|index and router|central router/i

export function buildMatchPool(seed: StoreSkill[], curated: StoreSkill[], community: StoreSkill[]): StoreSkill[] {
  const seen = new Set<string>()
  const out: StoreSkill[] = []
  for (const s of [...seed, ...curated, ...community]) {
    if (seen.has(s.name)) continue
    if (!isAutoMatchEligible(s)) continue
    if (STUB_RE.test(s.description)) continue
    seen.add(s.name); out.push(s)
  }
  return out
}

/* ── Fallback: nearest ready-made kit ───────────────────────────────────────────────
 * When matchGoal can't form a custom combo, the honest answer is not silence — it is
 * the CLOSEST curated kit. Kit copy is bilingual (name.zh/who.zh are real Chinese), so
 * zh goals literal-match via CJK bigrams with no INTENT row needed; en goals match via
 * toks(); goalTags-vs-member-skills overlap catches paraphrases in both languages. */

const ZH_STOP_BIGRAMS = new Set(['一个', '我要', '我想', '帮我', '一下', '什么', '怎么', '如何', '可以', '需要', '一套', '这个', '那个'])

function cjkBigrams(s: string): string[] {
  const out: string[] = []
  for (const run of s.match(/[一-鿿]+/g) ?? [])
    for (let i = 0; i < run.length - 1; i++) { const b = run.slice(i, i + 2); if (!ZH_STOP_BIGRAMS.has(b)) out.push(b) }
  return out
}

/** The framework-free slice of a ready-made bundle this lib needs to rank kits. */
export interface KitCopy { id: string; nameZh: string; nameEn: string; whoZh: string; whoEn: string; skills: string[] }

/** Goal → the closest ready-made kit, or null when nothing clears `minScore` (true
 *  no-match — e.g. 帮我算命 / asdfgh). Name hits weigh 4, intro hits 2 (the name
 *  weight is what rescues 2-char goals like 新手入门). */
export function nearestKit(goal: string, kits: KitCopy[], byName: Map<string, StoreSkill>, minScore = 4): { id: string; score: number } | null {
  const g = goal.trim()
  if (g.length < 2) return null
  const bigrams = cjkBigrams(g), words = [...toks(g)], tags = goalTags(g)
  let best: { id: string; score: number } | null = null
  for (const k of kits) {
    const nm = `${k.nameZh} ${k.nameEn}`.toLowerCase(), who = `${k.whoZh} ${k.whoEn}`.toLowerCase()
    let sc = 0
    for (const b of bigrams) { if (nm.includes(b)) sc += 4; else if (who.includes(b)) sc += 2 }
    for (const w of words) { if (nm.includes(w)) sc += 4; else if (who.includes(w)) sc += 2 }
    for (const n of k.skills) { const s = byName.get(n); if (s) sc += score(tags, s) }
    if (!best || sc > best.score) best = { id: k.id, score: sc }
  }
  return best && best.score >= minScore ? best : null
}
