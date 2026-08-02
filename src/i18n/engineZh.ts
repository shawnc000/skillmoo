/**
 * engineZh — Simplified-Chinese lookups for the strings the analysis engine
 * emits in English (`src/lib/analyzeSkill.ts`, `src/lib/scriptScan.ts`) plus a
 * few store/demo data labels (`src/data/samples.ts`, `src/data/seedSkills.ts`).
 *
 * The engine MUST stay English (the CLI and API reuse it verbatim), so we do NOT
 * translate at the source — instead the zh UI wraps each engine string here:
 *   lang === 'zh' ? zhFinding(f.title) : f.title
 *
 * Every helper is keyed by the EXACT English string and falls back to that
 * English if there is no match, so nothing ever renders blank. A handful of
 * strings are dynamic (a token count, a duplicate-line count, a word list, an
 * exfil dataflow) — those are matched by a stable substring and rebuilt with the
 * number/identifier re-inserted.
 *
 * Source skill NAMES (wrangler, claude-api …) and technical identifiers (curl,
 * base64, SKILL.md, token, API, .env …) intentionally stay as-is.
 */

const lookup = (map: Record<string, string>, key: string): string => map[key] ?? key

/* ---------------------------------------------------------------- findings -- */

const FINDING_TITLE: Record<string, string> = {
  // RISK_RULES (analyzeSkill)
  'Downloads and runs a remote script (curl … | sh)': '下载并运行远程脚本（curl … | sh）',
  'Possible prompt injection / instruction hijack': '疑似提示注入 / 指令劫持',
  'Possible data-exfiltration intent': '疑似数据外泄意图',
  'Possible obfuscated / encoded payload': '疑似混淆 / 编码过的载荷',
  'Reads private keys / cloud credentials': '读取私钥 / 云凭证',
  'References API keys / env config': '引用 API key / 环境变量配置',
  'Dynamic code execution / spawns a process': '动态执行代码 / 起子进程',
  'Destructive file operation': '破坏性文件操作',
  'Privilege escalation / changes exec permission': '提权 / 修改可执行权限',
  'Embedded shell script block': '内嵌 shell 脚本块',
  'Makes outbound network requests': '发起对外网络请求',
  'Contains curl / wget network command': '包含 curl / wget 网络命令',
  'Hard-coded IP address': '硬编码的 IP 地址',
  'References a .env file': '引用了 .env 文件',
  // Structure & spec
  'Missing YAML frontmatter': '缺少 YAML frontmatter',
  'Missing name field': '缺少 name 字段',
  'Non-standard name': 'name 命名不规范',
  'Missing description field': '缺少 description 字段',
  'Body has no section headings': '正文没有分节标题',
  // Triggering
  'Description too short / vague': 'description 太短 / 太笼统',
  'Description too long': 'description 太长',
  'Description doesn’t say WHEN to use it': 'description 没说清什么时候该用它',
  'Trigger is too broad': '触发条件太宽泛',
  'Over the spec’s body budget': '超出官方正文 token 预算',
  'Over the spec’s line budget': '超出官方 500 行预算',
  'Could defer detail to references/': '可把细节挪进 references/',
  'Description contains filler': 'description 里有废话',
  // Token efficiency
  'Bloated: high token cost': '内容冗长 · token 成本偏高',
  'Repeated content': '内容重复',
  // Exfiltration chain (analyzeSkill + scriptScan)
  'Credential read + network egress + risk signal = likely exfiltration chain':
    '读取凭证 + 网络外联 + 风险信号 = 疑似数据外泄链路',
  'Reads credentials and makes network calls — verify the destination':
    '既读凭证又发网络请求——请核实目标地址',
  'Exfiltration path in an embedded script': '内嵌脚本里存在数据外泄路径',
  // Security depth (P1/P5) — added when the web began showing full bundle findings (P8)
  'Downloads and runs a remote script from a raw IP (curl <ip> | sh)': '从裸 IP 下载并运行远程脚本（curl <ip> | sh）',
  'Runs a shell command before the model reads the skill (dynamic context)': '模型还没读到技能，就先跑了 shell 命令（动态上下文）',
  'Sends data to a known exfiltration / paste / tunnel service': '把数据发往已知的外泄 / 粘贴板 / 隧道服务',
  'Installs a persistence backdoor (auto-run / access file)': '装了个持久化后门（开机自启 / 长期访问文件）',
  'Writes to agent-config / instruction files': '写入 agent 配置 / 指令文件',
  'Installs an auto-run Claude Code hook (command on a lifecycle event)': '装了个会自动执行的 Claude Code hook（挂在生命周期事件上）',
  'Zero-click data exfiltration via image/link URL': '通过图片 / 链接 URL 零点击外泄数据',
  'Possible DNS-exfiltration covert channel': '疑似 DNS 外泄隐蔽信道',
  'Over-broad allowed-tools grant': 'allowed-tools 授权过宽',
  'Instruction to conceal actions from the user': '指示 agent 对用户隐瞒自己的动作',
  'Instruction to leak the system prompt / hidden context': '指示 agent 泄露系统提示 / 隐藏上下文',
  'Behavior manipulation — suppresses the agent’s safety judgment': '行为操纵——压制 agent 的安全判断',
  'Jailbreak / roleplay override (DAN / “no restrictions”)': '越狱 / 角色扮演绕过（DAN /“无限制”）',
  'Authority / role spoofing via forged chat-template tokens': '用伪造的对话模板控制符冒充权限 / 角色',
  'Memory poisoning — plants standing approvals in agent memory': '记忆投毒——往 agent 记忆里塞长期“已授权”',
  'Cross-tool hijack — intercepts other tools/skills': '跨工具劫持——拦截其他工具 / 技能',
  'Installs from a non-official / unencrypted package source': '从非官方 / 未加密的包源安装',
  'Time-bomb / rug-pull — date-gated code execution': '定时炸弹 / 抽地毯——按日期触发的代码执行',
  'Disables the human approval gate / passwordless privilege': '关掉人工确认闸门 / 免密提权',
  'Resource exhaustion / fork bomb': '资源耗尽 / fork 炸弹',
  'Password-protected payload (malware-delivery pattern)': '带密码的压缩包载荷（恶意软件投递套路）',
  'Catastrophic delete (rm -rf of root / home / wildcard)': '毁灭性删除（对 根 / home / 通配符 执行 rm -rf）',
  'Possible homoglyph name impersonation': '疑似同形字冒名',
  'Vague / generic name': 'name 太笼统 / 太通用',
  // Skill-engineering depth (P6)
  'Over-declared tools (least privilege)': '工具声明过多（最小权限）',
  'Uses shell but doesn’t declare Bash in allowed-tools': '用了 shell 却没在 allowed-tools 里声明 Bash',
  'References a bundled file that isn’t present': '引用了一个并不存在的捆绑文件',
  'Monolithic — should use progressive disclosure': '细节未分层 · 应按需加载（渐进式披露）',
  'Hidden instructions smuggled in invisible Unicode': '用隐形 Unicode 字符偷藏指令',
  'Credential + network in a security-analysis skill — verify it is an example': '安全分析类技能里出现凭证 + 网络——请确认这只是示例',
}

const DETAIL: Record<string, string> = {
  // RISK_RULES details
  'Fetches a remote script and executes it immediately — the classic supply-chain attack shape. One line, full machine control.':
    '拉取一段远程脚本并立即执行——典型的供应链攻击套路。一行命令，就能拿到整台机器的控制权。',
  'Contains "ignore previous instructions"-style text that can hijack the agent. 91% of malicious skills use exactly this.':
    '含有"忽略前面所有指令"这类可以劫持 agent 的文字。91% 的恶意 skill 用的正是这一招。',
  '"Send … to <server>" phrasing; combined with secret access this forms a complete data-leak path.':
    '出现"把 … 发送到 <服务器>"这类措辞；一旦再配上读取密钥，就凑齐了一条完整的数据泄露链路。',
  'A long base64 blob or decode-and-run (atob / base64 -d) is a common way to hide malicious code from keyword scanners.':
    '一大段 base64 数据，或"先解码再执行"（atob / base64 -d），是躲开关键词扫描、藏匿恶意代码的常见手法。',
  'Touches SSH private keys or cloud-credential files — rarely needed in a skill, and a data-theft signal when paired with network access.':
    '碰到了 SSH 私钥或云凭证文件——skill 很少真需要这么做，一旦再配上联网就是数据窃取的信号。',
  'Reads an API key or env var — normal for API clients. Ensure keys come from the runtime (not hardcoded); a leak risk only if sent to an untrusted endpoint.':
    '读取 API key 或环境变量——对 API 客户端来说很正常。确保 key 来自运行时（别硬编码在文件里）；只有把它发往不可信的地址时才有泄露风险。',
  'Calls eval/exec/subprocess — unpredictable behavior; this is the part that most needs sandbox isolation.':
    '调用了 eval/exec/subprocess——行为难以预料；这部分最需要放进沙箱隔离运行。',
  'Contains rm -rf or a similar delete command; misuse or abuse causes data loss.':
    '含有 rm -rf 或类似的删除命令；一旦误用或被滥用会导致数据丢失。',
  'sudo or chmod +x elevates privileges or makes files executable — needs human review.':
    'sudo 或 chmod +x 会提升权限、或把文件变成可执行——需要人工复核。',
  'Ships runnable command-line scripts. Not necessarily bad, but must be sandboxed and reviewed.':
    '附带了可直接运行的命令行脚本。不一定是坏事，但必须放进沙箱并经过审查。',
  'Sends or pulls data from external endpoints — a data-egress channel; confirm the target is trusted.':
    '向外部地址收发数据——这是一条数据外流通道；请确认目标是可信的。',
  'Accesses the network from the shell. If the target is untrusted it can pull malware or exfiltrate data.':
    '从 shell 直接访问网络。如果目标不可信，可能被用来拉取恶意程序或外传数据。',
  'Literal IPs are often used to bypass domain review for egress — worth verifying.':
    '写死的 IP 常被用来绕过域名审查、偷偷外联——值得核实一下。',
  'Touching .env usually means reading config or secrets — check its purpose.':
    '碰 .env 通常意味着在读配置或密钥——确认一下它到底想干什么。',
  // Structure & spec
  'A SKILL.md should open with --- delimited metadata (at least name and description) or the agent cannot register it.':
    'SKILL.md 开头应该有一段用 --- 包起来的元数据（至少要有 name 和 description），否则 agent 无法注册它。',
  'Without a name the skill cannot be referenced reliably.':
    '没有 name，就没法稳定地引用这个 skill。',
  'Use lowercase kebab-case, e.g. pr-review.':
    '请用小写加连字符的写法（kebab-case），例如 pr-review。',
  'The description is the ONLY thing the agent uses to decide when to fire this skill; missing it means it never triggers.':
    'agent 判断"什么时候触发这个 skill"唯一的依据就是 description；缺了它就永远不会触发。',
  'A long body with no headings is harder for the model to parse.':
    '正文很长却没有标题分节，模型更难读懂。',
  // Triggering
  'The description is read on every trigger check; overly long ones waste tokens and dilute the signal.':
    '每次判断要不要触发都会读一遍 description；写太长既浪费 token，又冲淡了关键信号。',
  'A good description names the trigger (e.g. "when reviewing a PR"). Without it the skill mis-fires or never fires.':
    '好的 description 会点明触发场景（比如"审查 PR 时"）。少了它，skill 要么乱触发、要么根本不触发。',
  'Phrases like "helps with various tasks" carry no signal — replace with a concrete scenario.':
    '"帮你处理各种任务"这类说法没有任何信息量——换成一个具体的使用场景。',
  // Exfiltration chain
  'Reads sensitive credentials (or hides/obfuscates code) AND talks to the network — together a data-theft path, not the benign API-client pattern.':
    '既读取敏感凭证（或把代码藏起来、做混淆），又对外联网——两者叠加就是一条数据窃取链路，不是正常 API 客户端那种模式。',
  'The normal shape of an API client (your key → the API). Static analysis sees the capability, not the intent — confirm the endpoint is one you trust; it is a data-leak risk only if it is not.':
    'API 客户端本来就长这样（你的 key → 对应的 API）。静态分析只看得到"能做什么"，看不到"想干什么"——确认这个地址是你信得过的；只有它不可信时才谈得上泄露风险。',
  // Negation-aware (any rule detail, when the match sits inside a warning)
  'Appears inside a prohibition/warning ("never …"), not as an instruction to run. Flagged for awareness only.':
    '它出现在一句禁止 / 警告里（"never …"），并不是要你执行的指令。这里只是提醒你留意一下。',
  // Security depth details (P1/P5)
  'Fetches a script from a bare IP address and runs it immediately — no legitimate installer does this. A classic supply-chain / malware-delivery shape with full machine control.':
    '从一个裸 IP 地址拉取脚本并立即执行——正经安装程序绝不会这么做。典型的供应链 / 恶意软件投递套路，一步就能拿到整台机器的控制权。',
  'A `!`command`` line executes on your machine BEFORE the model even reads the skill (Claude Code dynamic context). Pre-model execution skips the model’s safety reasoning — a top vector for silent credential theft.':
    '有一行 `!`命令`` 会在模型还没读到这个技能之前，就先在你机器上执行（Claude Code 动态上下文）。抢在模型之前跑，等于跳过了模型的安全判断——是悄悄窃取凭证的头号手段。',
  'References a service (webhook.site, requestbin, ngrok, pastebin, a Discord/Slack/Telegram webhook, an OAST/interactsh host…) that is almost only used to capture exfiltrated data — a strong data-egress signal.':
    '引用了一个几乎只用来接收外泄数据的服务（webhook.site、requestbin、ngrok、pastebin，或 Discord/Slack/Telegram webhook、OAST/interactsh 主机……）——是很强的数据外流信号。',
  'Writes to a file that auto-runs or grants standing access across sessions (shell rc, crontab, git hooks, ~/.ssh/authorized_keys or config, MCP config). This is how a one-time skill becomes a permanent backdoor.':
    '往一个会自动执行、或跨会话长期生效的文件里写东西（shell rc、crontab、git hooks、~/.ssh/authorized_keys 或 config、MCP 配置）。一次性技能就是这样变成常驻后门的。',
  'Modifies CLAUDE.md / AGENTS.md / .claude settings — legitimate for a memory or setup skill, but also how a skill silently rewrites the agent’s standing instructions. Verify the intent.':
    '改动了 CLAUDE.md / AGENTS.md / .claude 设置——对记忆类或初始化类技能是正常的，但技能也能借此悄悄改写 agent 的长期指令。请核实它的意图。',
  'Wires a shell command to a Claude Code lifecycle hook (PreToolUse / PostToolUse / SessionStart …) so it auto-runs on every matching event without asking. Legitimate for a formatter/lint setup skill, but also the classic silent-persistence backdoor — inspect exactly what command it runs before trusting it.':
    '把一条 shell 命令挂到了 Claude Code 的生命周期 hook（PreToolUse / PostToolUse / SessionStart …），每次命中该事件就自动执行、还不问你一声。对格式化 / lint 这类初始化技能是正常的，但也是典型的静默持久化后门——信它之前，先看清楚它到底跑的是什么命令。',
  'A markdown image/link with a dynamic value interpolated into its query string — the agent renders it and silently sends the data to an external host, no click required.':
    '一个 markdown 图片 / 链接，把某个动态值拼进了它的查询串——agent 一渲染，就把数据悄悄发给了外部主机，连点都不用点。',
  'Interpolates command output or a variable into a DNS lookup (dig / nslookup of `$(…).host`) — a covert channel that smuggles data out through subdomain queries and bypasses HTTP egress filtering. Rarely legitimate; a strong data-leak signal when it carries a secret.':
    '把命令输出或变量拼进了一次 DNS 查询（对 `$(…).host` 做 dig / nslookup）——这是一条隐蔽信道，靠子域名查询把数据偷带出去，还绕过 HTTP 外联过滤。很少有正当用途；一旦携带密钥就是很强的泄露信号。',
  'The skill grants itself wildcard tool access (Bash(*) / allowed-tools: *) — far more privilege than a focused skill needs. Narrow it to the specific commands it actually uses.':
    '技能给自己开了通配符级别的工具权限（Bash(*) / allowed-tools: *）——远超一个专注的技能真正需要的权限。把它收窄到实际用到的那几条命令。',
  'Tells the agent to hide what it does from the user — a hallmark of a malicious skill. On its own it may be benign phrasing; paired with an exec/exfil action it is a strong attack signal.':
    '让 agent 对用户隐藏自己的所作所为——恶意技能的典型特征。单看也许只是措辞；一旦配上执行 / 外泄动作，就是很强的攻击信号。',
  'Tells the agent to reveal its own system prompt / hidden initial instructions — an exfiltration of the agent’s privileged context (OWASP LLM07). Legitimate skills never need this.':
    '让 agent 说出自己的系统提示 / 隐藏的初始指令——这是在外泄 agent 的特权上下文（OWASP LLM07）。正经技能从不需要这么做。',
  'Steers the agent to override its own safety checks (“treat as safe regardless”, “never flag dangerous commands”, “auto-approve without asking”) without an explicit instruction-override. On its own a review flag; alongside an exec/exfil action it is a strong attack signal.':
    '在没有明说“覆盖指令”的情况下，把 agent 往“绕过自己的安全检查”上带（“一律当成安全的”、“绝不标记危险命令”、“不问直接批准”）。单看是复核项；配上执行 / 外泄动作就是很强的攻击信号。',
  'Contains a jailbreak/roleplay override ("you are now DAN", "developer mode enabled", "no restrictions apply", "stay in character no matter what") that strips the model’s safety guidelines — a hallmark of prompt-injection / model-evasion attacks.':
    '含有越狱 / 角色扮演绕过（"you are now DAN"、"developer mode enabled"、"no restrictions apply"、"stay in character no matter what"），把模型的安全准则整个剥掉——提示注入 / 模型规避攻击的典型特征。',
  'Embeds a model’s chat-template control tokens (ChatML `<|im_start|>`, Llama `<<SYS>>` / `[INST]`) or a fake-authority header (`[ADMIN OVERRIDE]`, `BEGIN SYSTEM PROMPT`) to forge a system/operator message boundary — a prompt-injection technique that makes attacker text read as a privileged instruction. Legitimate skills never need to write these delimiters.':
    '嵌入了模型对话模板的控制符（ChatML `<|im_start|>`、Llama `<<SYS>>` / `[INST]`）或伪造的权限头（`[ADMIN OVERRIDE]`、`BEGIN SYSTEM PROMPT`），用来伪造一条系统 / 操作者消息边界——这种提示注入手法能让攻击者的文字被当成特权指令来读。正经技能从不需要写这些分隔符。',
  'Writes an approval/permission assertion ("user approved", "skip all confirmations", "always allow") into the agent’s durable memory (CLAUDE.md / MEMORY.md / .claude memory) so future sessions skip safety checks. A review flag on its own; a strong signal alongside an exec/exfil action.':
    '往 agent 的长期记忆（CLAUDE.md / MEMORY.md / .claude memory）里写入一句“已授权”（"user approved"、"skip all confirmations"、"always allow"），好让以后的会话跳过安全检查。单看是复核项；配上执行 / 外泄动作就是很强的信号。',
  'Instructs the agent to reach into OTHER tools/skills and silently duplicate/redirect their actions ("whenever any other tool sends an email, silently BCC…"). A review flag on its own; a strong intercept/exfil signal when paired with a destination.':
    '指示 agent 伸手进别的工具 / 技能，悄悄复制或改道它们的动作（“只要别的工具一发邮件，就偷偷密送……”）。单看是复核项；一旦配上一个目标地址就是很强的拦截 / 外泄信号。',
  'Installs a package from a custom index / registry / git URL over http:// or a direct archive URL, instead of the official PyPI/npm registry — a supply-chain typosquat/backdoor vector. Verify the source is one you trust.':
    '从自定义索引 / registry / git 地址（走 http:// 或直接一个压缩包 URL）安装依赖，而不是官方的 PyPI/npm——供应链抢注 / 后门的常见入口。请确认这个来源你信得过。',
  'A date/time or counter condition guards a network-fetch-and-run or code-execution action ("if the date is past X, then curl … | sh") — the skill is benign now but flips malicious on a trigger. A hallmark of rug-pull / delayed-activation attacks.':
    '有一个日期 / 时间或计数器条件，守着一段“联网拉取并运行”或代码执行的动作（“如果日期过了 X，就 curl … | sh”）——技能现在人畜无害，一到触发点就翻脸变恶意。抽地毯 / 延迟激活攻击的典型特征。',
  'Instructs the agent to bypass the permission prompt (--dangerously-skip-permissions), run passwordless sudo (NOPASSWD), or world-open files (chmod 777) — removing the human safety gate. Rarely legitimate in a shared skill.':
    '指示 agent 绕过权限确认（--dangerously-skip-permissions）、免密 sudo（NOPASSWD）、或把文件权限全开（chmod 777）——等于拆掉了人工安全闸门。在一个要分享的技能里很少有正当理由。',
  'Contains a fork bomb (:(){ :|:& };:) or a raw-device overwrite (dd of=/dev/sd…) — a denial-of-service that can hang, fill, or brick the machine.':
    '含有 fork 炸弹（:(){ :|:& };:）或直写裸设备（dd of=/dev/sd…）——一种拒绝服务，能把机器卡死、塞满、甚至搞成砖。',
  'Tells the user to extract a password-protected archive and run it. Password-locking a download defeats malware scanners on the payload — a near-universal malware-delivery tell, not a legitimate install method.':
    '让用户解压一个带密码的压缩包再运行它。给下载包加密码，就是为了让杀毒扫描看不到里面的载荷——几乎是恶意软件投递的通用标志，不是正经安装方式。',
  'rm -rf targeting /, ~, $HOME, or a bare wildcard — catastrophic, irreversible data loss. Almost never a legitimate skill action.':
    'rm -rf 直指 /、~、$HOME 或一个裸通配符——毁灭性、不可逆的数据丢失。几乎不可能是正当的技能动作。',
  'The skill name contains Cyrillic/Greek characters that look like Latin letters — a lookalike-name trick used to impersonate a trusted skill. Use plain ASCII kebab-case.':
    '技能名里混了长得像拉丁字母的西里尔 / 希腊字符——用相似字形冒充可信技能的把戏。请用纯 ASCII 的小写连字符写法。',
  'A generic name (“helper”, “utils”, “assistant”…) gives the model no signal about when to fire this skill. Name it after the concrete task, e.g. “pr-review”.':
    '一个太通用的名字（“helper”、“utils”、“assistant”……）没法告诉模型该在什么时候触发这个技能。用它具体负责的任务来命名，比如“pr-review”。',
  // Skill-engineering depth details (P6)
  'The body ships a shell code block, but allowed-tools omits Bash — the skill will be blocked or prompt for permission at runtime. Add Bash (scoped to the commands it needs) or move the shell out.':
    '正文里带了一段 shell 代码块，但 allowed-tools 里没有 Bash——运行时这个技能会被拦下、或弹权限询问。把 Bash 加进去（限定到它需要的命令），或者把 shell 挪出去。',
  'The skill encodes readable text in invisible Unicode Tag characters (U+E00xx) — a model reads it, a human reviewer never sees it. This is a known prompt-injection smuggling channel; no legitimate skill conceals instructions this way.':
    '技能把可读文字编码进了隐形的 Unicode Tag 字符（U+E00xx）——模型读得到，人工审查却完全看不见。这是已知的提示注入偷渡通道；正经技能不会用这种方式藏指令。',
  'A script references credential material and reaches the network. In a security-analysis / detection skill these are usually examples — verify they are, not an actual key→network flow.':
    '某段脚本引用了凭证材料，又连了网络。在安全分析 / 检测类技能里这些通常是示例——请确认确实如此，而不是一条真的“密钥→网络”链路。',
}

// Suffix the engine appends to a finding title when the match sits in a warning.
const WARN_SUFFIX_EN = ' — in a warning'
const WARN_SUFFIX_ZH = ' —— 出现在警告里'

// Lowercased capability labels, for the dynamic "Script capability: <label>" title.
const CAP_LOWER: Record<string, string> = {
  'executes code': '执行代码',
  'runs encoded content': '运行编码内容',
  'reads secrets': '读取密钥',
  'network egress': '网络外联',
  'escalates privilege': '提权',
  'writes / deletes files': '写入 / 删除文件',
  'installs packages': '安装依赖包',
}

export function zhFinding(title: string): string {
  // Dynamic: scriptScan elevates a critical capability into "Script capability: <label>".
  if (title.startsWith('Script capability: ')) {
    const rest = title.slice('Script capability: '.length)
    return `脚本能力：${CAP_LOWER[rest] ?? rest}`
  }
  // A finding matched inside a "never …" warning gets a suffix; translate the base.
  if (title.endsWith(WARN_SUFFIX_EN)) {
    return lookup(FINDING_TITLE, title.slice(0, -WARN_SUFFIX_EN.length)) + WARN_SUFFIX_ZH
  }
  return lookup(FINDING_TITLE, title)
}

export function zhDetail(detail: string): string {
  let m: RegExpMatchArray | null

  // Bloat — "~18,325 tokens on every single call."
  if ((m = detail.match(/~([\d,]+) tokens on every single call/))) {
    return `每次调用都要多花约 ${m[1]} 个 token。精简指令、删减示例就能省下来。`
  }
  // Duplicate lines — "~15 duplicate lines detected;"
  if ((m = detail.match(/~([\d,]+) duplicate lines detected/))) {
    return `检测到约 ${m[1]} 行重复内容；去重就是白捡的 token。`
  }
  // Description too short — "Only ~37 chars — the model can’t tell…"
  if ((m = detail.match(/^Only ~([\d,]+) chars/))) {
    return `只有约 ${m[1]} 个字符——模型判断不出该在什么时候用它，于是常常该触发时不触发。`
  }
  // Trigger too broad — 'Words like "whenever", "anything" make it fire everywhere…'
  if ((m = detail.match(/^Words like (.+?) make it fire everywhere/))) {
    return `像 ${m[1]} 这样的词会让它到处触发，和别的 skill 抢同一个任务——这是冲突的头号原因。`
  }
  // scriptScan exfil dataflow — "A script reads <x> (name) and <verb> (host) — a data-theft flow…"
  if (
    (m = detail.match(
      /^A script reads (sensitive credentials|a secret)(?: \(([^)]*)\))? and (sends them to a raw IP|hides code behind encoding|reaches the network)(?: \(([^)]*)\))? — a data-theft flow/,
    ))
  ) {
    const read = m[1] === 'sensitive credentials' ? '敏感凭证' : '一个密钥'
    const verb =
      m[3] === 'sends them to a raw IP'
        ? '把它们发往了一个裸 IP'
        : m[3] === 'hides code behind encoding'
          ? '用编码把代码藏了起来'
          : '连上了网络'
    const name = m[2] ? `（${m[2]}）` : ''
    const host = m[4] ? `（${m[4]}）` : ''
    return `某段脚本读取了${read}${name}，还${verb}${host}——这是一条数据窃取链路，不是正常 API 客户端那种模式。`
  }
  // scriptScan capability finding — "An embedded script <detail>."
  if ((m = detail.match(/^An embedded script (.+)\.$/))) {
    return `内嵌脚本会${zhCapDetail(m[1])}。`
  }
  // Reference integrity (P6) — "Points to <list>, but those files aren’t in the skill bundle…"
  if ((m = detail.match(/^Points to (.+?), but (those files aren’t|that file isn’t) in the skill bundle/))) {
    const plural = m[2].startsWith('those')
    return `指向了 ${m[1]}，但${plural ? '这些文件' : '这个文件'}并不在技能包里——模型加载${plural ? '它们' : '它'}时会撞到死链。把文件补进去，或改对路径。`
  }
  // Over-declared allowed-tools (P6) — "Declares <Tools> in allowed-tools, but the body shows no sign of using <them|it>…"
  if ((m = detail.match(/^Declares (.+?) in allowed-tools, but the body shows no sign of using (them|it)\./))) {
    return `在 allowed-tools 里声明了 ${m[1]}，但正文里看不出用到${m[2] === 'them' ? '它们' : '它'}。每多授一个工具就多一分攻击面——把用不到的去掉，免得被劫持时用上。`
  }
  // Monolithic (P6) — "All ~<N> tokens load on EVERY trigger. … move your <H> detail sections out to cut the per-trigger cost ~<P>%."
  if ((m = detail.match(/^All ~([\d,]+) tokens load on EVERY trigger\..*?move your (\d+) detail sections out to cut the per-trigger cost ~(\d+)%\.$/))) {
    return `每次触发都要加载全部约 ${m[1]} 个 token。更省的写法是让 SKILL.md 保持精简、把细节放进按需加载的 \`references/\` 文件——把这 ${m[2]} 个细节小节挪出去，每次触发的成本能降约 ${m[3]}%。`
  }

  return lookup(DETAIL, detail)
}

/* --------------------------------------------------------------- verdicts -- */

const VERDICT: Record<string, string> = {
  'Serious security risk — blocked, do not ship': '存在严重安全风险——已拦截，请勿上线',
  'Risk too high — blocked, fix before shipping': '风险过高——已拦截，修好再上线',
  'Usable, but has fixable issues — human review recommended': '可以用，但有一些能修的问题——建议人工复核',
  'Clean and low-risk — safe to merge': '干净、低风险——可以放心合并',
}
export const zhVerdict = (v: string): string => lookup(VERDICT, v)

/* -------------------------------------------------------------- gate label -- */

const GATE_LABEL: Record<string, string> = {
  'Safe to merge': '可安全合并',
  'Needs review': '需要复核',
  Blocked: '已拦截',
}
export const zhGate = (label: string): string => lookup(GATE_LABEL, label)

/* ------------------------------------------------------------------- axes -- */

const AXIS: Record<string, string> = {
  Structure: '结构',
  Triggering: '触发',
  'Token efficiency': 'Token 效率',
  Risk: '风险',
}
export const zhAxis = (label: string): string => lookup(AXIS, label)

/* --------------------------------------------------------------- severity -- */

const SEVERITY: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
}
export const zhSeverity = (s: string): string => lookup(SEVERITY, s)

/* ----------------------------------------------------------- capabilities -- */

// Union of the LiveDemo CAP labels and the scriptScan BEHAVIOR labels.
const CAP_LABEL: Record<string, string> = {
  'Network egress': '网络外联',
  Filesystem: '文件系统',
  'Executes code': '执行代码',
  Privilege: '提权',
  'Secret access': '读取密钥',
  'Installs packages': '安装依赖包',
  'Encoded exec': '编码执行',
  'Runs encoded content': '运行编码内容',
  'Reads secrets': '读取密钥',
  'Escalates privilege': '提权',
  'Writes / deletes files': '写入 / 删除文件',
}
export const zhCap = (label: string): string => lookup(CAP_LABEL, label)

const CAP_DETAIL: Record<string, string> = {
  'downloads a remote script and runs it (curl | sh)': '下载远程脚本并直接运行（curl | sh）',
  'decodes then executes hidden content': '先解码、再执行藏起来的内容',
  'dynamic code / subprocess execution': '动态执行代码 / 起子进程',
  'reads keys, tokens, or credential files': '读取密钥、token 或凭证文件',
  'sends or fetches data over the network': '通过网络收发数据',
  'sudo / chmod / chown': 'sudo / chmod / chown 等提权操作',
  'modifies or deletes files': '修改或删除文件',
  'pulls third-party packages (supply chain)': '拉取第三方依赖包（供应链风险）',
}
export const zhCapDetail = (d: string): string => lookup(CAP_DETAIL, d)

/* ------------------------------------------------------------- categories -- */

const CATEGORY: Record<string, string> = {
  Documents: '文档处理',
  'UI/UX': '界面设计',
  Art: '艺术创作',
  'MCP Integration': 'MCP 集成',
  'Self Evolution': '自我进化',
  'Autonomous Coding': '自主编程',
  Writing: '写作',
  'Planning & Task': '规划与任务',
}
export const zhCategory = (cat: string): string => lookup(CATEGORY, cat)

/* ------------------------------------------------------- demo sample labels -- */

const SAMPLE: Record<string, string> = {
  'Original (bloated)': '原始版（臃肿）',
  'Optimized (clean)': '优化版（干净）',
  'Malicious (high-risk)': '恶意版（高危）',
  'Evasion (hidden)': '伪装版（隐藏）',
}
export const zhSample = (label: string): string => lookup(SAMPLE, label)

/* ------------------------------------------------------- one-click optimize -- */

// The change descriptions optimizeSkill emits (shown in the report's optimize
// block). Static labels are mapped; the duplicate-line one carries a count.
const CHANGE: Record<string, string> = {
  'Removed a filler sentence from the description': '删掉了 description 里的一句废话',
  'Removed vague “various related things”': '删掉了含糊的“various related things”',
  'Removed “of any kind”': '删掉了“of any kind”',
  'Trimmed a verbose example preamble': '精简了啰嗦的示例开场白',
  'Removed “carefully step by step” padding': '删掉了“carefully step by step”这类凑字',
  'Trimmed trailing whitespace': '清理了行尾多余的空白',
  'Shortened “in order to” → “to”': '把“in order to”缩成了“to”',
  'Shortened “due to the fact that” → “because”': '把“due to the fact that”缩成了“because”',
  'Shortened “for the purpose of” → “to”': '把“for the purpose of”缩成了“to”',
  'Shortened “in the event that” → “if”': '把“in the event that”缩成了“if”',
  'Shortened “at this point in time” → “now”': '把“at this point in time”缩成了“now”',
  'Shortened “a large number of” → “many”': '把“a large number of”缩成了“many”',
  'Shortened “the majority of” → “most”': '把“the majority of”缩成了“most”',
  'Removed “please note that” filler': '删掉了“please note that”这类凑字',
  'Removed “it is important to note that” filler': '删掉了“it is important to note that”这类凑字',
}
export function zhChange(label: string): string {
  const m = label.match(/^Removed (\d+) duplicate lines?$/)
  if (m) return `删除了 ${m[1]} 行重复内容`

  // optimizePro's wins are ASSEMBLED at runtime with numbers in them, so an exact-match
  // table can never catch them — they leaked to zh users as raw English. Match on shape.
  let g = label.match(/^Grade ([A-F]) → ([A-F]) — sharper description\/trigger$/)
  if (g) return `触发描述更精准了 —— 评分从 ${g[1]} 提到 ${g[2]}`
  g = label.match(/^−(\d+)% tokens \(([\d,]+) → ([\d,]+)\)$/)
  if (g) return `正文压缩 ${g[1]}% —— ${g[2]} → ${g[3]} token`
  g = label.match(/^Tighter wording \(grade ([A-F]), ([\d,]+) tokens\)$/)
  if (g) return `措辞更紧凑了（评分 ${g[1]}，${g[2]} token）`
  if (/^Behavior preserved/.test(label)) return '行为一字未改 —— 代码块完整、没有新增风险或权限'

  return lookup(CHANGE, label)
}

/* --------------------------------------------------- optimize-plan suggestions -- */

// The fixable-but-not-auto suggestions (optimizeSkill + optimizePlan synths). Shown in
// the improvement path. Keyed by exact English; the token synth carries a token count.
const SUGGESTION: Record<string, string> = {
  'Tighten the over-broad trigger (any/all/every) to the specific task it should fire on.':
    '把过于宽泛的触发（any/all/every）收窄到它该负责的具体任务。',
  'Move the detail sections into references/ files loaded on demand (progressive disclosure) — big per-trigger token win, but it restructures the bundle, so we leave it to you.':
    '把细节小节挪进按需加载的 references/ 文件（渐进式披露）——每次触发能省一大截 token，但会改动技能包结构，所以留给你自己定。',
  'Ship the missing referenced file(s) or fix the path — the skill will dead-link at load time otherwise.':
    '把缺失的被引用文件补上，或改对路径——否则技能加载时会撞死链。',
  'Narrow allowed-tools to what the skill actually uses (least privilege) — we don’t auto-remove a tool in case it’s used in a way we can’t see.':
    '把 allowed-tools 收窄到技能实际用到的（最小权限）——我们不自动删工具，以防它以我们看不到的方式在用。',
  'Add Bash (scoped to the commands it needs) to allowed-tools, or move the shell out — it will otherwise prompt/fail at runtime.':
    '在 allowed-tools 里加上 Bash（限定到它需要的命令），或把 shell 挪出去——否则运行时会弹权限或失败。',
  'Replace the embedded shell/script with a read-only tool call so the skill can’t run arbitrary code.':
    '把内嵌的 shell/脚本换成只读的工具调用，这样技能就不能执行任意代码。',
  'Remove direct secret/credential access; pass secrets via the runtime, not the skill file.':
    '去掉直接读取密钥/凭证的做法；让密钥从运行时传入，而不是写在技能文件里。',
  'Delete the instruction-override text (prompt-injection risk).':
    '删掉那段“覆盖指令”的文字（提示注入风险）。',
  'Sharpen the description — say exactly WHEN to use it and narrow the scope so it fires on the right task.':
    '把 description 写得更精准——明确“什么时候用”，并收窄范围，让它只在该触发的任务上触发。',
  'Tighten structure — add section headings, valid frontmatter, and make sure referenced files exist.':
    '完善结构——加上分节标题、合规的 frontmatter，并确保被引用的文件都在。',
  'Close to A — mostly tighter wording / sharper focus. The semantic rewrite (Pro) can take it the last step.':
    '离 A 很近了——主要是措辞更紧、聚焦更准。语义改写（Pro）能帮它走完最后一步。',
}
export function zhSuggestion(text: string): string {
  const m = text.match(/^~([\d,]+) tokens load on every call/)
  if (m) return `每次调用都要加载约 ${m[1]} 个 token——精简示例，或把细节挪到按需加载的 references/ 文件（渐进式披露）。`
  return lookup(SUGGESTION, text)
}
