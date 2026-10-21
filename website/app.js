'use strict';

// All examples are inert, local presentation data. This page has no SSH/API client.
(() => {
  const repo = 'https://github.com/jiamingZhao-zhao/ssh-cli';
  const text = {
    zh: {
      skip: '跳到内容', mainNav: '主导航', navWorkbench: '功能导览', navAgent: '给 Agent 用', navCommands: '命令参考', searchOpen: '搜索功能与命令', search: '搜索', start: '开始使用',
      release: '单文件 SSH 运维工具', heroLine1: 'SSH 客户端', heroLine2: '与日常运维工具',
      heroLead: '网页终端、文件传输、主机管理和命令行。人在工作台操作，脚本和 Agent 通过 CLI 调用，使用相同的主机与策略配置。',
      heroStart: '安装 ssh-cli', heroTour: '浏览功能', heroFootnote: '本地运行 · 开源 · 无需 Python / Node.js / Go 运行环境',
      proofTitle: '命令行用法', example: '示例 · 不连接服务器', proofRequest: '查看主机、检查策略、执行只读命令',
      proofHost: '查看主机', explicitAlias: '明确别名', proofPolicy: '检查策略', proofExecute: '读取磁盘', proofOutcome: '区分成功、失败和不确定结果',
      proofOutcomeBody: '响应丢了，不代表没执行。先核验状态，再决定下一步。', proofLink: '选择主机和命令，查看策略判断',
      platforms: '支持的平台', platformLabel: '一个可执行文件', download: '下载发布包 ↗',
      workbenchTitle: '工作台功能', workbenchLead: '点击左侧菜单查看用途、具体操作和注意事项。优先介绍终端、主机、监控和传输，再看配置、策略与维护。',
      railTitle: '你的 SSH 工作台', featureModules: '功能模块', railFootnote: '同一份配置。网页、CLI 与 Agent 共用。', featureProof: '用现有命令完成 · 示例，不会自动执行', agentAngle: 'Agent 使用价值', featureDocs: '查看命令说明',
      agentEyebrow: 'CLI / JSON / Skill', agentTitle: 'Agent 调用示例',
      agentLead: '下面是三种常见任务的调用顺序。重点是选准主机、执行前读策略，以及响应异常后先核验状态。',
      scenarioTabs: 'Agent 场景', scenarioRead: '只读排查', scenarioChange: '变更前检查', scenarioUnknown: '响应丢失后', scenarioCode: '可以交给 Agent 的调用顺序',
      specificIdentity: 'SSH agent 身份', specificIdentityBody: 'SSH agent 可绑定公钥指纹；身份缺失时失败，不静默改用别的密钥。',
      specificArguments: '远端参数保留', specificArgumentsBody: 'exec 保留分开的 argv，JSON 请求体与带空格参数不再靠 Agent 拼接猜测。',
      specificReuse: '显式连接复用', specificReuseBody: '显式启用 daemon 后可复用 exec 连接；普通调用不会自动启动或重试。',
      boundariesTitle: '默认行为与使用限制', boundariesLead: '以下行为以 v0.7.31 为准。建议在接入脚本或 Agent 前确认，尤其是生产只读和人工确认要求。',
      boundaryProd: '生产环境', boundaryProdTitle: 'prod 默认上限为只读', boundaryProdBody: '无限制交互终端在 readonly 下不可用；工具的文件操作仍检查权限和路径。',
      boundaryDanger: '危险命令', boundaryDangerTitle: '目录默认不等于拦截', boundaryDangerBody: '需要启用并选择规则才生效；启用后默认作用于 prod，也可显式指定其他环境。',
      boundaryHuman: '人工确认', boundaryHumanTitle: '确认门留给真实的交互终端', boundaryHumanBody: '非交互 Agent 不能用 --yes 绕过。standard/admin 的人工终端不逐条检查按键命令。',
      boundaryAudit: '本地审计', boundaryAuditTitle: '能记录和核验，也有信任前提', boundaryAuditBody: '本地 HMAC 无法抵抗同时掌握签名密钥和日志的人；这不是独立的远端防篡改系统。',
      installTitle: '安装与接入', installLead: '把仓库链接交给能读取仓库、执行本地命令的 Agent。它会准备 CLI 和 Skill，验证完成后，展示路径、版本与最短用法。',
      installNote: 'CLI 是 Skill 的硬性依赖。主机与凭据仍由你在 Agent 实际运行的环境中配置；安装不会自动连接服务器。', skillGuide: '查看各 Agent 安装说明',
      installMethods: '安装方式', installAgent: '交给 Agent', copy: '复制链接', installDetails: '安装细节 ↗', releaseNotes: '版本记录', source: '查看源码 ↗',
      footerLine: 'SSH 终端、文件管理与命令行运维。', searchTitle: '搜索功能与命令', searchPlaceholder: '如：文件、exec、--agent-key',
      searchHint: '↑ ↓ 选择 · Enter 打开 · Esc 关闭', close: '关闭', manualCopy: '手动复制', emptySearch: '没有匹配项。试试命令名、参数或功能名称。', searchCommands: '命令', searchAll: '打开完整命令参考', searchLoading: '正在读取命令索引…', searchFailed: '命令索引未加载，可直接打开命令参考。',
      copied: '已复制', copying: '复制中…', copyCommand: '复制命令', copyError: '无法访问剪贴板，请在下方选中内容手动复制。', copySuccess: '已复制，可以交给 Agent 或粘贴到终端。',
      navLab: '策略示例', featureSelect: '选择功能', featureSteps: '具体操作步骤', labTitle: '执行前的策略检查',
      labLead: '选一台示例主机和一条命令，查看允许、拒绝或需要人工确认的原因。切换规则范围，可比较测试与生产的差异。',
      labHost: '目标主机', labCommand: '待检查命令', labScope: '危险命令目录中的 mkfs 规则', labScopeOff: '未启用（默认）', labScopeProd: '启用规则 · 默认仅 prod', labScopeBoth: '启用规则 · prod 和 test',
      labConfigNote: '示例为 test 额外配置了 systemctl restart 确认规则；prod 使用内置只读上限。格式化命令只参与本地策略解释，不会执行。',
      labMode: '有效模式', labEnforced: '危险规则在此目标生效', labActive: '选中的生效规则', labCheckLabel: '在自己的配置中检查同一条命令：', labCopy: '复制检查命令', labManualCopy: '手动复制检查命令',
      labOutput: 'policy explain 输出节选', labOutputNote: '这是检查命令的退出码，不是远端执行结果。当前页面不读取你的主机配置，也不连接服务器。',
      labConfig: '查看示例配置与数据来源', labConfigBody: '两台主机仅使用文档地址 192.0.2.10 / 192.0.2.20。分组引用 standard 模式的示例策略，confirm 包含 systemctl restart；prod 的 readonly 上限仍生效。危险目录只选择 mkfs，按上方开关调整范围。', labSource: '查看对应版本源码 ↗',
      labAllowTitle: '策略允许', labAllowBody: '解释结果为 allowed: true，且不需要确认。它表示通过了当前配置的策略检查；实际连接与执行仍可能失败。',
      labConfirmTitle: '需要人工确认', labConfirmBody: '命中 systemctl restart 确认规则。解释命令本身返回 0，但实际执行需要交互式确认，非交互 Agent 应停下。',
      labDenyTitle: '策略拒绝', labDenyBody: '解释结果为 allowed: false，检查命令返回 253。不要执行，也不要通过改写命令绕过。具体命中原因保留在 findings 中。',
      groups: ['日常高频', '目标与操作边界', '记录与维护'], title: 'ssh-cli · SSH 客户端与日常运维工具'
    },
    en: {
      skip: 'Skip to content', mainNav: 'Main navigation', navWorkbench: 'Explore', navAgent: 'For agents', navCommands: 'Commands', searchOpen: 'Search features and commands', search: 'Search', start: 'Get started',
      release: 'SSH operations', heroLine1: 'SSH client', heroLine2: 'and operations tools',
      heroLead: 'A web terminal, file transfers, host management and a CLI. Use the workspace directly, or call the same configured hosts and policies from scripts and agents.',
      heroStart: 'Install ssh-cli', heroTour: 'Explore features', heroFootnote: 'Local · Open source · No Python, Node.js or Go runtime required',
      proofTitle: 'CLI usage', example: 'Example · no server connection', proofRequest: 'List hosts, inspect policies, run a read-only check',
      proofHost: 'Identify the target', explicitAlias: 'Explicit alias', proofPolicy: 'Read the boundaries', proofExecute: 'Run the check', proofOutcome: 'Success, failure and unknown outcomes',
      proofOutcomeBody: 'A lost response does not mean nothing ran. Verify state before taking the next step.', proofLink: 'Inspect a command',
      platforms: 'Supported platforms', platformLabel: 'One executable', download: 'Download a release ↗',
      workbenchTitle: 'Workspace features', workbenchLead: 'Select a menu for its purpose, steps and limitations. Start with terminals, hosts, monitoring and transfers, then explore configuration and maintenance.',
      railTitle: 'Your SSH workspace', featureModules: 'Feature modules', railFootnote: 'One configuration for the UI, CLI and agent.', featureProof: 'Existing commands · examples only, never executed here', agentAngle: 'What an agent gains', featureDocs: 'Open command reference',
      agentEyebrow: 'CLI / JSON / Skill', agentTitle: 'Agent command examples',
      agentLead: 'Three common workflows: choose the right host, inspect policies before a change, and verify state after an abnormal response.',
      scenarioTabs: 'Agent scenarios', scenarioRead: 'Read-only checks', scenarioChange: 'Before changes', scenarioUnknown: 'Lost responses', scenarioCode: 'A sequence an agent can follow',
      specificIdentity: 'SSH agent identity', specificIdentityBody: 'Select an SSH agent key by fingerprint. A missing identity fails instead of silently switching keys.',
      specificArguments: 'Remote arguments', specificArgumentsBody: 'exec preserves separate argv, including JSON bodies and arguments with spaces. No guesswork when joining quotes.',
      specificReuse: 'Opt-in connection reuse', specificReuseBody: 'An explicitly started daemon can reuse exec connections. Ordinary calls neither auto-start it nor retry.',
      boundariesTitle: 'Defaults and limitations', boundariesLead: 'Behavior as of v0.7.31. Review these defaults before using scripts or agents, especially production readonly mode and interactive confirmation.',
      boundaryProd: 'Production', boundaryProdTitle: 'prod defaults to a readonly ceiling', boundaryProdBody: 'Unrestricted terminals are unavailable in readonly mode. Tool file operations still check capabilities and paths.',
      boundaryDanger: 'Dangerous commands', boundaryDangerTitle: 'A catalog entry is not an active block', boundaryDangerBody: 'Enable enforcement and select rules first. Its default scope is prod; other environments can be named explicitly.',
      boundaryHuman: 'Human confirmation', boundaryHumanTitle: 'Confirmation requires a real interactive TTY', boundaryHumanBody: 'A noninteractive agent cannot bypass it with --yes. Human terminals in standard/admin do not inspect every keystroke command.',
      boundaryAudit: 'Local audit', boundaryAuditTitle: 'Records and verification have trust assumptions', boundaryAuditBody: 'Local HMAC cannot defeat someone holding both the signing key and logs. It is not an independent remote tamper-proof store.',
      installTitle: 'Installation', installLead: 'Give the repository link to an agent that can read repositories and run local commands. It prepares the CLI and skill, verifies setup, then reports paths, versions and a short usage guide.',
      installNote: 'The CLI is mandatory for the skill. Configure hosts and credentials in the agent’s execution environment. Installation does not connect to servers.', skillGuide: 'Read the agent setup guide',
      installMethods: 'Installation methods', installAgent: 'With an agent', copy: 'Copy link', installDetails: 'Install details ↗', releaseNotes: 'Release notes', source: 'View source ↗',
      footerLine: 'SSH terminals, file management and command-line operations.', searchTitle: 'Search features and commands', searchPlaceholder: 'Try files, exec or --agent-key',
      searchHint: '↑ ↓ select · Enter open · Esc close', close: 'Close', manualCopy: 'Copy manually', emptySearch: 'No matches. Try a command name, flag or feature.', searchCommands: 'Command', searchAll: 'Open full command reference', searchLoading: 'Loading command index…', searchFailed: 'Command index unavailable. Open the command reference directly.',
      copied: 'Copied', copying: 'Copying…', copyCommand: 'Copy command', copyError: 'Clipboard unavailable. Select the text below and copy it manually.', copySuccess: 'Copied. Send it to your agent or paste it into your terminal.',
      navLab: 'Policy examples', featureSelect: 'Choose a feature', featureSteps: 'How to use it', labTitle: 'Inspect a command',
      labLead: 'Choose a sample host and command to see why it is allowed, denied or requires confirmation. Change rule scope to compare test and production behavior.',
      labHost: 'Target host', labCommand: 'Command to inspect', labScope: 'mkfs rule from the dangerous catalog', labScopeOff: 'Disabled (default)', labScopeProd: 'Enabled · prod only (default scope)', labScopeBoth: 'Enabled · prod and test',
      labConfigNote: 'The example adds a systemctl restart confirmation rule for test. prod keeps its builtin readonly ceiling. Formatting commands are only inspected locally, never executed.',
      labMode: 'Effective mode', labEnforced: 'Dangerous rules enforced here', labActive: 'Selected active rules', labCheckLabel: 'Inspect the command against your own configuration:', labCopy: 'Copy inspection command', labManualCopy: 'Copy inspection command manually',
      labOutput: 'policy explain output excerpt', labOutputNote: 'This exit code belongs to inspection, not remote execution. The page neither reads your host configuration nor connects to servers.',
      labConfig: 'Example configuration and data source', labConfigBody: 'Hosts use documentation addresses 192.0.2.10 / 192.0.2.20. Both groups reference a standard example policy with systemctl restart in confirm. prod still has its readonly ceiling. The dangerous catalog selects only mkfs, with scope chosen above.', labSource: 'Read the matching source version ↗',
      labAllowTitle: 'Allowed by policy', labAllowBody: 'allowed is true and no confirmation is required. This passes the configured policy check; connecting and executing may still fail.',
      labConfirmTitle: 'Human confirmation required', labConfirmBody: 'The systemctl restart confirmation rule matched. Inspection returns 0, but actual execution requires an interactive TTY. A noninteractive agent must stop.',
      labDenyTitle: 'Denied by policy', labDenyBody: 'allowed is false and inspection exits 253. Do not execute or rewrap the command to evade the rule. The actual matching findings are retained in the output.',
      groups: ['Everyday work', 'Targets & boundaries', 'Records & maintenance'], title: 'ssh-cli · SSH client and operations toolkit'
    }
  };

  // The module IDs and names map to internal/ui/web/index.html. Grouping here
  // prioritizes the product tour and does not reorder the application's sidebar.
  const features = [
    { id: 'terminal', group: 0, icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
      command: 'ssh-cli ui\nssh-cli exec -H demo --json -- df -h\nssh-cli upload -H demo ./app.jar /tmp/app.jar --json',
      zh: { nav: '终端', title: '终端、文件和主机监控', description: '多标签终端、目录树、传输队列与主机监控在一个工作区。排查、传文件、回看历史，始终围绕当前主机。', benefits: [['少切几个窗口', '终端回看搜索、字号调整、中文输入与粘贴，配合当前主机的文件和监控。'], ['传输过程看得懂', '区分传输、提交和待核验；文件区默认约占三分之一，拖动不牵动左侧概况。']], agent: '人在终端里处理问题，Agent 用 exec、ls、upload 等结构化接口做事；共享主机配置，不依赖模拟键盘敲命令。', boundary: 'standard/admin 的人工终端不逐条套用命令策略；readonly 环境拒绝无限制终端。' },
      en: { nav: 'Terminal', title: 'Terminal, files and host monitoring', description: 'Terminal tabs, a directory tree, transfers and host metrics stay together. Investigate, move files and revisit history in the context of the current host.', benefits: [['Fewer window switches', 'Search scrollback, adjust type, paste and enter CJK text alongside files and monitoring.'], ['Understand each transfer stage', 'Separate transfer, commit and verification. Resizing the lower file panel does not move the left overview.']], agent: 'People use the terminal; agents use structured exec, ls and upload calls. They share host configuration without simulating keystrokes.', boundary: 'Human terminals in standard/admin do not inspect commands per keystroke. Readonly environments refuse unrestricted terminals.' } },
    { id: 'hosts', group: 0, icon: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/>', command: 'ssh-cli host list --json\nssh-cli policy show -H demo --json',
      zh: { nav: '主机', title: '主机地址与认证配置', description: '统一管理地址、端口、用户、认证与跳板引用。每次操作指向明确的主机别名，减少环境和机器之间的混淆。', benefits: [['凭据留在本地配置', '密码引用、私钥路径或 SSH agent 身份，不必让 Agent 在提示词里反复接触口令。'], ['选择明确的身份', '可指定 agentKey 公钥指纹；需要的密钥不存在时直接失败。']], agent: '先列清单再显式传 -H。已有目标与认证可复用，避免凭聊天记忆猜 IP、用户或私钥。', boundary: 'Skill 不会把本地密钥和配置自动同步到云端 Agent。' },
      en: { nav: 'Hosts', title: 'Host addresses and authentication', description: 'Keep addresses, ports, users, authentication and jump-host references together. An explicit alias reduces ambiguity between machines and environments.', benefits: [['Credentials stay in configuration', 'Use password references, identity paths or SSH agent authentication instead of credentials in prompts.'], ['Choose the required identity', 'An agentKey fingerprint selects a public key. If the key is absent, authentication fails.']], agent: 'List registered hosts, then pass -H explicitly. Reuse configured targets and authentication instead of guessing an IP or key from chat history.', boundary: 'A skill does not automatically transfer local keys or configuration to cloud agents.' } },
    { id: 'home', group: 0, icon: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>', command: 'ssh-cli host list --json\nssh-cli status -H demo --json',
      zh: { nav: '概览', title: '配置概览与主机状态', description: '工作台概览把主机、分组、环境和操作入口放在一起；连接主机后，在终端工作区查看 CPU、内存、磁盘、进程和网络采样。', benefits: [['配置入口集中', '先知道有哪些目标和环境，再进入具体主机，减少无上下文的操作。'], ['状态有更新时间', '监控区区分缺失数据与零值；采样时间帮助判断眼前的信息是否足够新。']], agent: '使用 status --json 做健康检查，得到机器状态。网页概览负责配置总览，监控采样不等于告警平台。', boundary: 'noDataOutflow 会限制监控与进程详情；缺失值不应被当成健康或 0。' },
      en: { nav: 'Overview', title: 'Inventory and host status', description: 'The overview brings hosts, groups, environments and entry points together. After connecting, the terminal workspace shows CPU, memory, disk, processes and network samples.', benefits: [['Context before action', 'See available targets and environments before opening a host.'], ['Freshness is visible', 'The monitor separates missing data from zero, with timestamps for recent samples.']], agent: 'Use status --json for host health. The web overview is inventory context; monitoring samples are not a full alerting platform.', boundary: 'noDataOutflow restricts metrics and process details. Missing data does not mean zero or healthy.' } },
    { id: 'relay', group: 0, icon: '<rect x="2" y="5" width="6" height="13" rx="1"/><rect x="16" y="5" width="6" height="13" rx="1"/><path d="M9 10h6m-2-2 2 2-2 2m2 3H9m2-2-2 2 2 2"/>', command: 'ssh-cli relay --from demo-test:/srv/app/app.jar --to demo-prod:/tmp/app.jar --json',
      zh: { nav: '跨机拷贝', title: '经本机中继远端文件', description: '通过本机进程把单个远端文件流式中继到另一台主机，完成后核对目标内容。无需先下载到桌面，再手工上传。', benefits: [['传输不留本地明文副本', '数据经当前进程中转，使用同一份主机清单和认证。'], ['跨环境要说清楚', '来源、目标、路径和跨环境限制明确展示，受保护目的路径仍需确认。']], agent: '用 --from 和 --to 表达两个独立端点，避免把复制误当成在某一台主机执行的单端操作。', boundary: '这是经本机的文件中继，不是远端直传或 SSH 跳板；跨环境与策略检查仍然适用。' },
      en: { nav: 'Relay', title: 'Relay files through the local process', description: 'Stream one remote file through the local process to another host, then verify the destination. Skip the manual download-then-upload routine.', benefits: [['No local plaintext copy', 'Data passes through the process using existing host inventory and authentication.'], ['Explicit cross-environment intent', 'Source, destination and paths stay clear. Protected destinations still require confirmation.']], agent: 'Use --from and --to to name two endpoints. A relay is not a single-host operation selected with -H.', boundary: 'This is a local-process relay, not direct server-to-server transfer or an SSH jump host. Cross-environment and policy checks still apply.' } },
    { id: 'envs', group: 1, icon: '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5M3 17l9 5 9-5"/>', command: 'ssh-cli env list --json\nssh-cli policy show -H demo --json',
      zh: { nav: '环境', title: '环境与权限上限', description: 'dev、test、preprod、prod 把环境含义落实到权限上限与默认策略，而不只是一段容易忽略的标签。', benefits: [['prod 默认只读', '有效模式受环境上限约束，单台主机的模式不能静默越过上限。'], ['数据流出也有约束', 'noDataOutflow 可限制下载、监控和历史正文等数据返回。']], agent: 'policy show 返回 envRules。Agent 在执行前能读到 maxMode 与数据流出限制，再决定是否需要人工接手。', boundary: '环境限制只覆盖经工具处理的操作；修改环境归属也不是绕过权限的方法。' },
      en: { nav: 'Envs', title: 'Environments and permission ceilings', description: 'dev, test, preprod and prod map environment names to mode ceilings and default policies, rather than a label that is easy to overlook.', benefits: [['prod defaults to readonly', 'The effective mode is clamped by the environment ceiling. A host mode does not silently exceed it.'], ['Control data flowing out', 'noDataOutflow can restrict downloads, metrics and history bodies.']], agent: 'policy show exposes envRules, including maxMode and data restrictions, before an agent decides whether to proceed or involve a person.', boundary: 'Environment limits cover operations mediated by the tool. Changing an environment is not a way around permissions.' } },
    { id: 'policy', group: 1, icon: '<path d="m12 3 8 3v6c0 5-3.4 7.8-8 9-4.6-1.2-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>', command: 'ssh-cli policy show -H demo --json\nssh-cli policy explain -H demo -- "systemctl restart nginx"',
      zh: { nav: '危险命令', title: '危险命令与执行前检查', description: '把建议目录与实际生效的拦截规则分开。查看当前主机合并后的规则、确认门和受保护路径，再解释一条具体命令。', benefits: [['看得见真正生效的规则', 'v0.7.31 的危险命令目录默认未启用；启用并选定规则后才拦截，默认范围为 prod。'], ['变更前无需试错', 'policy show 和 policy explain 只读本地配置，不连接服务器、不执行远端命令。']], agent: '先读取 confirm、protectedPaths、envRules 和 dangerousCommands.active / enforcedHere，避免用一次失败的写请求来发现限制。', boundary: '只加启用开关还不够，还要选择规则。只读上限等其他限制独立生效；目录匹配本身不等于拒绝。' },
      en: { nav: 'Commands', title: 'Dangerous commands and policy checks', description: 'Separate the suggested catalog from active blocking rules. Inspect the host’s merged policy, confirmation gates and protected paths, then explain a specific command.', benefits: [['See what is actually enforced', 'In v0.7.31 the catalog is off by default. Enable it and select rules to enforce them; prod is the default scope.'], ['No trial write needed', 'policy show and policy explain read local configuration. They neither connect nor run a remote command.']], agent: 'Read confirm, protectedPaths, envRules and dangerousCommands.active / enforcedHere before attempting a change.', boundary: 'The enable switch alone is insufficient; select rules too. Readonly ceilings remain independent. Matching the catalog alone does not mean denial.' } },
    { id: 'groups', group: 1, icon: '<rect x="3" y="4" width="7" height="6" rx="1"/><rect x="14" y="4" width="7" height="6" rx="1"/><rect x="3" y="14" width="7" height="6" rx="1"/><path d="M14 17h7m-3.5-3.5v7"/>', command: 'ssh-cli group list --json\nssh-cli policy show -H demo --json',
      zh: { nav: '分组', title: '业务分组与策略复用', description: '用分组组织同一业务和环境中的主机，集中管理策略引用与受保护路径，让主机配置更一致。', benefits: [['规则有组织地复用', '把共同设置放在分组，减少逐台维护时遗漏或配错。'], ['看合并后的实际结果', '配置来源可以多层，执行前仍按目标主机解析最终有效策略。']], agent: '清单先表达业务归属，再按主机读取最终策略。Agent 无需从名字猜每台机器继承了什么。', boundary: '分组不是独立权限沙箱；判断能否执行应查看目标主机的最终策略。' },
      en: { nav: 'Groups', title: 'Groups and shared policy references', description: 'Organize hosts by business and environment. Manage shared policy references and protected paths together.', benefits: [['Reuse common settings', 'Reduce drift and omissions when maintaining several hosts.'], ['Inspect the merged result', 'Settings can have multiple sources. Resolve the effective policy for the target before execution.']], agent: 'Inventory provides business context; a host policy shows the final rules. No need to infer inherited permissions from names.', boundary: 'A group is not an independent sandbox. Inspect the target’s effective policy to decide what may run.' } },
    { id: 'tags', group: 1, icon: '<path d="M4 12V5h7l9 9-7 7-9-9Z"/><circle cx="8" cy="9" r="1"/>', command: 'ssh-cli host list --json',
      zh: { nav: '标签', title: '按角色筛选主机', description: '在分组之外，用 app、db、nginx 等标签表达角色。工作台可按标签查看主机，不必为了另一种检索方式重建分组。', benefits: [['一台机器，多种检索维度', '业务分组与技术角色同时保留，避免单一目录结构越用越复杂。'], ['目标范围更容易复核', '先查看标签下有哪些别名，再决定这次任务真正需要处理的主机。']], agent: '标签用于发现候选目标。让 Agent 先核对清单，再对具体别名执行，减少范围误解。', boundary: '标签帮助选择，不授予权限；选中的每台主机仍受自身策略限制。' },
      en: { nav: 'Tags', title: 'Find hosts by role', description: 'Labels such as app, db or nginx add a second way to find hosts, without restructuring business groups.', benefits: [['Several views of one host', 'Keep business organization and technical roles without growing a rigid directory tree.'], ['Review the target set', 'See the aliases behind a label before choosing which machines a task should touch.']], agent: 'Tags discover candidate targets. Review the inventory and execute against explicit aliases to keep scope understandable.', boundary: 'Tags select hosts; they do not grant permissions. Each target retains its own policy.' } },
    { id: 'audit', group: 2, icon: '<path d="M6 3h12v18H6zM9 7h6M9 11h6M9 15h4"/>', command: 'ssh-cli audit list --host demo --json\nssh-cli audit verify --json',
      zh: { nav: '审计', title: '操作记录与完整性检查', description: '按主机、时间和结果回看工具操作。失败和不确定状态留下上下文，排查时不用只凭聊天记录推断发生了什么。', benefits: [['复盘有依据', '工具记录 CLI / UI 操作来源，可筛选、分页并导出 CSV。'], ['完整性可以核验', '显式建立保护基线后，可用 audit verify 检查；历史脱敏仍是启发式的。']], agent: '响应异常时先查已有记录和远端状态，再报告是否完成。审计是核验线索，不是自动重试授权。', boundary: '人工终端不记录每个按键；本地 HMAC 有密钥和检查点的信任前提，也不能回滚已发生的变更。' },
      en: { nav: 'Audit', title: 'Operation records and integrity checks', description: 'Review tool operations by host, time and outcome. Failed and uncertain operations retain context beyond a chat transcript.', benefits: [['Evidence for a review', 'Filter, paginate and export CSV, with CLI / UI sources recorded.'], ['Verify integrity', 'After explicitly creating a protection baseline, audit verify checks it. Redaction remains heuristic.']], agent: 'After an abnormal response, inspect existing records and remote state before claiming completion. Records are evidence, not authorization to retry.', boundary: 'Human terminal keystrokes are not individually logged. Local HMAC relies on trusted keys and checkpoints, and cannot undo changes.' } },
    { id: 'bundle', group: 2, icon: '<path d="m3 7 9-4 9 4-9 4-9-4Zm0 0v10l9 4 9-4V7m-9 4v10"/>', command: 'ssh-cli config export\nssh-cli session list --json',
      zh: { nav: '运维', title: '配置迁移与维护', description: '迁出、迁入配置包，查看策略 HMAC 状态，清理较早审计，并保留会话列表与执行的高级入口。', benefits: [['配置可迁移，口令不打包', '导出主机、环境、策略和密钥引用，不导出明文密码或主密钥。'], ['高级维护有位置', '策略签名状态和旧审计清理集中展示，日常终端仍保持简洁。']], agent: '能识别这是配置迁移而非凭据迁移。另一台运行环境仍需准备自己的密钥与凭据。', boundary: '导入可能改变目标或权限，需要相应确认；UI 会话只活在 UI 进程里，CLI session 不是同一个会话池。' },
      en: { nav: 'Ops', title: 'Configuration migration and maintenance', description: 'Export and import configuration, inspect policy HMAC state, clean older audit records and access advanced session and execution views.', benefits: [['Move settings, not passwords', 'Bundles contain hosts, environments, policies and key references, not plaintext passwords or the master key.'], ['A place for maintenance', 'Keep signature state and older-record cleanup available without crowding the terminal workspace.']], agent: 'Configuration migration is not credential migration. The new execution environment still needs its own keys and credentials.', boundary: 'Imports that change targets or widen permissions may need confirmation. UI sessions live in the UI process, separate from CLI session pools.' } },
    { id: 'settings', group: 2, icon: '<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="15" cy="17" r="3"/>', command: 'ssh-cli ui\nssh-cli version',
      zh: { nav: '设置', title: '浏览器偏好与会话时限', description: '调整主题、紧凑表格、超时、分页，以及会话空闲与最长寿命。把高频交互调到适合自己的节奏。', benefits: [['浏览偏好留在浏览器', '主题、分页和表单默认值在当前浏览器保存，不会暗中写成所有 Agent 的参数。'], ['会话寿命明确配置', '空闲和最长时限写入 hosts.yaml，和命令行 session 使用同一组字段。']], agent: '浏览器偏好与 CLI 的执行参数分开理解。具体命令的 --help 仍是该版本支持选项的依据。', boundary: '修改浏览器默认值不代表修改 CLI 全局权限或放宽策略。设置页不保存密码。' },
      en: { nav: 'Settings', title: 'Browser preferences and session limits', description: 'Adjust theme, compact tables, timeouts, pagination and session lifetimes. Tune the repeated interactions to your workflow.', benefits: [['Browser preferences stay local', 'Theme, pagination and form defaults belong to the current browser, not every agent’s command arguments.'], ['Explicit session lifetime', 'Idle and maximum lifetime settings use hosts.yaml fields shared with CLI sessions.']], agent: 'Distinguish browser preferences from CLI execution arguments. A command’s --help remains the authority for flags supported by that version.', boundary: 'Changing a browser default does not change global CLI permissions or widen a policy. This page does not save passwords.' } }
  ];

  const featureSteps = {
    terminal: { zh: ['运行 ssh-cli ui，在终端页选择已登记的主机并打开连接。', '在同一工作区使用目录树、文件表与历史；文件传输在左侧队列查看。', '需要 Agent 检查时，用明确的 -H 别名调用 exec / ls 等命令，读取 JSON 结果。'], en: ['Run ssh-cli ui, select a registered host on the Terminal page and open a connection.', 'Use the directory tree, file table and history in the workspace; inspect transfers in the left queue.', 'For agent checks, call exec / ls with an explicit -H alias and read the JSON result.'] },
    hosts: { zh: ['在主机页登记地址、登录用户和认证方式，设置便于辨认的别名。', '如使用 SSH agent，可从已加载公钥中选择身份；需要跳板时引用已登记主机。', '执行前读取 host list --json，确认别名和所属环境，再操作该主机。'], en: ['Register the address, user and authentication method with a recognizable alias.', 'For SSH agent authentication, select a loaded public key; reference a registered jump host if needed.', 'Read host list --json, verify the alias and environment, then select that host for the operation.'] },
    home: { zh: ['在概览页确认主机、分组与环境的配置数量和入口。', '进入终端并连接目标主机，查看监控区的 CPU、内存、磁盘与更新时间。', 'Agent 使用 status -H <alias> --json 读取状态；遇到缺失采样要明确说明。'], en: ['Review configured hosts, groups and environments from Overview.', 'Connect from Terminal to inspect CPU, memory, disk and sampling timestamps.', 'Agents can read status -H <alias> --json and explicitly report missing samples.'] },
    relay: { zh: ['在跨机拷贝页选择来源主机、来源文件、目标主机和目标路径。', '确认是否跨环境，以及目的路径是否受保护；按提示完成人工确认。', '提交后核对结果。响应中断时先检查目标文件，不直接再次复制。'], en: ['Choose source and destination hosts and paths on the Relay page.', 'Review environment crossing and protected destinations; complete requested human confirmation.', 'Check the final result. After an interrupted reply, inspect the destination before copying again.'] },
    envs: { zh: ['查看 dev、test、preprod、prod 的权限上限与默认策略。', '把业务分组归入实际环境；不要为执行一条命令临时把生产机器移到测试环境。', '通过 policy show 查看目标的 envRules 和最终 mode，而非仅依赖页面颜色。'], en: ['Inspect mode ceilings and default policies for dev, test, preprod and prod.', 'Assign business groups to their real environment; do not move a production host to test just to run a command.', 'Read envRules and effective mode from policy show instead of relying on a color label.'] },
    policy: { zh: ['在危险命令页区分建议目录、启用状态、已选规则和作用环境。', '执行变更前，先运行 policy show，再用 policy explain 检查准确的命令参数。', '需要确认则交给人工 TTY；被拒绝时停止。可在下方策略示例中比较结果。'], en: ['Distinguish catalog suggestions, the enable switch, selected rules and scope.', 'Before a change, use policy show and policy explain with the exact intended arguments.', 'Leave confirmation to a human TTY and stop on denial. Compare examples in the policy inspector below.'] },
    groups: { zh: ['在分组页按业务建立分组，选择环境并引用需要的命名策略。', '把主机归入对应分组，为共同保护的目录设置受保护路径。', '对具体主机运行 policy show，核对环境、分组与主机层合并后的结果。'], en: ['Create a business group, choose its environment and reference a named policy.', 'Assign hosts to the group and configure shared protected directories.', 'Run policy show for a host to inspect the merged environment, group and host result.'] },
    tags: { zh: ['在主机配置中设置角色标签，如 app、db、nginx。', '从标签页查看匹配的主机，先核对清单，不直接把检索结果当作变更授权。', '为具体任务确认目标别名；批量操作还要核对环境范围与各主机权限。'], en: ['Set role tags such as app, db or nginx on host configuration.', 'Review matching hosts on Tags; discovery results are not authorization for changes.', 'Confirm target aliases for a task, checking environment scope and policies for a batch.'] },
    audit: { zh: ['在审计页按时间、主机和结果筛选记录，需要进一步分析时导出 CSV。', '发现失败或 unknown，结合目标主机当前状态核验，不自动重放原操作。', '需要完整性检查时先按文档建立保护基线，再用 audit verify 验证。'], en: ['Filter records by time, host and outcome; export CSV for further analysis.', 'For failures or unknown outcomes, verify current remote state without replaying the operation.', 'For integrity checks, establish the documented protection baseline before audit verify.'] },
    bundle: { zh: ['在旧电脑的运维页生成导出，检查主机、策略和密钥引用。', '把配置包交给新电脑，在其运维页导入；密钥文件与凭据另行准备。', '导入涉及目标或权限变化时按要求确认；高级会话入口也在运维页。'], en: ['Export from the old machine and review hosts, policies and key references.', 'Import the bundle on the new machine; prepare key files and credentials separately.', 'Confirm target or permission changes when required. Advanced session entry points are also under Ops.'] },
    settings: { zh: ['在设置页调整主题、紧凑表格、分页和表单默认值。', '按实际需求设置会话空闲与最长寿命，保存后检查配置。', 'Agent 的命令超时等参数仍应显式传入，不假设继承浏览器里的偏好。'], en: ['Adjust theme, compact tables, pagination and form defaults in Settings.', 'Set appropriate idle and maximum session lifetimes, save and review the configuration.', 'Agents should still pass execution parameters such as timeouts explicitly rather than assume browser preferences apply.'] }
  };

  const scenarios = {
    read: {
      signal: 'READ FIRST', command: 'ssh-cli host list --json\nssh-cli policy show -H demo --json\nssh-cli status -H demo --json',
      zh: ['只读检查主机状态', '显式指定 -H，减少默认主机带来的歧义；JSON 让 Agent 读取状态，而不是猜终端文本。', '只读检查仍受当前主机策略与数据流出限制。', '目标明确 → 检查权限 → 读取状态 → 汇报结果'],
      en: ['Read-only host inspection', 'An explicit -H avoids ambiguity from defaults. JSON gives an agent structured data rather than terminal text to guess at.', 'Read-only checks still respect host policies and data restrictions.', 'Identify → inspect permissions → read state → report']
    },
    change: {
      signal: 'CHECK BEFORE CHANGE', command: 'ssh-cli policy show -H demo --json\nssh-cli policy explain -H demo -- "systemctl restart nginx"',
      zh: ['执行前检查确认要求', '先读确认门、受保护路径和环境上限，再解释具体命令。发现需要人工确认，就交回真实交互终端处理。', '这两条命令只读本地配置，不连接服务器。非交互 --yes 不会绕过确认。', '读取规则 → 解释命令 → 需要确认则停下'],
      en: ['Check confirmation requirements first', 'Read confirmation gates, protected paths and environment ceilings, then explain the exact command. Leave required confirmation to a human TTY.', 'Both commands read local configuration without connecting. Noninteractive --yes cannot bypass a gate.', 'Read rules → explain the command → stop for confirmation']
    },
    unknown: {
      signal: 'UNKNOWN ≠ NOT EXECUTED', command: 'ssh-cli audit list --host demo --json\nssh-cli ls -H demo /tmp --json',
      zh: ['丢失响应后的核验', '写操作或文件提交可能已经发生。先查已有审计，再读取目标目录等远端状态，保留尚不能确认的部分。', '目录存在或单条审计都不能单独证明内容正确；按原任务核验目标文件、服务或状态。', '保留 unknown → 查已有记录 → 核验远端 → 再决定'],
      en: ['Verification after a lost response', 'A write or file commit may already have happened. Read existing audit records and inspect relevant remote state, retaining any uncertainty.', 'A directory entry or one audit record alone does not prove correct contents. Verify the target file, service or state for the original task.', 'Keep unknown → review records → verify remote state → decide']
    }
  };
  const install = {
    agent: { command: repo, zh: ['把这个链接发给你的 Agent，并让它安装。', '先检查 CLI → 缺失时安装并校验 → 安装 Skill → 汇报结果'], en: ['Send this link to your agent and ask it to install.', 'Check CLI → install and verify if missing → install skill → report'] },
    unix: { command: 'curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh', zh: ['安装当前系统与架构的 CLI 发布包。', '下载发布包并验证校验和。随后运行 ssh-cli version；主机与 Skill 可按文档继续配置。'], en: ['Install the CLI release for your operating system and architecture.', 'Downloads and verifies release checksums. Run ssh-cli version afterward, then configure hosts and skills using the guide.'] },
    windows: { command: 'irm https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.ps1 | iex', zh: ['在 Windows PowerShell 中安装 CLI。', '默认安装到 %LOCALAPPDATA%\\ssh-cli\\bin，验证校验和；新终端中运行 ssh-cli version。'], en: ['Install the CLI in Windows PowerShell.', 'Installs to %LOCALAPPDATA%\\ssh-cli\\bin with checksum verification. Run ssh-cli version in a new terminal.'] }
  };
  const $ = id => document.getElementById(id);
  let language = 'zh';
  let currentFeature = 'terminal';
  let currentScenario = 'read';
  let currentInstall = 'agent';
  let searchReturnFocus = null;
  let copyGeneration = 0;
  let labGeneration = 0;
  let commandIndexState = 'idle';
  try { if (localStorage.getItem('ssh-cli-site-language') === 'en') language = 'en'; } catch { /* Storage can be unavailable in private/file contexts. */ }
  const languageQuery = new URL(location.href).searchParams.get('lang');
  if (languageQuery === 'zh' || languageQuery === 'en') language = languageQuery;
  function commandLink(id = '', query = '') { return 'commands.html?lang=' + language + (query ? '&q=' + encodeURIComponent(query) : '') + (id ? '#' + encodeURIComponent(id) : ''); }

  function setText(id, value) { $(id).textContent = value; }
  function makeIcon(path) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('aria-hidden', 'true');
    svg.innerHTML = path; // Static, repository-owned SVG paths only.
    return svg;
  }
  function renderFeatureTabs() {
    const root = $('feature-tabs'); root.replaceChildren();
    $('feature-mobile').replaceChildren();
    text[language].groups.forEach((name, index) => {
      const options = document.createElement('optgroup'); options.label = name;
      const group = document.createElement('div'); group.className = 'feature-tab-group'; group.setAttribute('role', 'presentation');
      const label = document.createElement('span'); label.className = 'feature-tab-group-label'; label.textContent = name; label.setAttribute('aria-hidden', 'true');
      const buttons = document.createElement('div'); buttons.className = 'feature-tab-group-buttons'; buttons.setAttribute('role', 'presentation');
      features.filter(f => f.group === index).forEach(feature => {
        const option = document.createElement('option'); option.value = feature.id; option.textContent = feature[language].nav; options.append(option);
        const button = document.createElement('button'); button.id = 'tab-' + feature.id; button.className = 'feature-tab'; button.type = 'button'; button.setAttribute('role', 'tab');
        button.setAttribute('aria-controls', 'feature-panel'); button.setAttribute('aria-selected', String(feature.id === currentFeature)); button.tabIndex = feature.id === currentFeature ? 0 : -1;
        const title = document.createElement('span'); title.textContent = feature[language].nav;
        const arrow = document.createElement('span'); arrow.className = 'tab-arrow'; arrow.textContent = '↗'; arrow.setAttribute('aria-hidden', 'true');
        button.append(makeIcon(feature.icon), title, arrow);
        button.addEventListener('click', () => selectFeature(feature.id));
        buttons.append(button);
      });
      group.append(label, buttons); root.append(group);
      $('feature-mobile').append(options);
    });
  }
  function selectFeature(id) {
    const feature = features.find(f => f.id === id);
    if (!feature) return;
    currentFeature = id;
    $('feature-mobile').value = id;
    const content = feature[language];
    document.querySelectorAll('.feature-tab').forEach(button => {
      const selected = button.id === 'tab-' + id;
      button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1;
    });
    $('feature-panel').setAttribute('aria-labelledby', 'tab-' + id);
    setText('feature-position', String(features.indexOf(feature) + 1).padStart(2, '0') + ' / 11');
    setText('feature-category', text[language].groups[feature.group]);
    setText('feature-title', content.title); setText('feature-description', content.description); setText('feature-command', feature.command);
    setText('feature-agent', content.agent); setText('feature-boundary', content.boundary);
    $('feature-benefits').replaceChildren(...content.benefits.map(([title, description]) => {
      const row = document.createElement('div'), copy = document.createElement('div'), strong = document.createElement('strong'), p = document.createElement('p');
      strong.textContent = title; p.textContent = description; copy.append(strong, p); row.append(copy); return row;
    }));
    $('feature-steps').replaceChildren(...featureSteps[id][language].map(step => { const li = document.createElement('li'); li.textContent = step; return li; }));
    const command = { terminal:'ui', hosts:'host', home:'status', relay:'relay', envs:'env', policy:'policy-show', groups:'group', tags:'host-list', audit:'audit-list', bundle:'config', settings:'ui' };
    $('feature-docs').href = commandLink(command[id] || 'root');
  }
  function selectScenario(id) {
    const scenario = scenarios[id]; if (!scenario) return;
    currentScenario = id;
    document.querySelectorAll('[data-scenario]').forEach(button => { const selected = button.dataset.scenario === id; button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; });
    $('scenario-panel').setAttribute('aria-labelledby', 'scenario-' + id);
    setText('scenario-signal', scenario.signal); setText('scenario-command', scenario.command);
    ['scenario-title', 'scenario-description', 'scenario-rule', 'scenario-result'].forEach((target, index) => setText(target, scenario[language][index]));
  }
  function selectInstall(id) {
    const method = install[id]; if (!method) return;
    currentInstall = id; copyGeneration++;
    document.querySelectorAll('[data-install]').forEach(button => { const selected = button.dataset.install === id; button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; });
    $('install-panel').setAttribute('aria-labelledby', 'install-' + id);
    setText('install-command', method.command); setText('install-instruction', method[language][0]); setText('install-verification', method[language][1]);
    setText('copy-install', text[language][id === 'agent' ? 'copy' : 'copyCommand']); setText('copy-status', '');
    $('copy-install').dataset.state = 'default'; $('copy-install').disabled = false; $('manual-copy').hidden = true;
  }
  function renderLanguage() {
    document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en'; document.title = text[language].title;
    for (const [attribute, property] of [['data-i18n', 'textContent'], ['data-i18n-aria', 'aria-label'], ['data-i18n-placeholder', 'placeholder']]) {
      document.querySelectorAll('[' + attribute + ']').forEach(element => {
        const value = text[language][element.getAttribute(attribute)];
        if (property === 'textContent') element.textContent = value;
        else element.setAttribute(property, value);
      });
    }
    setText('language', language === 'zh' ? 'EN' : '中文');
    $('language').setAttribute('aria-label', language === 'zh' ? 'Switch to English' : '切换到中文');
    $('skill-guide').href = repo + '/blob/main/docs/skills' + (language === 'en' ? '.en' : '') + '.md';
    document.querySelectorAll('[data-command-reference]').forEach(link => { link.href = commandLink(); });
    renderFeatureTabs(); selectFeature(currentFeature); selectScenario(currentScenario); selectInstall(currentInstall); renderSearch(); renderLab();
  }
  function renderLab() {
    labGeneration++;
    const key = [$('lab-host').value, $('lab-scope').value, $('lab-command').value].join('/');
    const record = window.SSH_CLI_POLICY_EXAMPLES?.records[key];
    if (!record) {
      setText('lab-result-title', language === 'zh' ? '示例数据未加载' : 'Example data unavailable');
      setText('lab-result-description', language === 'zh' ? '请重新加载页面，或打开源码中的使用说明。' : 'Reload the page or read the linked usage guide.');
      $('copy-lab').disabled = true; return;
    }
    const result = record.explanation;
    const state = !result.allowed ? 'deny' : result.needsConfirm ? 'confirm' : 'allow';
    const keyPrefix = 'lab' + state[0].toUpperCase() + state.slice(1);
    setText('lab-decision', state === 'deny' ? '⊘ DENY' : state === 'confirm' ? '◇ CONFIRM' : '✓ ALLOW');
    $('lab-decision').dataset.state = state;
    setText('lab-exit', 'policy explain · exit ' + record.exitCode);
    setText('lab-result-title', text[language][keyPrefix + 'Title']);
    setText('lab-result-description', text[language][keyPrefix + 'Body']);
    setText('lab-mode', result.mode); setText('lab-enforced', String(result.dangerousCommands.enforcedHere));
    setText('lab-active', result.dangerousCommands.active.join(', ') || '—');
    setText('lab-json', JSON.stringify(result, null, 2));
    setText('lab-check-command', 'ssh-cli policy explain -H ' + result.host + ' --json -- "' + result.command + '"');
    setText('copy-lab', text[language].labCopy); setText('lab-copy-status', '');
    $('copy-lab').dataset.state = 'default'; $('copy-lab').disabled = false; $('lab-manual-copy').hidden = true;
  }
  function renderSearch() {
    const focusedId = document.activeElement?.dataset.searchId;
    const query = $('feature-search').value.trim().toLocaleLowerCase();
    const matches = features.filter(feature => {
      const content = feature[language];
      return [feature.id, feature.zh.nav, feature.en.nav, content.title, content.description, content.agent].join(' ').toLocaleLowerCase().includes(query);
    });
    const root = $('search-results'); root.replaceChildren();
    matches.forEach(feature => {
      const button = document.createElement('button'); button.className = 'search-result'; button.type = 'button';
      button.dataset.searchId = 'feature-' + feature.id;
      const label = document.createElement('span'); label.textContent = feature[language].nav;
      const group = document.createElement('span'); group.textContent = text[language].groups[feature.group];
      button.append(makeIcon(feature.icon), label, group);
      button.addEventListener('click', () => { closeSearch(false); selectFeature(feature.id); $('workbench').scrollIntoView(); (matchMedia('(max-width: 39.99rem)').matches ? $('feature-mobile') : $('tab-' + feature.id)).focus({ preventScroll: true }); });
      root.append(button);
    });
    const tokens = query.normalize('NFKC').split(/\s+/).filter(Boolean);
    const commands = (window.SSH_CLI_COMMAND_INDEX?.commands || []).filter(command => tokens.length ? tokens.every(token => [command.path, command.title, command.summary, command.searchFlags].join(' ').normalize('NFKC').toLocaleLowerCase().includes(token)) : ['exec','upload','host-list','policy-show'].includes(command.id)).slice(0, 8);
    commands.forEach(command => {
      const button = document.createElement('button'); button.className = 'search-result command-search-result'; button.type = 'button';
      button.dataset.searchId = 'command-' + command.id;
      const code = document.createElement('code'); code.textContent = command.path;
      const purpose = document.createElement('small'); purpose.textContent = language === 'zh' ? command.title : command.summary;
      const kind = document.createElement('span'); kind.textContent = text[language].searchCommands;
      button.append(code, purpose, kind); button.addEventListener('click', () => { location.href = commandLink(command.id); }); root.append(button);
    });
    const pending = commandIndexState === 'idle' || commandIndexState === 'loading';
    if (!matches.length && !commands.length && !pending && commandIndexState !== 'error') { const empty = document.createElement('p'); empty.className = 'search-empty'; empty.setAttribute('role', 'status'); empty.textContent = text[language].emptySearch; root.append(empty); }
    if (pending || commandIndexState === 'error') { const state = document.createElement('p'); state.className = 'search-empty'; state.setAttribute('role','status'); state.textContent = text[language][pending ? 'searchLoading' : 'searchFailed']; root.append(state); }
    const all = document.createElement('a'); all.className = 'search-reference-link'; all.href = commandLink('', query); all.textContent = text[language].searchAll + ' ↗'; root.append(all);
    if (focusedId && $('search-dialog').open) [...root.querySelectorAll('button')].find(button => button.dataset.searchId === focusedId)?.focus({preventScroll:true});
  }
  function loadCommandIndex() {
    if (commandIndexState !== 'idle') return;
    commandIndexState = 'loading';
    const script = document.createElement('script'); script.src = 'command-index.js';
    script.onload = () => { commandIndexState = window.SSH_CLI_COMMAND_INDEX?.commands?.length ? 'ready' : 'error'; renderSearch(); };
    script.onerror = () => { commandIndexState = 'error'; renderSearch(); };
    document.head.append(script);
  }
  function openSearch() {
    if ($('search-dialog').open) return;
    searchReturnFocus = document.activeElement; $('feature-search').value = ''; renderSearch();
    $('search-dialog').showModal(); $('feature-search').focus();
    loadCommandIndex();
  }
  function closeSearch(restore = true) { $('search-dialog').close(); if (restore && searchReturnFocus instanceof HTMLElement) searchReturnFocus.focus({ preventScroll: true }); }
  function tabKeys(event, selector, attribute, select, vertical = false) {
    const tabs = [...event.currentTarget.querySelectorAll(selector)];
    const index = tabs.indexOf(document.activeElement); if (index < 0) return;
    const next = vertical ? 'ArrowDown' : 'ArrowRight', previous = vertical ? 'ArrowUp' : 'ArrowLeft';
    let target;
    if (event.key === next) target = (index + 1) % tabs.length;
    if (event.key === previous) target = (index - 1 + tabs.length) % tabs.length;
    if (event.key === 'Home') target = 0;
    if (event.key === 'End') target = tabs.length - 1;
    if (target === undefined) return;
    event.preventDefault(); const button = tabs[target];
    select(attribute === 'id' ? button.id.replace('tab-', '') : button.getAttribute(attribute)); button.focus({ preventScroll: true });
  }
  $('feature-tabs').addEventListener('keydown', event => tabKeys(event, '[role="tab"]', 'id', selectFeature, true));
  $('feature-mobile').addEventListener('change', () => selectFeature($('feature-mobile').value));
  document.querySelector('.scenario-tabs').addEventListener('keydown', event => tabKeys(event, '[role="tab"]', 'data-scenario', selectScenario));
  document.querySelector('.install-tabs').addEventListener('keydown', event => tabKeys(event, '[role="tab"]', 'data-install', selectInstall));
  document.querySelectorAll('[data-scenario]').forEach(button => button.addEventListener('click', () => selectScenario(button.dataset.scenario)));
  document.querySelectorAll('[data-install]').forEach(button => button.addEventListener('click', () => selectInstall(button.dataset.install)));
  $('language').addEventListener('click', () => { language = language === 'zh' ? 'en' : 'zh'; try { localStorage.setItem('ssh-cli-site-language', language); } catch { /* Preference persistence is optional. */ } renderLanguage(); });
  $('copy-install').addEventListener('click', async () => {
    const generation = ++copyGeneration, command = install[currentInstall].command;
    $('copy-install').disabled = true; setText('copy-install', text[language].copying); $('copy-install').dataset.state = 'loading';
    try {
      await navigator.clipboard.writeText(command);
      if (generation !== copyGeneration) return;
      setText('copy-install', text[language].copied); setText('copy-status', text[language].copySuccess); $('copy-install').dataset.state = 'success';
    } catch {
      if (generation !== copyGeneration) return;
      setText('copy-install', text[language].copyCommand); setText('copy-status', text[language].copyError); $('copy-install').dataset.state = 'error';
      $('manual-copy').hidden = false; $('manual-copy').value = command; $('manual-copy').focus({ preventScroll: true }); $('manual-copy').select();
    } finally { if (generation === copyGeneration) $('copy-install').disabled = false; }
  });
  ['lab-host', 'lab-command', 'lab-scope'].forEach(id => $(id).addEventListener('change', renderLab));
  $('copy-lab').addEventListener('click', async () => {
    const generation = ++labGeneration, command = $('lab-check-command').textContent;
    $('copy-lab').disabled = true; $('copy-lab').dataset.state = 'loading'; setText('copy-lab', text[language].copying);
    try {
      await navigator.clipboard.writeText(command);
      if (generation !== labGeneration) return;
      setText('copy-lab', text[language].copied); setText('lab-copy-status', text[language].copySuccess); $('copy-lab').dataset.state = 'success';
    } catch {
      if (generation !== labGeneration) return;
      setText('copy-lab', text[language].labCopy); setText('lab-copy-status', text[language].copyError); $('copy-lab').dataset.state = 'error';
      $('lab-manual-copy').hidden = false; $('lab-manual-copy').value = command; $('lab-manual-copy').focus({ preventScroll: true }); $('lab-manual-copy').select();
    } finally { if (generation === labGeneration) $('copy-lab').disabled = false; }
  });
  $('search-open').addEventListener('click', openSearch); $('search-close').addEventListener('click', () => closeSearch());
  $('search-dialog').addEventListener('cancel', event => { event.preventDefault(); closeSearch(); });
  $('search-dialog').addEventListener('click', event => { const r = $('search-dialog').getBoundingClientRect(); if (event.target === $('search-dialog') && (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom)) closeSearch(); });
  $('feature-search').addEventListener('input', renderSearch);
  $('search-dialog').addEventListener('keydown', event => {
    const buttons = [...$('search-results').querySelectorAll('button')]; if (!buttons.length) return;
    const index = buttons.indexOf(document.activeElement);
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') { event.preventDefault(); const offset = event.key === 'ArrowDown' ? 1 : -1; const target = index < 0 ? (offset === 1 ? 0 : buttons.length - 1) : (index + offset + buttons.length) % buttons.length; buttons[target].focus(); }
    if (event.key === 'Enter' && document.activeElement === $('feature-search')) { event.preventDefault(); buttons[0].click(); }
  });
  document.addEventListener('keydown', event => {
    if ((event.metaKey || event.ctrlKey) && !event.altKey && event.key.toLowerCase() === 'k') { event.preventDefault(); if ($('search-dialog').open) closeSearch(); else openSearch(); }
  });
  renderLanguage();
  document.documentElement.classList.remove('no-js');
})();
