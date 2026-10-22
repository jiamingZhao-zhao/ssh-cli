'use strict';

// All examples are inert, local presentation data. This page has no SSH/API client.
(() => {
  const repo = 'https://github.com/jiamingZhao-zhao/ssh-cli';
  const text = {
    zh: {
      navRecords: "命令审计", navPerformance: "连接复用", credentialReference: "本机密文保存、配置使用引用，思路参考 ",
      navCredentials: '凭据安全', credentialEyebrow: '密码与凭据', credentialTitle: "凭据在本机登记，Agent 调用只写别名",
      credentialLead: "你输入一次密码，ssh-cli 加密保存。日常调用使用主机别名，不用反复把密码贴进对话或命令。",
      credentialBoundary: '加密保存不等于隔离 Agent。以你的系统账号运行、能访问密钥和凭据的程序，仍可能取得密码。',
      credentialMore: '保存方式与使用边界 ↓', credentialTabs: '密码使用流程', credentialRegister: '登记一次', credentialUse: '按别名调用', credentialStorage: '怎么保存',
      credentialConfig: '主机信息和密码引用，不保存密码原文。', credentialCipher: '加密后的密码，认证时由本机进程解密。', credentialKeyLabel: '解密用的主密钥', credentialKey: '优先使用系统凭据库；也支持环境变量和本地密钥文件。',
      credentialDocs: '查看这一步的用法 ↗', credentialManualCopy: '手动复制示例命令', credentialInert: '流程演示：本页不接收密码，不读取你的配置，也不连接服务器。',
      credentialDetails: '加密、密钥和日志，分别保护什么？', credentialAtRestTitle: '密码文件', credentialAtRest: '密码使用 ChaCha20-Poly1305 加密并校验完整性。配置只存引用；单独拿到配置或密码密文文件，不能直接读出密码。',
      credentialMasterTitle: '主密钥', credentialMaster: '依次尝试系统凭据库、SSH_CLI_MASTER_KEY、本地 master.key。系统凭据库不可用而回退到文件时会提示。主密钥与密文同时泄露，仍可被解密；主密钥丢失后，已有密码也可能无法恢复。',
      credentialRecordsTitle: '使用与记录', credentialRecords: '主机列表不返回已保存的密码原文。审计和历史会尝试脱敏，但不能识别所有秘密；不要把密码写进远端命令或聊天。需要时也可选择私钥或 SSH agent，私钥认证同样是 OpenSSH 已有能力。',
      labScriptTitle: '明确的脚本调用允许执行', labScriptBody: 'standard 不再仅因远端脚本正文不可见而要求确认。这里只检查调用参数，脚本内部操作不会逐条检查；显式 allow、deny、confirm 仍然生效。',
      resultLabel: "执行结果", proofPolicyHint: "权限与确认",

      confirmDemoTitle: "需要确认时，怎么继续？",
      confirmDemoNote: "页面演示，不连接服务器，也不向 Agent 发放许可。",
      confirmDemoLabel: "输入 demo-test，再检查输入",
      confirmDemoButton: "检查输入",
      confirmDemoIdle: "真实终端里，输入匹配后才会继续当前命令。输入错误会直接退出。",
      confirmDemoSuccess: "别名匹配。真实终端会继续执行你刚运行的这一条命令；本页不会执行。",
      confirmDemoError: "别名不匹配。真实命令会直接退出，不会发送重启命令。",
      confirmMore: "生产变更与确认边界",
      confirmProduction: "生产只读不是“输入确认就放行”。确需单次变更时，管理员须事先启用该环境的 break-glass。你在自己的终端运行下面的命令，核对主机、原因和操作后，输入 elevate:demo-prod。它只运行这一条命令，15m 是最长运行时间，不是给 Agent 开放 15 分钟权限；显式禁止规则仍然生效。",
      confirmTTY: "普通 exec 只在有交互终端时接受 --yes，且要放在 -- 之前。Windows CMD、PowerShell 和 Windows Terminal 均可使用。elevate 仍须手动输入确认。能控制交互终端的程序也可能完成输入；终端检查不是身份验证。",
      confirmLink: "查看单次提权用法 ↗",
      labConfirmation: "查看具体确认步骤 ↗",
      scenarioDocs: "查看命令参数 ↗",

      skip: '跳到内容', mainNav: '主导航', navWorkbench: "网页工作台", navAgent: "Agent 排查", navCommands: '命令参考', searchOpen: '搜索功能与命令', search: '搜索', start: '开始使用',
      release: "面向 Agent 的 SSH CLI", heroLine1: "让 Agent 按地区和环境", heroLine2: "找对主机，再排查",
      heroLead: "湖南、新疆、淄博；测试、生产。按分组和标签认准主机，对照双实例日志，检查操作规则，执行结果按主机留记录。",
      heroStart: "安装 CLI", heroTour: "看一次排查流程", heroFootnote: '本地运行 · 开源 · 无需 Python / Node.js / Go 运行环境',
      proofTitle: "Agent 的调用顺序", example: '示例 · 不连接服务器', proofRequest: "认准机器 → 检查规则 → 执行并读取结果",
      proofHost: "读取环境清单", explicitAlias: '明确别名', proofPolicy: "核对每台的有效策略", proofExecute: "读取日志，再按主机核验结果", proofOutcome: "知道哪台报错，哪台还不确定",
      proofOutcomeBody: '响应丢了，不代表没执行。先核验状态，再决定下一步。', proofLink: '选择主机和命令，查看策略判断',
      platforms: '支持的平台', platformLabel: '一个可执行文件', download: '下载发布包 ↗',
      workbenchTitle: "人工网页工作台", workbenchLead: "需要人工查看或接手时，打开本机工作台。终端、文件、监控与配置管理使用同一份主机登记；Agent 的主要入口仍是 CLI。",
      railTitle: '你的 SSH 工作台', featureModules: '功能模块', railFootnote: '同一份配置。网页、CLI 与 Agent 共用。', featureProof: '用现有命令完成 · 示例，不会自动执行', agentAngle: 'Agent 使用价值', featureDocs: '查看命令说明',

      boundariesTitle: "默认设置与使用边界", boundariesLead: "以下以 v0.7.37 为准。CLI 策略、网页交互终端和本机凭据各有边界，接入前一起看清楚。",
      boundaryProd: '生产环境', boundaryProdTitle: "生产主机默认只读", boundaryProdBody: "CLI 执行和文件变更仍检查只读权限。网页交互终端按远端账号权限运行，终端内不逐条检查命令策略。",
      boundaryDanger: '危险命令', boundaryDangerTitle: "危险命令清单默认未开启拦截", boundaryDangerBody: "先开启并选择规则，才会按这份清单拦截；启用后默认只在生产环境生效，可按需指定范围。",
      boundaryHuman: '人工确认', boundaryHumanTitle: "需要确认的操作，无交互终端时拒绝", boundaryHumanBody: "你在自己的终端重新运行命令，按提示输入主机别名。聊天里回复“同意”不会自动放行。普通 exec 在交互终端允许 --yes；终端检查不能证明操作者一定是真人。",
      boundaryAudit: '本地审计', boundaryAuditTitle: "记录保存在本机，重要结果需另外留存", boundaryAuditBody: "能同时修改记录和本地校验材料的人，仍可能破坏记录的可信度。重要场景需要独立保存记录，不能只依赖这一台电脑。",
      installTitle: '安装与接入', installLead: '把仓库链接交给能读取仓库、执行本地命令的 Agent。它会准备 CLI 和 Skill，验证完成后，展示路径、版本与最短用法。',
      installNote: 'CLI 是 Skill 的硬性依赖。主机与凭据仍由你在 Agent 实际运行的环境中配置；安装不会自动连接服务器。', skillGuide: '查看各 Agent 安装说明',
      installMethods: '安装方式', installAgent: '交给 Agent', copy: '复制链接', installDetails: '安装细节 ↗', releaseNotes: '版本记录', source: "GitHub 仓库 ↗",
      footerLine: "面向 Agent 的 SSH CLI，附本机网页工作台。", searchTitle: '搜索功能与命令', searchPlaceholder: "如：密码、exec、--agent-key",
      searchHint: '↑ ↓ 选择 · Enter 打开 · Esc 关闭', close: '关闭', manualCopy: '手动复制', emptySearch: '没有匹配项。试试命令名、参数或功能名称。', searchCommands: '命令', searchAll: '打开完整命令参考', searchLoading: '正在读取命令索引…', searchFailed: '命令索引未加载，可直接打开命令参考。',
      copied: '已复制', copying: '复制中…', copyCommand: '复制命令', copyError: '无法访问剪贴板，请在下方选中内容手动复制。', copySuccess: '已复制，可以交给 Agent 或粘贴到终端。',
      navLab: '策略示例', featureSelect: '选择功能', featureSteps: '具体操作步骤', labTitle: "生产环境要拦哪些操作，先定下来",
      labLead: "CLI 默认按生产只读上限检查。危险命令清单需显式启用和选择规则；下面可查看实际检查结果。",
      labHost: '目标主机', labCommand: '待检查命令', labScope: '危险命令目录中的 mkfs 规则', labScopeOff: '未启用（默认）', labScopeProd: '启用规则 · 默认仅 prod', labScopeBoth: '启用规则 · prod 和 test',
      labConfigNote: "test 使用内置 standard，prod 使用 readonly。重启需要确认；明确的脚本调用可直接允许。所有结果只做策略解释，不执行命令。",
      labMode: '有效模式', labEnforced: '危险规则在此目标生效', labActive: '选中的生效规则', labCheckLabel: '在自己的配置中检查同一条命令：', labCopy: '复制检查命令', labManualCopy: '手动复制检查命令',
      labOutput: "检查结果（JSON）", labOutputNote: "这里展示的是检查结果，命令并没有被执行。页面也不会读取你的主机配置或连接服务器。",
      labConfig: "示例里的规则是什么", labConfigBody: "dev 的权限上限是 admin，默认策略仍为 standard；test 的上限和默认策略都是 standard，彼此不影响。示例中的脚本调用在 standard 下允许，systemctl restart 仍需确认，prod 仍按 readonly 拒绝写操作。mkfs 的危险目录规则是否启用、在哪些环境生效，由上方选项决定。", labSource: "查看策略检查用法 ↗",
      labAllowTitle: "这条命令允许执行", labAllowBody: "当前规则允许这条命令继续执行，也不需要额外确认。实际连接和执行仍可能失败。",
      labConfirmTitle: "需要你确认后才能执行", labConfirmBody: "检查不执行重启。无交互终端的调用会被拒绝；你可在自己的终端重新运行 exec，按提示输入主机别名 demo-test。聊天里回复“同意”不会恢复 Agent 的调用。",
      labDenyTitle: "当前规则不允许执行", labDenyBody: "示例规则拒绝这条命令。请先查看命中原因，再调整任务或交给有权限的人处理，不要换一种写法绕过。",
      groups: ['日常高频', '目标与操作边界', '记录与维护'], title: "ssh-cli · 面向 Agent 的 SSH 命令行工具"
    },
    en: {
      navRecords: "Audit", navPerformance: "Reuse SSH", credentialReference: "Local ciphertext and references in config; approach informed by ",
      navCredentials: 'Credentials', credentialEyebrow: 'PASSWORDS / CREDENTIALS', credentialTitle: "Register credentials locally. Call hosts by alias.",
      credentialLead: "Enter the password once; ssh-cli stores it encrypted. Routine calls use a host alias instead of repeating the password in chats or commands.",
      credentialBoundary: 'Encryption at rest does not isolate an agent. Software running as your OS account with access to the keys and credentials may still obtain the password.',
      credentialMore: 'Storage and access limits ↓', credentialTabs: 'Password workflow', credentialRegister: 'Register', credentialUse: 'Use alias', credentialStorage: 'Storage',
      credentialConfig: 'Host details and a password reference, without the plaintext password.', credentialCipher: 'Encrypted passwords, decrypted locally for authentication.', credentialKeyLabel: 'Master key', credentialKey: 'The OS credential store takes priority, followed by an environment key or local key file.',
      credentialDocs: 'Read this command’s usage ↗', credentialManualCopy: 'Copy the example command manually', credentialInert: 'Workflow example only. This page does not accept passwords, read your configuration or connect to servers.',
      credentialDetails: 'What do encryption, keys and redaction protect?', credentialAtRestTitle: 'Password file', credentialAtRest: 'Passwords use ChaCha20-Poly1305 encryption with integrity checking. The configuration stores a reference. A configuration or ciphertext file alone does not reveal the password.',
      credentialMasterTitle: 'Master key', credentialMaster: 'Keys are checked in this order: OS credential store, SSH_CLI_MASTER_KEY, then master.key. Falling back to a local key file produces a warning. Possession of both ciphertext and its key allows decryption. Losing the key may make saved passwords unrecoverable.',
      credentialRecordsTitle: 'Use and records', credentialRecords: 'Host listings do not return saved plaintext passwords. Audit and history redaction is heuristic and cannot catch every secret; keep passwords out of remote commands and chat. Private keys and SSH agent authentication are also supported, as they are in OpenSSH.',
      labScriptTitle: 'This literal script invocation is allowed', labScriptBody: 'standard no longer requests confirmation just because the remote file body is unavailable. Invocation arguments are checked; commands inside the file are not. Explicit allow, deny and confirm rules still apply.',
      resultLabel: "Result", proofPolicyHint: "Rules / confirmation",

      confirmDemoTitle: "How do I complete a required confirmation?",
      confirmDemoNote: "Page demonstration only. No server connection or permission is sent to an agent.",
      confirmDemoLabel: "Enter demo-test, then check the input",
      confirmDemoButton: "Check input",
      confirmDemoIdle: "In a real terminal, a match continues the current command. A mismatch exits.",
      confirmDemoSuccess: "Alias matched. A real terminal would continue the command you just ran. This page runs nothing.",
      confirmDemoError: "Alias did not match. The real command would exit without sending the restart request.",
      confirmMore: "Production and confirmation limits",
      confirmProduction: "Readonly production cannot be bypassed by typing a confirmation. An administrator must first enable break-glass for the environment. Run the command below in your own terminal, review the host, reason and command, then type elevate:demo-prod. It runs one command. 15m limits its runtime; it is not a 15-minute grant to the agent. Explicit denies still apply.",
      confirmTTY: "Ordinary exec accepts --yes only with an interactive terminal, before --. Windows CMD, PowerShell and Windows Terminal are supported. elevate still requires typed input. Software controlling a terminal may also confirm: a terminal check is not identity verification.",
      confirmLink: "Read single-command elevation usage ↗",
      labConfirmation: "See the confirmation steps ↗",
      scenarioDocs: "Read command flags ↗",

      skip: 'Skip to content', mainNav: 'Main navigation', navWorkbench: "Web workspace", navAgent: "Agent workflow", navCommands: 'Commands', searchOpen: 'Search features and commands', search: 'Search', start: 'Get started',
      release: "SSH CLI for agents", heroLine1: "Let your agent find the right hosts", heroLine2: "before investigating",
      heroLead: "Across Hunan, Xinjiang and Zibo; test and production. Organize hosts by group and tag, compare two instances, check policy, and review results per host.",
      heroStart: "Install CLI", heroTour: "Walk through an investigation", heroFootnote: 'Local · Open source · No Python, Node.js or Go runtime required',
      proofTitle: "An agent’s command sequence", example: 'Example · no server connection', proofRequest: "Identify the host → check its rules → execute and read the result",
      proofHost: "Read the environment inventory", explicitAlias: 'Explicit alias', proofPolicy: "Check each host’s effective policy", proofExecute: "Read logs; verify results per host", proofOutcome: "Know which host failed or remains uncertain",
      proofOutcomeBody: 'A lost response does not mean nothing ran. Verify state before taking the next step.', proofLink: 'Inspect a command',
      platforms: 'Supported platforms', platformLabel: 'One executable', download: 'Download a release ↗',
      workbenchTitle: "A web workspace for people", workbenchLead: "Open the local workspace when you need to inspect or take over. Terminals, files, monitoring and configuration share the same host inventory. Agents primarily use the CLI.",
      railTitle: 'Your SSH workspace', featureModules: 'Feature modules', railFootnote: 'One configuration for the UI, CLI and agent.', featureProof: 'Existing commands · examples only, never executed here', agentAngle: 'What an agent gains', featureDocs: 'Open command reference',

      boundariesTitle: "Defaults and access boundaries", boundariesLead: "Behavior as of v0.7.37. CLI policies, interactive web terminals and local credentials have different access boundaries.",
      boundaryProd: 'Production', boundaryProdTitle: "Production defaults to readonly", boundaryProdBody: "CLI execution and file changes still check readonly permissions. Interactive web terminals run with the remote account’s privileges, without checking each command against policy.",
      boundaryDanger: 'Dangerous commands', boundaryDangerTitle: "Extra catalog blocking starts disabled", boundaryDangerBody: "Enable the catalog and select rules before it blocks commands. Its default scope is production; choose other environments explicitly.",
      boundaryHuman: 'Human confirmation', boundaryHumanTitle: "Confirmation-required calls need an interactive terminal", boundaryHumanBody: "Rerun the command in your own terminal and enter the requested host alias. Saying yes in chat does not authorize it. Ordinary exec accepts --yes in an interactive terminal; this check does not prove a human is present.",
      boundaryAudit: 'Local audit', boundaryAuditTitle: "Records stay local; keep important results elsewhere too", boundaryAuditBody: "Someone able to change both records and local verification material can undermine trust in them. Important records need an independent copy, beyond this computer.",
      installTitle: 'Installation', installLead: 'Give the repository link to an agent that can read repositories and run local commands. It prepares the CLI and skill, verifies setup, then reports paths, versions and a short usage guide.',
      installNote: 'The CLI is mandatory for the skill. Configure hosts and credentials in the agent’s execution environment. Installation does not connect to servers.', skillGuide: 'Read the agent setup guide',
      installMethods: 'Installation methods', installAgent: 'With an agent', copy: 'Copy link', installDetails: 'Install details ↗', releaseNotes: 'Release notes', source: "GitHub ↗",
      footerLine: "SSH CLI for agents, with a local web workspace.", searchTitle: 'Search features and commands', searchPlaceholder: "Try password, exec or --agent-key",
      searchHint: '↑ ↓ select · Enter open · Esc close', close: 'Close', manualCopy: 'Copy manually', emptySearch: 'No matches. Try a command name, flag or feature.', searchCommands: 'Command', searchAll: 'Open full command reference', searchLoading: 'Loading command index…', searchFailed: 'Command index unavailable. Open the command reference directly.',
      copied: 'Copied', copying: 'Copying…', copyCommand: 'Copy command', copyError: 'Clipboard unavailable. Select the text below and copy it manually.', copySuccess: 'Copied. Send it to your agent or paste it into your terminal.',
      navLab: 'Policy examples', featureSelect: 'Choose a feature', featureSteps: 'How to use it', labTitle: "Define which production operations are refused",
      labLead: "CLI calls respect production’s default readonly ceiling. Dangerous catalog rules must be explicitly enabled and selected. Inspect actual decisions below.",
      labHost: 'Target host', labCommand: 'Command to inspect', labScope: 'mkfs rule from the dangerous catalog', labScopeOff: 'Disabled (default)', labScopeProd: 'Enabled · prod only (default scope)', labScopeBoth: 'Enabled · prod and test',
      labConfigNote: "test uses builtin standard; prod uses readonly. Restarts require confirmation; literal script-file calls can be allowed directly. These are policy explanations, not execution.",
      labMode: 'Effective mode', labEnforced: 'Dangerous rules enforced here', labActive: 'Selected active rules', labCheckLabel: 'Inspect the command against your own configuration:', labCopy: 'Copy inspection command', labManualCopy: 'Copy inspection command manually',
      labOutput: "Check result (JSON)", labOutputNote: "This is an inspection result; no command has been executed. The page does not read your host configuration or connect to a server.",
      labConfig: "Which rules does this example use?", labConfigBody: "dev has an admin ceiling but still defaults to standard; test has a standard ceiling and default. They do not affect each other. The example script call is allowed in standard, systemctl restart still requires confirmation, and prod retains readonly write restrictions. The controls above select whether and where the mkfs catalog rule is active.", labSource: "Read policy-check usage ↗",
      labAllowTitle: "This command is allowed", labAllowBody: "The current rules allow the command without extra confirmation. Connecting and executing can still fail.",
      labConfirmTitle: "Your confirmation is needed first", labConfirmBody: "Inspection does not restart anything. Calls without an interactive terminal are refused. Rerun exec in your own terminal and type demo-test at the prompt. Saying yes in chat does not resume the agent’s call.",
      labDenyTitle: "The current rules refuse this command", labDenyBody: "Read the matching reason, then change the task or hand it to an authorized person. Do not reword the command to bypass the rule.",
      groups: ['Everyday work', 'Targets & boundaries', 'Records & maintenance'], title: "ssh-cli · SSH commands for agents"
    }
  };

  // The module IDs and names map to internal/ui/web/index.html. Grouping here
  // prioritizes the product tour and does not reorder the application's sidebar.
  const features = [
    { id: 'terminal', group: 0, icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
      command: 'ssh-cli ui\nssh-cli exec -H demo --json -- df -h\nssh-cli upload -H demo ./app.jar /tmp/app.jar --json',
      zh: { nav: '终端', title: '终端、文件和主机监控', description: '先按环境、分组筛选主机，再打开终端或文件连接。多标签终端、目录树、传输队列与监控围绕当前主机显示。', benefits: [['少切几个窗口', '终端回看搜索、字号调整、中文输入与粘贴，配合当前主机的文件和监控。'], ['传输过程看得懂', '区分传输、提交和待核验；文件区默认约占三分之一，拖动不牵动左侧概况。']], agent: '人在终端里处理问题，Agent 用 exec、ls、upload 等结构化接口做事；共享主机配置，不依赖模拟键盘敲命令。', boundary: '网页交互终端在 readonly、standard、admin 下均按远端账号权限运行；终端内不逐条检查命令策略。noDataOutflow 仍禁止终端。' },
      en: { nav: 'Terminal', title: 'Terminal, files and host monitoring', description: 'Filter hosts by environment and group before opening a terminal or file connection. Terminal tabs, files, transfers and metrics stay with the current host.', benefits: [['Fewer window switches', 'Search scrollback, adjust type, paste and enter CJK text alongside files and monitoring.'], ['Understand each transfer stage', 'Separate transfer, commit and verification. Resizing the lower file panel does not move the left overview.']], agent: 'People use the terminal; agents use structured exec, ls and upload calls. They share host configuration without simulating keystrokes.', boundary: 'Interactive web terminals use remote account privileges in readonly, standard and admin, without per-command policy checks. noDataOutflow still refuses terminals.' } },
    { id: 'hosts', group: 0, icon: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/>', command: 'ssh-cli host list --json\nssh-cli policy show -H demo --json',
      zh: { nav: '主机', title: '主机地址与认证配置', description: '管理地址、端口、认证与跳板，按环境和分组标签筛选。密码加密保存在本机，日常调用使用明确的主机别名。', benefits: [['凭据留在本地配置', '密码引用、私钥路径或 SSH agent 身份，不必让 Agent 在提示词里反复接触口令。'], ['选择明确的身份', '可指定 agentKey 公钥指纹；需要的密钥不存在时直接失败。']], agent: '先列清单再显式传 -H。已有目标与认证可复用，避免凭聊天记忆猜 IP、用户或私钥。', boundary: 'Skill 不会把本地密钥和配置自动同步到云端 Agent。' },
      en: { nav: 'Hosts', title: 'Host addresses and authentication', description: 'Manage addresses, ports, authentication and jump hosts, with environment and group filters. Passwords are encrypted locally; routine calls use explicit host aliases.', benefits: [['Credentials stay in configuration', 'Use password references, identity paths or SSH agent authentication instead of credentials in prompts.'], ['Choose the required identity', 'An agentKey fingerprint selects a public key. If the key is absent, authentication fails.']], agent: 'List registered hosts, then pass -H explicitly. Reuse configured targets and authentication instead of guessing an IP or key from chat history.', boundary: 'A skill does not automatically transfer local keys or configuration to cloud agents.' } },
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
      zh: { nav: '危险命令', title: '危险命令与执行前检查', description: '把建议目录与实际生效的拦截规则分开。查看当前主机合并后的规则、确认门和受保护路径，再解释一条具体命令。', benefits: [['看得见真正生效的规则', 'v0.7.37 的危险命令目录默认未启用；启用并选定规则后才拦截，默认范围为 prod。'], ['变更前无需试错', 'policy show 和 policy explain 只读本地配置，不连接服务器、不执行远端命令。']], agent: '先读取 confirm、protectedPaths、envRules 和 dangerousCommands.active / enforcedHere，避免用一次失败的写请求来发现限制。', boundary: '只加启用开关还不够，还要选择规则。只读上限等其他限制独立生效；目录匹配本身不等于拒绝。' },
      en: { nav: 'Commands', title: 'Dangerous commands and policy checks', description: 'Separate the suggested catalog from active blocking rules. Inspect the host’s merged policy, confirmation gates and protected paths, then explain a specific command.', benefits: [['See what is actually enforced', 'In v0.7.37 the catalog is off by default. Enable it and select rules to enforce them; prod is the default scope.'], ['No trial write needed', 'policy show and policy explain read local configuration. They neither connect nor run a remote command.']], agent: 'Read confirm, protectedPaths, envRules and dangerousCommands.active / enforcedHere before attempting a change.', boundary: 'The enable switch alone is insufficient; select rules too. Readonly ceilings remain independent. Matching the catalog alone does not mean denial.' } },
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
    policy: { zh: ['在危险命令页区分建议目录、启用状态、已选规则和作用环境。', '执行变更前，先运行 policy show，再用 policy explain 检查准确的命令参数。', '需要确认则交给人工 TTY；被拒绝时停止。可在上方策略示例中比较结果。'], en: ['Distinguish catalog suggestions, the enable switch, selected rules and scope.', 'Before a change, use policy show and policy explain with the exact intended arguments.', 'Leave confirmation to a human TTY and stop on denial. Compare examples in the policy inspector above.'] },
    groups: { zh: ['在分组页按业务建立分组，选择环境并引用需要的命名策略。', '把主机归入对应分组，为共同保护的目录设置受保护路径。', '对具体主机运行 policy show，核对环境、分组与主机层合并后的结果。'], en: ['Create a business group, choose its environment and reference a named policy.', 'Assign hosts to the group and configure shared protected directories.', 'Run policy show for a host to inspect the merged environment, group and host result.'] },
    tags: { zh: ['在主机配置中设置角色标签，如 app、db、nginx。', '从标签页查看匹配的主机，先核对清单，不直接把检索结果当作变更授权。', '为具体任务确认目标别名；批量操作还要核对环境范围与各主机权限。'], en: ['Set role tags such as app, db or nginx on host configuration.', 'Review matching hosts on Tags; discovery results are not authorization for changes.', 'Confirm target aliases for a task, checking environment scope and policies for a batch.'] },
    audit: { zh: ['在审计页按时间、主机和结果筛选记录，需要进一步分析时导出 CSV。', '发现失败或 unknown，结合目标主机当前状态核验，不自动重放原操作。', '需要完整性检查时先按文档建立保护基线，再用 audit verify 验证。'], en: ['Filter records by time, host and outcome; export CSV for further analysis.', 'For failures or unknown outcomes, verify current remote state without replaying the operation.', 'For integrity checks, establish the documented protection baseline before audit verify.'] },
    bundle: { zh: ['在旧电脑的运维页生成导出，检查主机、策略和密钥引用。', '把配置包交给新电脑，在其运维页导入；密钥文件与凭据另行准备。', '导入涉及目标或权限变化时按要求确认；高级会话入口也在运维页。'], en: ['Export from the old machine and review hosts, policies and key references.', 'Import the bundle on the new machine; prepare key files and credentials separately.', 'Confirm target or permission changes when required. Advanced session entry points are also under Ops.'] },
    settings: { zh: ['在设置页调整主题、紧凑表格、分页和表单默认值。', '按实际需求设置会话空闲与最长寿命，保存后检查配置。', 'Agent 的命令超时等参数仍应显式传入，不假设继承浏览器里的偏好。'], en: ['Adjust theme, compact tables, pagination and form defaults in Settings.', 'Set appropriate idle and maximum session lifetimes, save and review the configuration.', 'Agents should still pass execution parameters such as timeouts explicitly rather than assume browser preferences apply.'] }
  };

  // Installation does not configure host credentials or connect to servers.
  const install = {
    agent: { command: repo, zh: ['把这个链接发给你的 Agent，并让它安装。', '先检查 CLI → 缺失时安装并校验 → 安装 Skill → 汇报结果'], en: ['Send this link to your agent and ask it to install.', 'Check CLI → install and verify if missing → install skill → report'] },
    unix: { command: 'curl -fsSL https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.sh | sh', zh: ['安装当前系统与架构的 CLI 发布包。', '下载发布包并验证校验和。随后运行 ssh-cli version；主机与 Skill 可按文档继续配置。'], en: ['Install the CLI release for your operating system and architecture.', 'Downloads and verifies release checksums. Run ssh-cli version afterward, then configure hosts and skills using the guide.'] },
    windows: { command: 'irm https://raw.githubusercontent.com/jiamingZhao-zhao/ssh-cli/main/install.ps1 | iex', zh: ['在 Windows PowerShell 中安装 CLI。', '默认安装到 %LOCALAPPDATA%\\ssh-cli\\bin，验证校验和；新终端中运行 ssh-cli version。'], en: ['Install the CLI in Windows PowerShell.', 'Installs to %LOCALAPPDATA%\\ssh-cli\\bin with checksum verification. Run ssh-cli version in a new terminal.'] }
  };
  const credentials = {
    register: { command: 'ssh-cli host add demo-test --group app-test --host 192.0.2.10 --user deploy', docs: 'host-add',
      zh: ['由你在本机输入密码', '先建立 app-test 分组，再在自己的终端登记主机。出现 Password: 时输入，字符不会显示；也可以在本机网页工作台添加。', 'ssh-cli 拒绝明文 --password 参数。自动化登记可用 --password-stdin，但输入来源仍由你安全提供。'],
      en: ['Enter the password locally', 'Create the app-test group first, then register the host in your own terminal. At Password:, input is hidden. You can also register it in the local workbench.', 'Plaintext --password arguments are rejected. --password-stdin is available for setup automation; provide its input securely.'] },
    use: { command: 'ssh-cli exec -H demo-test --json -- df -h /', docs: 'exec',
      zh: ['Agent 调用时，用别名就够了', '调用中只有主机别名和要执行的命令。ssh-cli 在本机取出对应凭据进行 SSH 认证，不需要在每次任务里重新提供密码。', '这减少了对话和命令中的密码暴露，不代表拥有本机凭据访问权限的 Agent 无法取到密码。'],
      en: ['Routine calls use an alias', 'The call contains a host alias and a command. ssh-cli retrieves the registered credentials locally for SSH authentication, without asking you to repeat the password for each task.', 'This reduces passwords in chats and command arguments. It does not prevent an agent with local credential access from retrieving them.'] },
    storage: { command: 'ssh-cli host list --json', docs: 'host-list',
      zh: ['配置存引用，密码加密保存', '主机清单可以交给 Agent 核对别名和环境，其中不会返回已保存的密码原文。密码与解密主密钥分别管理。', '列表仍可能包含地址和用户名。下面列出存储用途，不会读取你本机的实际文件。'],
      en: ['References in config. Encrypted passwords on disk.', 'An agent can inspect host aliases and environments without saved plaintext passwords in the listing. Password ciphertext and the decryption key are managed separately.', 'Listings can still include addresses and usernames. These are storage roles, not files read from your computer.'] }
  };
  const $ = id => document.getElementById(id);
  let language = 'zh';
  let currentFeature = 'terminal';
  let confirmationState = 'default';
  let currentInstall = 'agent';
  let currentCredential = 'use';
  let credentialGeneration = 0;
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
  function renderConfirmation() {
    const key = confirmationState === 'success' ? 'confirmDemoSuccess' : confirmationState === 'error' ? 'confirmDemoError' : 'confirmDemoIdle';
    if ($('confirmation-feedback').textContent !== text[language][key]) setText('confirmation-feedback', text[language][key]);
    $('confirmation-feedback').dataset.state = confirmationState;
    $('confirmation-check').disabled = !$('confirmation-alias').value.trim();
    if (confirmationState === 'error') $('confirmation-alias').setAttribute('aria-invalid', 'true');
    else $('confirmation-alias').removeAttribute('aria-invalid');
  }
  function selectCredential(id) {
    const item = credentials[id]; if (!item) return;
    currentCredential = id; credentialGeneration++;
    document.querySelectorAll('[data-credential]').forEach(button => { const selected = button.dataset.credential === id; button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; });
    $('credential-panel').setAttribute('aria-labelledby', 'credential-' + id);
    setText('credential-position', String(Object.keys(credentials).indexOf(id) + 1).padStart(2, '0') + ' / 03');
    ['credential-step-title', 'credential-step-description', 'credential-note'].forEach((target, i) => setText(target, item[language][i]));
    setText('credential-command', item.command); $('credential-files').hidden = id !== 'storage';
    $('credential-docs').href = commandLink(item.docs);
    setText('copy-credential', text[language].copyCommand); setText('credential-copy-status', '');
    $('copy-credential').disabled = false; $('copy-credential').dataset.state = 'default'; $('credential-manual-copy').hidden = true;
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
    $('lab-reference').href = commandLink('policy-explain');
    document.querySelectorAll('[data-command-reference]').forEach(link => { link.href = commandLink(); });
    renderFeatureTabs(); selectFeature(currentFeature); selectCredential(currentCredential); selectInstall(currentInstall); renderSearch(); renderLab(); renderConfirmation();
    document.dispatchEvent(new CustomEvent("ssh-cli-language", { detail: language }));
  }
  function renderLab() {
    labGeneration++;
    const key = [$('lab-host').value, $('lab-scope').value, $('lab-command').value].join('/');
    const record = window.SSH_CLI_POLICY_EXAMPLES?.records[key];
    if (!record) {
      setText('lab-result-title', language === 'zh' ? '示例数据未加载' : 'Example data unavailable');
      setText('lab-result-description', language === 'zh' ? '请重新加载页面，或打开命令参考查看用法。' : 'Reload the page or read the linked usage guide.');
      setText('lab-decision', '—'); $('lab-decision').removeAttribute('data-state');
      for (const id of ['lab-exit', 'lab-mode', 'lab-enforced', 'lab-active', 'lab-json', 'lab-check-command']) setText(id, '—');
      $('lab-confirmation-entry').hidden = true;
      $('copy-lab').disabled = true; return;
    }
    const result = record.explanation;
    const state = !result.allowed ? 'deny' : result.needsConfirm ? 'confirm' : 'allow';
    $('lab-confirmation-entry').hidden = state !== 'confirm';
    const keyPrefix = 'lab' + state[0].toUpperCase() + state.slice(1);
    setText('lab-decision', state === 'deny' ? '⊘ DENY' : state === 'confirm' ? '◇ CONFIRM' : '✓ ALLOW');
    $('lab-decision').dataset.state = state;
    setText('lab-exit', 'policy explain · exit ' + record.exitCode);
    setText('lab-result-title', text[language][keyPrefix + 'Title']);
    setText('lab-result-description', text[language][keyPrefix + 'Body']);
    if (state === 'allow' && result.command === window.SSH_CLI_POLICY_EXAMPLES.commands.script) {
      setText('lab-result-title', text[language].labScriptTitle); setText('lab-result-description', text[language].labScriptBody);
    }
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
    const root = $('search-results'), featureResults = document.createDocumentFragment(); root.replaceChildren();
    matches.forEach(feature => {
      const button = document.createElement('button'); button.className = 'search-result'; button.type = 'button';
      button.dataset.searchId = 'feature-' + feature.id;
      const label = document.createElement('span'); label.textContent = feature[language].nav;
      const group = document.createElement('span'); group.textContent = text[language].groups[feature.group];
      button.append(makeIcon(feature.icon), label, group);
      button.addEventListener('click', () => { closeSearch(false); $('workbench-optional').open = true; selectFeature(feature.id); $('workbench').scrollIntoView(); (matchMedia('(max-width: 39.99rem)').matches ? $('feature-mobile') : $('tab-' + feature.id)).focus({ preventScroll: true }); });
      featureResults.append(button);
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
    root.append(featureResults);
    if (!query || ['密码', '凭据', '密文', '加密', 'password', 'credential', 'secret'].some(term => query.includes(term))) {
      const button = document.createElement('button'); button.type = 'button'; button.className = 'search-result'; button.dataset.searchId = 'credential-safety';
      button.textContent = text[language].credentialTitle; button.addEventListener('click', () => { closeSearch(false); document.dispatchEvent(new CustomEvent('ssh-cli-flow', { detail: 'credentials' })); $('credential-' + currentCredential).focus({ preventScroll: true }); }); root.append(button);
    }
    const pending = commandIndexState === 'idle' || commandIndexState === 'loading';
    if (!root.querySelector('.search-result') && !pending && commandIndexState !== 'error') { const empty = document.createElement('p'); empty.className = 'search-empty'; empty.setAttribute('role', 'status'); empty.textContent = text[language].emptySearch; root.append(empty); }
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
  $('confirmation-alias').addEventListener('input', () => { confirmationState = 'default'; renderConfirmation(); });
  $('confirmation-form').addEventListener('submit', event => {
    event.preventDefault();
    // Inert explanation of confirmTyped's trimmed, exact alias match. No authorization is issued.
    confirmationState = $('confirmation-alias').value.trim() === 'demo-test' ? 'success' : 'error';
    renderConfirmation();
  });
  $('lab-confirmation-link').addEventListener('click', event => { event.preventDefault(); $('confirm-guide').open = true; $('confirmation-alias').focus({ preventScroll: true }); $('confirm-guide').scrollIntoView({ block: 'nearest' }); });
  document.querySelector('.install-tabs').addEventListener('keydown', event => tabKeys(event, '[role="tab"]', 'data-install', selectInstall));
  document.querySelector('.credential-tabs').addEventListener('keydown', event => tabKeys(event, '[role="tab"]', 'data-credential', selectCredential));
  document.querySelectorAll('[data-credential]').forEach(button => button.addEventListener('click', () => selectCredential(button.dataset.credential)));
  document.addEventListener('ssh-cli-flow-change', () => { selectCredential(currentCredential); renderLab(); });
  document.querySelector('[data-open-credential-details]').addEventListener('click', () => { $('credential-details').open = true; });
  $('copy-credential').addEventListener('click', async () => {
    const generation = ++credentialGeneration, command = credentials[currentCredential].command;
    $('copy-credential').disabled = true; $('copy-credential').dataset.state = 'loading'; setText('copy-credential', text[language].copying);
    try {
      await navigator.clipboard.writeText(command);
      if (generation !== credentialGeneration) return;
      setText('copy-credential', text[language].copied); setText('credential-copy-status', text[language].copySuccess); $('copy-credential').dataset.state = 'success';
    } catch {
      if (generation !== credentialGeneration) return;
      setText('copy-credential', text[language].copyCommand); setText('credential-copy-status', text[language].copyError); $('copy-credential').dataset.state = 'error';
      $('credential-manual-copy').hidden = false; $('credential-manual-copy').value = command; $('credential-manual-copy').focus({ preventScroll: true }); $('credential-manual-copy').select();
    } finally { if (generation === credentialGeneration) $('copy-credential').disabled = false; }
  });
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
