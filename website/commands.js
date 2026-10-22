'use strict';
(() => {
  const data = window.SSH_CLI_COMMAND_REFERENCE;
  const $ = id => document.getElementById(id);
  if (!data?.commands?.length) return;
  const entries = data.commands;
  const byId = new Map(entries.map(command => [command.id, command]));
  const pageSize = 8;
  const common = ['exec', 'upload', 'download', 'ls', 'status', 'host-list', 'policy-show', 'policy-explain', 'service', 'relay', 'ui', 'audit-list'];
  const categories = {
    all: ['全部功能', 'All features'], execution: ['执行与终端', 'Execution'], files: ['文件与传输', 'Files'], inventory: ['主机与组织', 'Inventory'],
    policy: ['策略与确认', 'Policies'], records: ['审计与历史', 'Records'], configuration: ['配置与身份', 'Configuration'], tools: ['工具与更新', 'Tools']
  };
  const effects = {
    all: ['全部影响', 'All effects'], group: ['命令分组', 'Command group'], 'local-read': ['本地读取', 'Local read'], 'remote-read': ['远端读取', 'Remote read'],
    'local-write': ['修改本地配置', 'Local change'], 'remote-write': ['远端写入', 'Remote write'], mixed: ['取决于操作内容', 'Depends on action'], transfer: ['下载到本机', 'Download'],
    human: ['仅人工确认', 'Human TTY'], 'process-only': ['独立调用不可用', 'Not standalone'], 'local-server': ['启动本机服务', 'Local server'],
    'local-output': ['输出脚本或配置', 'Local output'], 'local-update': ['查询或安装更新', 'Check / install']
  };
  const copy = {
    zh: { skip:'跳到命令详情',nav:'主导航',home:'产品介绍',reference:'命令参考',install:'安装',title:'命令参考',intro:'按命令名、用途或参数查找。先看示例和操作影响，再按需展开参数与原始帮助。',entries:'个入口，含命令组与 Shell 补全',source:'此版本更新记录 ↗',browse:'查找命令',searchLabel:'搜索命令或参数',searchPlaceholder:'如：上传、exec、--agent-key',clear:'清空搜索',category:'功能分类',effect:'操作影响',common:'常用',choose:'选择命令',previous:'上一页',next:'下一页',searchHint:'/ 或 Ctrl / ⌘ K 搜索；↑ ↓ 选择，Enter 打开。',allCommands:'全部命令',syntax:'语法',example:'调用示例',copy:'复制示例',exampleNote:'只复制，不自动执行。demo、文件路径和配置名称需替换为你实际登记的值。',subcommands:'子命令',parameters:'本命令参数',parameterNote:'类型与原始说明来自该版本 --help；默认值和可重复选项保留在原文中。中文补充不替代原始说明。',globalParameters:'可用的通用参数',globalNote:'只列出此命令实际继承的参数；本地同名参数优先。--json、--daemon 等仍受具体命令支持范围限制。',rawHelp:'CLI 原始帮助（英文）',installedHelp:'查看你当前安装版本的帮助：',copyLink:'复制此命令链接',manualCopy:'手动复制示例',manualLink:'手动复制命令链接',footer:'命令与参数来自实际 CLI；中文用途与注意事项另行整理。',usage:'使用参考 ↗',empty:'没有匹配的命令。试试命令名、参数，或清除分类筛选。',none:'无',copied:'已复制',copying:'复制中…',copyError:'无法访问剪贴板，请在下方选中原文手动复制。',copySuccess:'已复制；页面不会执行该命令。',linkSuccess:'已复制，链接包含当前命令和筛选条件。',result:'个匹配',unavailable:'此入口不提供独立 CLI 会话操作，请使用 session run 或网页 UI。',remoteNote:'远端操作需先登记目标与凭据，并通过当前主机策略检查。需要确认时交给人工；响应丢失后先核验。',writeNote:'此命令可能改动配置、文件或服务。复制示例并不表示已执行或已获准变更。',humanNote:'要求真实交互式 TTY；非交互 Agent 不应代为确认，--yes 不能绕过。',outputNote:'默认输出到终端；文件重定向、--output 或加载补全脚本是另外的本地操作。' },
    en: { skip:'Skip to command details',nav:'Main navigation',home:'Overview',reference:'Commands',install:'Install',title:'Command reference',intro:'Find a command by name, purpose or flag. Read examples and effects first, then expand parameters and raw help as needed.',entries:'entries, including groups and shell completion',source:'Release notes ↗',browse:'Browse commands',searchLabel:'Search commands and flags',searchPlaceholder:'Try upload, exec or --agent-key',clear:'Clear search',category:'Category',effect:'Effect',common:'Common',choose:'Choose a command',previous:'Previous',next:'Next',searchHint:'/ or Ctrl / ⌘ K to search; ↑ ↓ select, Enter open.',allCommands:'All commands',syntax:'Syntax',example:'Example',copy:'Copy example',exampleNote:'Copy only; nothing runs here. Replace demo aliases, paths and configuration names with your actual values.',subcommands:'Subcommands',parameters:'Command flags',parameterNote:'Types and original descriptions come from this version’s --help, including defaults and repeatable flags.',globalParameters:'Available global flags',globalNote:'Only flags actually inherited by this command are listed; local flags take precedence. --json and --daemon remain subject to command-specific support.',rawHelp:'Raw CLI help',installedHelp:'Read help for your installed version:',copyLink:'Copy command link',manualCopy:'Copy example manually',manualLink:'Copy command link manually',footer:'Commands and flags come from the CLI; usage notes are curated.',usage:'Usage reference ↗',empty:'No matching commands. Try a name or flag, or clear the category filter.',none:'None',copied:'Copied',copying:'Copying…',copyError:'Clipboard unavailable. Select the text below and copy it manually.',copySuccess:'Copied; the page does not execute commands.',linkSuccess:'Copied, including the selected command and filters.',result:'matches',unavailable:'This entry does not provide standalone session operations. Use session run or the web UI.',remoteNote:'Register the target and credentials first, and respect its policy. Leave confirmation to a person and verify state after a lost reply.',writeNote:'This command may change configuration, files or services. Copying an example neither executes nor authorizes a change.',humanNote:'Requires a real interactive TTY. Noninteractive agents must not confirm on your behalf; --yes cannot bypass it.',outputNote:'Prints to stdout by default. Redirection, --output or sourcing a completion script is a separate local operation.' }
  };
  const flagHints = {
    json:'输出结构化结果；部分工具类命令仍按自己的输出方式运行。',daemon:'仅 exec 使用已启动的本机复用服务，不自动启动或失败回退。',
    config:'指定本地配置目录，优先于 SSH_CLI_HOME 和系统默认目录。',host:'目标主机别名，可重复；host add/edit 中同名本地参数另指地址。',group:'按分组选择目标；host add/edit 中同名本地参数为主机归属。',env:'按环境限制目标；policy dangerous set 中为规则作用环境。',tag:'按标签选择（多个标签取 OR）；主机编辑时为替换标签列表。',
    yes:'通常只允许交互式 TTY；不是非交互 Agent 的确认豁免。update 的非交互安装另有规则。','insecure-ignore-host-key':'跳过服务端密钥核验的逃生选项，不作为常规操作方式。','allow-cross-env':'显式允许一次选择跨环境目标，仍不越过各主机权限。','skip-denied':'跳过被拒绝的目标，不改变拒绝规则。',
    timeout:'限制此操作的时间预算；超时不能回滚远端已经发生的变更。',parallel:'并行执行的主机数量上限。',script:'从本地文件读取要执行的远端脚本。',stdin:'从本地标准输入读取脚本。','forward-stdin':'将标准输入转给单个远端命令，不等于把输入作为 shell 脚本解析。',
    backup:'覆盖前为已有远端文件保留 .ssh-cli.bak。','confirm-overwrite':'覆盖时要求输入主机别名，没有 TTY 则拒绝。',agent:'使用本机 SSH_AUTH_SOCK；不转发 SSH agent。','agent-key':'选择 SSH agent 公钥的 SHA256 指纹。',identity:'本地私钥文件路径，不是私钥内容。','password-stdin':'从标准输入读取密码；不要把密码写进参数或聊天。',via:'引用已登记的跳板主机。',
    allow:'命令参数前缀的允许列表，不是 shell 通配符。',deny:'命令参数前缀的拒绝规则。',confirm:'命令参数前缀的人工确认规则。','protected-path':'受保护的远端路径，可重复设置。',mode:'策略模式：readonly、standard 或 admin，仍受环境上限约束。','max-mode':'环境允许的最高模式。',
    from:'来源：主机别名:/远端路径。',to:'目标：主机别名:/远端路径。',reason:'写入审计的破窗原因，不应包含凭据。',ttl:'破窗操作的最长时间，还受已配置上限约束。','max-ttl':'环境允许的破窗 TTL 上限。',
    'retention-days':'自动保留天数；0 关闭自动删除，其他取值 30–3650。','require-writable':'审计准入不可持久化时，拒绝新的相关远端操作。',follow:'持续等待新增审计，需手动停止。','dry-run':'只展示导入计划，不应用变更。',output:'输出文件路径；不传通常输出到终端。',
    enable:'启用危险目录开关；还需选择规则才会拦截。',rule:'要拦截的危险目录规则 ID，可重复。',all:'选中全部危险目录规则。',disable:'关闭相应开关；危险拦截缩小时可能需要确认。',
    check:'仅检查更新，不替换当前二进制。','allow-missing-checksum':'显式允许没有校验和的发布包；校验不匹配仍会失败。',addr:'本机 UI 监听地址，默认 127.0.0.1:7788。'
  };
  const synonyms = {
    upload:'上传 传文件 备份 覆盖 SFTP',download:'下载 保存文件 SFTP',relay:'跨机 复制 中继 传文件',exec:'运行 执行 命令 脚本 shell',
    'host-add':'添加主机 密码 私钥 ssh-agent 认证', 'host-edit':'修改主机 密码 私钥 ssh-agent 认证',
    'keys-known-list':'服务端 指纹 信任 密钥', 'policy-show':'权限 检查 只读 规则', 'policy-explain':'权限 检查 拒绝 确认'
  };
  let language = 'zh';
  try { if (localStorage.getItem('ssh-cli-site-language') === 'en') language = 'en'; } catch { /* Optional preference storage. */ }
  const languageQuery = new URL(location.href).searchParams.get('lang');
  if (languageQuery === 'en' || languageQuery === 'zh') language = languageQuery;
  let selected = 'exec', page = 0, copyGeneration = 0;
  const mobile = matchMedia('(max-width: 49.99rem)');
  const label = pair => pair[language === 'zh' ? 0 : 1];
  const normalize = value => String(value).normalize('NFKC').toLocaleLowerCase().trim();
  function write(id, value) { $(id).textContent = value; }
  function element(tag, className, value) { const node = document.createElement(tag); if (className) node.className = className; if (value !== undefined) node.textContent = value; return node; }
  function syncUrl(push = false) {
    const url = new URL(location.href);
    for (const [name, value] of [['q',$('command-query').value.trim()],['category',$('command-category').value],['effect',$('command-effect').value]]) {
      if (value && value !== 'all') url.searchParams.set(name, value); else url.searchParams.delete(name);
    }
    url.searchParams.set('lang',language);
    url.hash = selected;
    if (url.href !== location.href) history[push ? 'pushState' : 'replaceState'](null, '', url);
  }
  function matches() {
    const tokens = normalize($('command-query').value).split(/\s+/).filter(Boolean);
    return entries.filter(command => {
      if ($('command-category').value !== 'all' && command.category !== $('command-category').value) return false;
      if ($('command-effect').value !== 'all' && command.note.effect !== $('command-effect').value) return false;
      const haystack = normalize([command.path, command.id, command.aliases, command.summary, command.description, command.searchFlags, command.note.title, command.note.noteZh || '', command.note.noteEn || '', synonyms[command.id] || '', ...categories[command.category]].join(' '));
      return tokens.every(token => haystack.includes(token));
    }).sort((a,b) => {
      const query = normalize($('command-query').value);
      const rank = command => query && (normalize(command.id) === query || normalize(command.path) === query || normalize(command.path).replace('ssh-cli ','') === query) ? -100 : common.includes(command.id) ? common.indexOf(command.id) : 100;
      return rank(a)-rank(b) || a.path.localeCompare(b.path);
    });
  }
  function renderResults() {
    const focusedId=document.activeElement?.closest('.command-result')?.dataset.id;
    const result = matches(), pages = Math.max(1, Math.ceil(result.length/pageSize));
    page = Math.max(0, Math.min(page, pages-1));
    $('command-results').replaceChildren();
    for (const command of result.slice(page*pageSize,(page+1)*pageSize)) {
      const button = element('button','command-result'); button.type = 'button'; button.dataset.id = command.id;
      button.setAttribute('aria-current', String(command.id===selected));
      button.append(element('code','',command.path),element('span','command-result-description',language==='zh'?command.note.title:command.summary));
      button.addEventListener('click',()=>choose(command.id,true)); $('command-results').append(button);
    }
    if (!result.length) $('command-results').append(element('p','command-empty',copy[language].empty));
    write('command-match-count',result.length+' / '+entries.length); write('page-state',(page+1)+' / '+pages);
    $('previous-page').disabled=page===0; $('next-page').disabled=page>=pages-1;
    if(focusedId)[...$('command-results').querySelectorAll('button')].find(button=>button.dataset.id===focusedId)?.focus({preventScroll:true});
  }
  function renderFlags(target, flags, command) {
    $(target).replaceChildren();
    for (const flag of flags) {
      const row=element('div','flag-row'), name=element('div'), description=element('div','flag-description');
      name.append(element('code','',(flag.short?'-'+flag.short+', ':'')+'--'+flag.name),element('span','flag-type',flag.type));
      let hint=flagHints[flag.name];
      if (flag.name==='host' && ['host-add','host-edit'].includes(command.id)) hint='此处填写远端地址或 DNS 名称。远端操作命令中的 -H 则用来选择已登记别名。';
      if (flag.name==='group' && ['host-add','host-edit'].includes(command.id)) hint='此主机所属的业务分组。';
      if (flag.name==='env' && command.id==='group-add') hint='新分组所属的环境，必须填写且只能指定一个。';
      if (flag.name==='env' && command.id==='policy-dangerous-set') hint='危险规则实际生效的环境，可重复；未指定时默认 prod。';
      if (language==='zh' && hint) description.append(element('div','',hint));
      description.append(element('p','',flag.description)); row.append(name,description); $(target).append(row);
    }
    if (!flags.length) $(target).append(element('p','parameter-note',copy[language].none));
  }
  function renderDetail() {
    const command=byId.get(selected); if (!command) return;
    copyGeneration++;
    write('command-title',command.path); write('command-purpose',language==='zh'?command.note.title:command.summary);
    write('command-impact',label(effects[command.note.effect])); $('command-impact').dataset.effect=command.note.effect;
    write('command-category-label',label(categories[command.category])); write('command-usage',command.usage);
    write('command-example',command.note.example); write('command-raw-help',command.help);
    // Resolve parents by actual child lists; hyphens can be part of a command name.
    const parent=entries.find(entry=>entry.children.includes(command.id));
    $('command-parent').href='#'+(parent?.id||'root');
    $('command-parent').textContent=parent?parent.path:copy[language].allCommands;
    $('command-cautions').replaceChildren();
    const note=language==='zh'?command.note.noteZh:command.note.noteEn;
    if (note) $('command-cautions').append(element('p','',note));
    const effectNote=command.note.effect==='process-only'?'unavailable':command.note.effect==='human'?'humanNote':['remote-read','remote-write','transfer','mixed'].includes(command.note.effect)?'remoteNote':['local-write','local-update'].includes(command.note.effect)?'writeNote':command.note.effect==='local-output'?'outputNote':null;
    if (effectNote) $('command-cautions').append(element('p','',copy[language][effectNote]));
    $('command-children-section').hidden=!command.children.length; $('command-children').replaceChildren();
    for (const childId of command.children) {const child=byId.get(childId);if(!child)continue;const link=element('a');link.href='#'+childId;link.dataset.command=childId;link.append(element('code','',child.path));$('command-children').append(link);}
    renderFlags('command-flags',command.flags,command);renderFlags('command-global-flags',command.globalFlags,command);
    write('local-flag-count',command.flags.length);write('global-flag-count',command.globalFlags.length);
    write('command-help-call',command.path+' --help');
    document.querySelectorAll('.reference-disclosure').forEach(detail=>{detail.open=false;});
    for(const [button,status,manual,key] of [['copy-command','command-copy-status','command-copy-manual','copy'],['copy-command-link','command-link-status','command-link-manual','copyLink']]) {write(button,copy[language][key]);write(status,'');$(button).dataset.state='default';$(button).disabled=false;$(manual).hidden=true;}
  }
  function choose(id, push=false) {
    if(!byId.has(id))return;
    const detailNavigation=document.activeElement?.matches('[data-command],#command-parent');
    selected=id; renderDetail(); renderResults();syncUrl(push);
    if(mobile.matches)$('command-results-disclosure').open=false;
    if(mobile.matches||detailNavigation){$('command-detail').scrollIntoView({block:'start'});$('command-detail').focus({preventScroll:true});}
  }
  function renderLanguage() {
    const category=$('command-category').value||'all', effect=$('command-effect').value||'all';
    document.documentElement.lang=language==='zh'?'zh-CN':'en';document.title=copy[language].title+' · ssh-cli';
    for(const [attribute,target] of [['data-copy','textContent'],['data-label','aria-label'],['data-placeholder','placeholder']])document.querySelectorAll('['+attribute+']').forEach(node=>{const value=copy[language][node.getAttribute(attribute)];if(target==='textContent')node.textContent=value;else node.setAttribute(target,value);});
    write('language',language==='zh'?'EN':'中文');$('language').setAttribute('aria-label',language==='zh'?'Switch to English':'切换到中文');write('command-total',entries.length);
    for(const [id,source,current] of [['command-category',categories,category],['command-effect',effects,effect]]){$(id).replaceChildren(...Object.entries(source).map(([value,pair])=>{const option=element('option','',label(pair));option.value=value;return option;}));$(id).value=Object.hasOwn(source,current)?current:'all';}
    renderDetail();renderResults();
  }
  function fromLocation() {
    const url=new URL(location.href);let id;
    const requestedLanguage=url.searchParams.get('lang');
    if(['zh','en'].includes(requestedLanguage)&&requestedLanguage!==language){language=requestedLanguage;renderLanguage();}
    try{id=decodeURIComponent(url.hash.slice(1));}catch{id='';}
    selected=byId.has(id)?id:'exec';$('command-query').value=url.searchParams.get('q')||'';
    $('command-category').value=Object.hasOwn(categories,url.searchParams.get('category'))?url.searchParams.get('category'):'all';
    $('command-effect').value=Object.hasOwn(effects,url.searchParams.get('effect'))?url.searchParams.get('effect'):'all';
    const at=matches().findIndex(command=>command.id===selected);page=at<0?0:Math.floor(at/pageSize);
    renderDetail();renderResults();
  }
  async function copyValue(buttonId,statusId,manualId,value,isLink=false) {
    const generation=copyGeneration, button=$(buttonId);button.disabled=true;button.dataset.state='loading';button.textContent=copy[language].copying;
    try{await navigator.clipboard.writeText(value);if(generation!==copyGeneration)return;button.dataset.state='success';button.textContent=copy[language].copied;write(statusId,copy[language][isLink?'linkSuccess':'copySuccess']);}
    catch{if(generation!==copyGeneration)return;button.dataset.state='error';button.textContent=copy[language][isLink?'copyLink':'copy'];write(statusId,copy[language].copyError);$(manualId).hidden=false;$(manualId).value=value;$(manualId).focus({preventScroll:true});$(manualId).select();}
    finally{if(generation===copyGeneration)button.disabled=false;}
  }
  document.addEventListener('click',event=>{const link=event.target.closest('[data-command]');if(link&&!event.metaKey&&!event.ctrlKey&&!event.shiftKey&&!event.altKey){event.preventDefault();choose(link.dataset.command,true);}});
  $('command-parent').addEventListener('click',event=>{if(event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;event.preventDefault();choose($('command-parent').hash.slice(1),true);});
  $('command-query').addEventListener('input',()=>{page=0;renderResults();syncUrl();if(mobile.matches)$('command-results-disclosure').open=true;});
  $('command-query').addEventListener('focus',()=>{if(mobile.matches)$('command-results-disclosure').open=true;});
  $('clear-query').addEventListener('click',()=>{$('command-query').value='';page=0;renderResults();syncUrl();$('command-query').focus();if(mobile.matches)$('command-results-disclosure').open=true;});
  ['command-category','command-effect'].forEach(id=>$(id).addEventListener('change',()=>{page=0;renderResults();syncUrl();if(mobile.matches)$('command-results-disclosure').open=true;}));
  for(const [id,offset] of [['previous-page',-1],['next-page',1]])$(id).addEventListener('click',()=>{page+=offset;renderResults();$('command-results').scrollTop=0;});
  $('copy-command').addEventListener('click',()=>copyValue('copy-command','command-copy-status','command-copy-manual',byId.get(selected).note.example));
  $('copy-command-link').addEventListener('click',()=>{syncUrl();copyValue('copy-command-link','command-link-status','command-link-manual',location.href,true);});
  $('language').addEventListener('click',()=>{language=language==='zh'?'en':'zh';try{localStorage.setItem('ssh-cli-site-language',language);}catch{}renderLanguage();syncUrl();});
  document.addEventListener('keydown',event=>{
    const editing=event.target.matches('input,textarea,select')||event.target.isContentEditable;
    if((event.key==='/'&&!editing&&!event.metaKey&&!event.ctrlKey)||((event.ctrlKey||event.metaKey)&&!event.altKey&&event.key.toLowerCase()==='k')){event.preventDefault();$('command-query').focus();$('command-query').select();if(mobile.matches)$('command-results-disclosure').open=true;}
    const results=[...document.querySelectorAll('.command-result')],index=results.indexOf(document.activeElement);
    if((document.activeElement===$('command-query')||index>=0)&&results.length){if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();const delta=event.key==='ArrowDown'?1:-1;results[index<0?(delta>0?0:results.length-1):(index+delta+results.length)%results.length].focus();}if(event.key==='Enter'&&document.activeElement===$('command-query')){event.preventDefault();results[0].click();}}
  });
  addEventListener('popstate',fromLocation);addEventListener('hashchange',fromLocation);
  mobile.addEventListener('change',()=>{$('command-results-disclosure').open=!mobile.matches;});
  renderLanguage();fromLocation();$('command-results-disclosure').open=!mobile.matches;document.documentElement.classList.remove('no-js');
})();
