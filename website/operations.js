'use strict';
// Inert workflow examples. Only the audit verification outcomes come from generated local fixtures.
(() => {
  const $ = id => document.getElementById(id);
  const t = {
    zh: {
      flowTitle:'Agent 接到任务后，怎么一步步做', flowLead:'选准范围，再看差异；需要操作时检查规则，结果按主机留下记录。切换下面的步骤看具体调用。',
      scopeTab:'Agent 选机',logsTab:'双实例日志',credentialsTab:'密码怎么用',policyTab:'生产策略',recordsTab:'操作记录',reuseTab:'复用连接',
      before:'直接调用 SSH',after:'使用 ssh-cli',scopeBefore:'自行维护地区、环境与目标筛选。',scopeAfter:'Agent 读取分类清单，筛好后按别名调用。',logsBefore:'自行给多台输出补主机身份、整理结果。',logsAfter:'JSON 保留主机和状态，便于 Agent 对照。',policyBefore:'主要依赖远端账号权限与调用方检查。',policyAfter:'CLI 发送前再按环境、分组和主机规则检查。',auditBefore:'自行收集调用记录并做完整性保护。',auditAfter:'按主机记录，可启用完整性核验。',
      taskLabel:'给 Agent 的任务示例',region:'地区',environment:'环境',service:'服务标签',hunan:'湖南',xinjiang:'新疆',zibo:'淄博',test:'测试',prod:'生产',
      scopeTitle:'先列清单，再锁定这两台',scopeLead:'地区用分组或标签组织，环境单独标记。Agent 读取清单、筛出分组和标签，再用明确的主机别名执行。',
      listLabel:'1 · 读取目标环境的主机清单',selectedLabel:'2 · Agent 从返回的分组、标签中筛出目标',scopeNote:'示例登记，不读取真实配置。地区以分组组织；权限仍按每台主机的策略检查。',
      logsTitle:'把两台实例的日志放在一起看',logsLead:'读取同一服务的最近日志，结果带着各自主机身份。差异交给 Agent 分析，先核验再决定是否操作。',
      logsCommand:'对已核对的两个别名读取日志',logsExample:'示例日志，非服务器实测。页面不执行命令，也不实时诊断。',
      logsFinding:'实例 1 出现数据库连接超时，实例 2 正常。先核对实例配置、版本与数据库连通性；这些日志还不足以确定根因。',
      auditJump:'接着看操作记录 ↓',recordsTitle:'哪台主机做了什么，按记录核对',recordsLead:'CLI 执行、上传、下载等按主机记下命令和结果。可启用 HMAC 完整性保护，核验记录是否被修改、删除或截断。',
      original:'完整记录',tampered:'修改一条',deleted:'删除日志',auditGroup:'审计完整性示例',auditGood:'校验通过',auditBad:'发现完整性异常',auditMissing:'示例日志已移除，保留的校验基线仍能发现缺失。',
      auditNote:'示例记录未对应远端执行；三种校验结果由实际审计模块生成。点击只切换展示，不修改你的日志。',
      auditBoundary:'本机保护不等于不可变存证：密钥被取得，或日志与校验基线一起回滚，超出本机校验边界。',
      auditMore:'启用保护与写入保障',auditSetup:'首次 audit protect 由你在终端确认。可再启用审计不可写则拒绝新操作；重要场景把校验基线保存在独立可信位置。',
      performanceTitle:'连续查几条命令，可以复用 SSH 连接',performanceLead:'同一主机的连接仍有效时，后续 exec 可复用它，减少重复握手和认证。每条命令的策略仍会重新检查。',
      reuse:'启用复用',direct:'默认直连',reuseGroup:'连接方式示意',reuseNotice:'先在单独终端启动 daemon，再给 exec 加 --daemon；不会自动启动。仅覆盖无需确认的 exec，不含文件传输。',
      directNotice:'默认每次独立连接；适合临时调用。复用图只说明连接方式，没有延迟或速度实测数据。',
      reuseCount:'1 条有效 SSH 连接 · 3 个命令会话',directCount:'3 次独立 SSH 建连 · 3 条命令',
      reuseCondition:'示意条件：同一台主机，连接未断开、未过期。复用失败不自动回退，也不重放命令。',
      moreBenefits:'还有哪些现成步骤，与直接 SSH 调用有什么不同？',task:'日常任务',plain:'Agent 直接用 ssh / scp',provided:'ssh-cli 提供的流程',
      rowScope:'整理多机结果',plainScope:'调用方整理主机身份、输出和退出状态。',providedScope:'JSON 带主机、环境、结果状态，方便合并比较。',
      rowFiles:'替换远端文件',plainFiles:'自行安排备份、暂存和结果核对。',providedFiles:'暂存后提交；可选 --backup，传输结果带校验信息。',
      rowUnknown:'响应中断',plainUnknown:'调用方判断远端是否已执行。',providedUnknown:'用 unknown 标记不确定结果，供核验；不自动重跑。',
      rowParallel:'多机检查',plainParallel:'自行组织并发和结果归属。',providedParallel:'exec 可显式并发，最多 4 台；仍整体检查策略。',
      fair:'OpenSSH 也支持密钥、跳板和连接复用。这里的便利是把分类、检查、结果和审计接成一套 Agent 调用流程，不是每一项都独有。',
      copy:'复制命令',copying:'复制中…',copied:'已复制',copyOK:'只复制了示例，未执行。',copyError:'剪贴板不可用，请选中下方原文复制。',manual:'手动复制命令',
      uiOptional:'人工网页工作台（可选）',uiOptionalLead:'多标签终端、文件目录、拖拽上传下载和监控。需要人工接手时再打开。'
    },
    en: {
      flowTitle:'How an agent works through a task',flowLead:'Choose the scope, compare evidence, check policy before changes, then review results by host. Switch steps for concrete calls.',
      scopeTab:'Hosts',logsTab:'Compare logs',credentialsTab:'Credentials',policyTab:'Policy checks',recordsTab:'Audit records',reuseTab:'Reuse SSH',
      before:'Direct SSH calls',after:'With ssh-cli',scopeBefore:'Maintain region, environment and target filtering yourself.',scopeAfter:'Read categorized inventory, filter it, then call explicit aliases.',logsBefore:'Attribute and combine output from separate host calls.',logsAfter:'JSON retains host identity and outcome for comparison.',policyBefore:'Rely on remote account permissions and caller-side checks.',policyAfter:'Also check environment, group and host rules before sending.',auditBefore:'Collect operation records and protect their integrity yourself.',auditAfter:'Per-host records with optional integrity verification.',
      taskLabel:'Example task for an agent',region:'Region',environment:'Environment',service:'Service tag',hunan:'Hunan',xinjiang:'Xinjiang',zibo:'Zibo',test:'Test',prod:'Production',
      scopeTitle:'Read the inventory. Pin down these two hosts.',scopeLead:'Organize regions through groups or tags, with a separate environment. The agent filters returned metadata and executes against explicit aliases.',
      listLabel:'1 · Read the environment’s inventory',selectedLabel:'2 · Match the returned group and tags',scopeNote:'Illustrative registrations only; your configuration is not read. Region is not an extra built-in permission layer.',
      logsTitle:'Compare two instances side by side',logsLead:'Read recent logs for the same service, with each result tied to its host. The agent reviews differences and verifies before acting.',
      logsCommand:'Read logs from the two verified aliases',logsExample:'Illustrative logs, not server measurements. Nothing is executed or diagnosed live.',
      logsFinding:'Instance 1 shows a database connection timeout; instance 2 completes normally. Check configuration, versions and database connectivity next. These lines alone do not establish a root cause.',
      auditJump:'Review operation records next ↓',recordsTitle:'Review what ran on each host',recordsLead:'CLI execution and transfers record the command and result per host. Optional HMAC integrity protection can detect edits, deletion and truncation against its checkpoint.',
      original:'Intact',tampered:'Edit a record',deleted:'Delete logs',auditGroup:'Audit integrity example',auditGood:'Verification passed',auditBad:'Integrity mismatch detected',auditMissing:'The example log was removed; the retained checkpoint still detects the missing file.',
      auditNote:'These example records do not represent remote execution. Verification outcomes come from the actual audit module. Buttons only switch the display.',
      auditBoundary:'Local protection is not immutable evidence. Key theft or rollback of both logs and checkpoint lies outside this integrity boundary.',
      auditMore:'Enable protection and write admission',auditSetup:'Confirm the initial audit protect in your terminal. Optionally refuse new operations when audit admission cannot be saved. Keep an independent trusted checkpoint when required.',
      performanceTitle:'Reuse SSH for consecutive checks',performanceLead:'While a host connection remains valid, later exec calls can reuse it, reducing repeated handshakes and authentication. Policy is still checked for every command.',
      reuse:'Reuse enabled',direct:'Direct default',reuseGroup:'Connection example',reuseNotice:'Start the foreground daemon separately, then pass --daemon to exec. It never starts automatically. Reuse covers non-confirming exec calls, not file transfers.',
      directNotice:'Calls connect independently by default. The diagram explains connection behavior, without measured latency or speed claims.',
      reuseCount:'1 valid SSH connection · 3 command sessions',directCount:'3 separate SSH connections · 3 commands',
      reuseCondition:'Assumes the same host and an unexpired, connected session. Failure does not cause automatic fallback or replay.',
      moreBenefits:'Other ready-made steps, compared with direct SSH calls',task:'Task',plain:'Agent calling ssh / scp directly',provided:'ssh-cli workflow',
      rowScope:'Combine host results',plainScope:'Arrange host identity, output and exit status.',providedScope:'JSON carries host, environment and outcome for comparison.',
      rowFiles:'Replace remote files',plainFiles:'Arrange backup, staging and verification.',providedFiles:'Stage before committing; optional --backup and verification details.',
      rowUnknown:'Lost response',plainUnknown:'Determine whether the operation ran remotely.',providedUnknown:'An unknown outcome signals verification before another attempt.',
      rowParallel:'Check multiple hosts',plainParallel:'Arrange concurrency and result attribution.',providedParallel:'Explicit exec concurrency, up to 4, with policy preflight.',
      fair:'OpenSSH also supports keys, jump hosts and connection reuse. The convenience here is one agent workflow for organization, checks, results and audit; these capabilities are not individually unique.',
      copy:'Copy command',copying:'Copying…',copied:'Copied',copyOK:'Example copied; nothing executed.',copyError:'Clipboard unavailable. Select and copy the text below.',manual:'Copy the command manually',
      uiOptional:'Local workbench (optional)',uiOptionalLead:'Terminal tabs, file browsing, drag-and-drop transfers and monitoring, when a person takes over.'
    }
  };
  const regions=[{id:'hunan',short:'hn'},{id:'xinjiang',short:'xj'},{id:'zibo',short:'zb'}];
  const state={flow:'targets',region:'hunan',env:'test',service:'wms',audit:'original',reuse:true};
  let language='zh',epoch=0;
  const words=()=>t[language];
  const el=(tag,text,cls)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;};
  const inventory=regions.flatMap((r,ri)=>['test','prod'].flatMap((env,ei)=>['wms','api'].flatMap((service,si)=>[1,2].map(n=>({alias:r.short+'-'+env+'-'+service+'-0'+n,group:r.id+'-'+env,env,tags:[service,'instance-'+n],host:'192.0.2.'+(10+ri*8+ei*4+si*2+n)})))));
  const commandLink=id=>'commands.html?lang='+language+'#'+id;
  function scope(){return inventory.filter(h=>h.group===state.region+'-'+state.env&&h.tags.includes(state.service));}
  function resetCopies(){
    epoch++;
    document.querySelectorAll('[data-ops-copy]').forEach(b=>{b.disabled=false;b.dataset.state='default';b.textContent=words().copy;const box=b.closest('.ops-command');box.querySelector('[role="status"]').textContent='';box.querySelector('textarea').hidden=true;});
  }
  function renderScope(){
    const w=words(),hosts=scope(),region=w[state.region],environment=w[state.env],service=state.service;
    $('ops-request').textContent=language==='zh'?'比较'+region+environment+'环境中，标记 '+service+' 的两个实例。先看日志差异，不要重启。':'Compare the two '+service+' instances in '+region+' / '+environment+'. Review logs first; do not restart them.';
    $('ops-list-command').textContent='ssh-cli host list --env '+state.env+' --json';
    $('ops-selection').textContent=language==='zh'?'group = '+state.region+'-'+state.env+'，tags 包含 '+service+' → '+hosts.length+' 台目标':'group = '+state.region+'-'+state.env+', tags include '+service+' → '+hosts.length+' targets';
    $('ops-hosts').replaceChildren(...hosts.map(h=>{const li=el('li');const identity=el('div');identity.append(el('strong',h.alias),el('small','deploy@'+h.host));const meta=el('div');meta.append(el('span',h.group+' · '+h.env),el('small',h.tags.join(' / ')));li.append(identity,meta);return li;}));
    $('ops-log-command').textContent='ssh-cli exec '+hosts.map(h=>'-H '+h.alias).join(' ')+' --env '+state.env+' --parallel 2 --json -- journalctl -u '+service+' -n 40 --no-pager';
    $('ops-logs').replaceChildren(...hosts.map((h,i)=>{const article=el('article');article.append(el('h4',h.alias),el('pre','09:41:02 INFO service='+service+' version='+(i?'2.5.9':'2.6.0')+'\n'+(i?'09:42:11 INFO request completed status=200':'09:42:11 ERROR database connection timeout')));return article;}));
    $('ops-scope-docs').href=commandLink('host-list');$('ops-log-docs').href=commandLink('exec');
    for(const [id,value] of [['ops-region',state.region],['ops-env',state.env],['ops-service',state.service]])$(id).value=value;
  }
  function renderAudit(){
    const fixture=window.SSH_CLI_AUDIT_EXAMPLES,w=words();
    $('ops-verify-command').textContent='ssh-cli audit verify --json';
    if(!fixture){$('ops-audit-status').textContent=language==='zh'?'示例数据未加载，请刷新重试。':'Example data unavailable. Reload to retry.';$('ops-audit-status').dataset.state='error';document.querySelectorAll('[data-audit-case]').forEach(b=>b.disabled=true);return;}
    const value=fixture.variants[state.audit],rows=state.audit==='deleted'?[]:fixture.records;
    $('ops-audit-rows').replaceChildren(...rows.map((r,i)=>{const li=el('li');li.append(el('strong',r.host),el('small','09:41:0'+i+' · '+r.env+' / '+r.group+' · source='+r.source),el('code',state.audit==='tampered'&&i===0?'rm -rf /opt/app':r.command));return li;}));
    $('ops-audit-empty').hidden=rows.length>0;
    $('ops-audit-status').textContent=value.ok?w.auditGood:w.auditBad;$('ops-audit-status').dataset.state=value.ok?'success':'error';
    $('ops-audit-output').textContent=value.ok?'{"ok":true,"integrity":"verified"}':value.error;
    document.querySelectorAll('[data-audit-case]').forEach(b=>{const on=b.dataset.auditCase===state.audit;b.setAttribute('aria-pressed',String(on));});
  }
  function renderReuse(){
    const w=words(),alias=scope()[0].alias;
    $('ops-reuse-count').textContent=state.reuse?w.reuseCount:w.directCount;
    $('ops-reuse-note').textContent=state.reuse?w.reuseNotice:w.directNotice;
    $('ops-reuse-command').textContent=(state.reuse?'ssh-cli daemon serve\n\n':'')+['uptime','df -h /','free -m'].map(c=>'ssh-cli exec '+(state.reuse?'--daemon ':'')+'-H '+alias+' --json -- '+c).join('\n');
    $('ops-reuse-diagram').replaceChildren(...['uptime','df -h /','free -m'].map((c,i)=>{const row=el('div');row.append(el('code',c),el('span',(state.reuse?'SSH 1':'SSH '+(i+1))+' → '+(language==='zh'?'会话 ':'session ')+(i+1)));return row;}));
    document.querySelectorAll('[data-reuse]').forEach(b=>{const on=(b.dataset.reuse==='on')===state.reuse;b.setAttribute('aria-pressed',String(on));});
    $('ops-reuse-docs').href=commandLink('daemon-serve');
  }
  const panels=['targets','logs','credentials','lab','records','performance'];
  function showFlow(id,scroll=false){
    if(!panels.includes(id))return;state.flow=id;
    panels.forEach(p=>{$(p).hidden=p!==id;});
    document.querySelectorAll('[data-flow]').forEach(b=>{const on=b.dataset.flow===id;b.setAttribute('aria-selected',String(on));b.tabIndex=on?0:-1;});
    $('ops-context').hidden=!['targets','logs'].includes(id);resetCopies();
    document.dispatchEvent(new CustomEvent('ssh-cli-flow-change'));
    if(scroll)$('flow-frame').scrollIntoView({block:'start'});
  }
  function route(hash,scroll=false){const id=hash.replace('#','');if(panels.includes(id))showFlow(id,scroll);else if(id==='credential-details'){showFlow('credentials',scroll);$('credential-details').open=true;}}
  function render(){
    document.querySelectorAll('[data-ops-i18n]').forEach(n=>{const v=words()[n.dataset.opsI18n];if(v!==undefined)n.textContent=v;});
    document.querySelectorAll('[data-ops-aria]').forEach(n=>n.setAttribute('aria-label',words()[n.dataset.opsAria]));
    document.querySelectorAll('.ops-command textarea').forEach(n=>n.setAttribute('aria-label',words().manual));
    $('flow-tabs').setAttribute('aria-label',language==='zh'?'Agent 排查流程':'Agent workflow');
    $('ops-region').replaceChildren(...regions.map(r=>{const o=el('option',words()[r.id]);o.value=r.id;return o;}));
    $('ops-env').replaceChildren(...['test','prod'].map(v=>{const o=el('option',words()[v]);o.value=v;return o;}));
    renderScope();renderAudit();renderReuse();showFlow(state.flow);
  }
  document.addEventListener('ssh-cli-language',e=>{language=e.detail==='en'?'en':'zh';render();});
  document.addEventListener('ssh-cli-flow',e=>showFlow(e.detail,true));
  for(const [id,key] of [['ops-region','region'],['ops-env','env'],['ops-service','service']])$(id).addEventListener('change',()=>{state[key]=$(id).value;render();});
  document.querySelectorAll('[data-flow]').forEach(b=>b.addEventListener('click',()=>showFlow(b.dataset.flow)));
  $('flow-tabs').addEventListener('keydown',e=>{const tabs=[...document.querySelectorAll('[data-flow]')],i=tabs.indexOf(document.activeElement);let next=i;if(['ArrowDown','ArrowRight'].includes(e.key))next=(i+1)%tabs.length;else if(['ArrowUp','ArrowLeft'].includes(e.key))next=(i-1+tabs.length)%tabs.length;else if(e.key==='Home')next=0;else if(e.key==='End')next=tabs.length-1;else return;e.preventDefault();showFlow(tabs[next].dataset.flow);tabs[next].focus({preventScroll:true});});
  document.querySelectorAll('[data-audit-case]').forEach(b=>b.addEventListener('click',()=>{state.audit=b.dataset.auditCase;renderAudit();}));
  document.querySelectorAll('[data-reuse]').forEach(b=>b.addEventListener('click',()=>{state.reuse=b.dataset.reuse==='on';renderReuse();resetCopies();}));
  document.querySelectorAll('[data-ops-copy]').forEach(b=>b.addEventListener('click',async()=>{
    const token=epoch,box=b.closest('.ops-command'),value=$(b.dataset.opsCopy).textContent,status=box.querySelector('[role="status"]'),manual=box.querySelector('textarea');
    b.disabled=true;b.dataset.state='loading';b.textContent=words().copying;
    try{await navigator.clipboard.writeText(value);if(token!==epoch)return;b.dataset.state='success';b.textContent=words().copied;status.textContent=words().copyOK;}
    catch{if(token!==epoch)return;b.dataset.state='error';b.textContent=words().copy;status.textContent=words().copyError;manual.hidden=false;manual.value=value;manual.focus({preventScroll:true});manual.select();}
    finally{if(token===epoch)b.disabled=false;}
  }));
  document.addEventListener('click',e=>{const a=e.target.closest('a[href^="#"]');if(!a)return;const id=a.getAttribute('href').slice(1);if(!panels.includes(id)&&id!=='credential-details')return;e.preventDefault();if(location.hash!=='#'+id)history.pushState(null,'','#'+id);route('#'+id,true);});
  window.addEventListener('hashchange',()=>route(location.hash,true));
  render();document.documentElement.classList.remove('no-flow');route(location.hash);
})();
