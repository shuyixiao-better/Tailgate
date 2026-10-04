'use strict';

const $ = (id) => document.getElementById(id);
const state = { session: null, hosts: [], view: 'overview', setting: 'hosts', settings: null, detailHost: '', hostEdit: '', userEdit: '', auditOffset: 0, auditTotal: 0, auditLimit: 50, terminals: new Map(), activeTerminal: null, terminalSequence: 0, logSocket: null, logText: '', logPaused: false, logScheduled: false, refreshing: false };
const pageInfo = { overview: ['主机总览', '一眼了解服务器的运行状态。'], terminal: ['网页终端', '一个工作空间，连接多台服务器。'], logs: ['日志查看器', '跟踪现场日志，让问题浮出水面。'], audit: ['操作审计', '每一次访问，每一条命令，都有迹可循。'], settings: ['网关设置', '管理服务器、访问凭证与网页用户。'] };
const dateFormatter = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
let confirmResolve = null;

function element(tag, className, text) { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined && text !== null) node.textContent = String(text); return node; }
function button(text, className, action) { const node = element('button', 'button ' + (className || 'secondary'), text); node.type = 'button'; node.addEventListener('click', action); return node; }
function badge(text, kind) { return element('span', 'badge ' + (kind || ''), text); }
function percent(value) { return value === null || value === undefined || !Number.isFinite(Number(value)) ? '—' : Number(value).toFixed(1) + '%'; }
function bytes(value) { if (value === null || value === undefined) return '—'; const n = Number(value); if (!Number.isFinite(n)) return '—'; if (n === 0) return '0 B'; const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; const i = Math.min(Math.floor(Math.log(Math.max(n, 1)) / Math.log(1024)), units.length - 1); return (n / (1024 ** i)).toFixed(i ? 1 : 0) + ' ' + units[i]; }
function time(value) { if (!value || String(value).startsWith('0001-')) return '尚未采集'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '—' : dateFormatter.format(date); }
function uptime(seconds) { if (seconds === null || seconds === undefined) return '—'; const minutes = Math.floor(Number(seconds) / 60); const days = Math.floor(minutes / 1440); const hours = Math.floor((minutes % 1440) / 60); return (days ? days + ' 天 ' : '') + hours + ' 小时 ' + (minutes % 60) + ' 分'; }
function hostStatus(host) { return host.status || host; }
function hostName(host) { return host.name || host.host || ''; }
function highestDisk(status) { return (status.disks || []).reduce((max, disk) => Math.max(max, Number(disk.used_percent) || 0), 0); }
function hostAlert(host) { const s = hostStatus(host); return !s.online || highestDisk(s) > 85 || (s.failed_services || []).length > 0; }
function route(base, name) { return base + '/' + encodeURIComponent(name); }
function toast(message, error = false) { const node = element('div', 'toast' + (error ? ' error' : ''), message); $('toast-container').append(node); window.setTimeout(() => node.remove(), error ? 7000 : 4500); }
function closeDialog(dialog) { dialog.close(); }
function showDialog(id) { if (!$(id).open) $(id).showModal(); }
function clearSecrets() { $('login-password').value = ''; $('host-form').elements.password.value = ''; $('user-form').elements.password.value = ''; $('token-result').value = ''; }
function closeAllConnections() { for (const id of [...state.terminals.keys()]) closeTerminal(id); stopLogs(false); }
function showLogin() { closeAllConnections(); state.session = null; state.settings = null; state.hosts = []; state.logText = ''; state.logPaused = false; renderLog(); clearSecrets(); for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close(); $('app-screen').hidden = true; $('login-screen').hidden = false; $('login-username').focus(); }

async function api(path, options = {}) {
  const method = options.method || 'GET';
  const headers = { Accept: 'application/json' };
  if (method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = state.session ? state.session.csrf : '';
  if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { method, headers, credentials: 'same-origin', body: options.body !== undefined ? JSON.stringify(options.body) : undefined, signal: options.signal });
  let body = null;
  try { body = await response.json(); } catch (_) { body = {}; }
  body = body || {};
  if (!response.ok || body.error) {
    if (response.status === 401 && path !== '/api/login') showLogin();
    const error = new Error(body.error && body.error.message ? body.error.message : '请求失败（' + response.status + '）');
    error.code = body.error ? body.error.code : 'request_failed';
    throw error;
  }
  return body;
}

async function withBusy(buttonNode, task) { const wasDisabled = buttonNode.disabled; buttonNode.disabled = true; try { return await task(); } catch (error) { toast(error.message, true); return null; } finally { buttonNode.disabled = wasDisabled; } }
function isAdmin() { return Boolean(state.session && state.session.user && state.session.user.admin); }
async function enterApp(session) { state.session = session; $('login-error').textContent = ''; $('login-password').value = ''; $('login-screen').hidden = true; $('app-screen').hidden = false; $('user-name').textContent = session.user.name; $('user-avatar').textContent = (session.user.name || 'U').slice(0, 1).toUpperCase(); $('user-role').textContent = session.user.admin ? '管理员' : '操作员'; for (const node of document.querySelectorAll('.admin-only')) node.hidden = !session.user.admin; if (state.view === 'settings' && !session.user.admin) state.view = 'overview'; await showView(state.view); }

async function showView(view) {
  if (!pageInfo[view] || view === 'settings' && !isAdmin()) return;
  state.view = view;
  for (const node of document.querySelectorAll('.view')) node.hidden = node.id !== 'view-' + view;
  for (const node of document.querySelectorAll('[data-view]')) node.classList.toggle('active', node.dataset.view === view);
  $('page-title').textContent = pageInfo[view][0]; $('page-subtitle').textContent = pageInfo[view][1];
  try {
    if (view === 'overview') await refreshHosts();
    if (view === 'audit') await loadAudit();
    if (view === 'settings') await loadSettings();
    if (view === 'terminal' || view === 'logs') { if (!state.hosts.length) await refreshHosts(); updateHostSelects(); }
    if (view === 'terminal') fitActiveTerminal();
  } catch (error) { toast(error.message, true); }
}

async function refreshHosts() {
  if (state.refreshing) return;
  state.refreshing = true;
  $('refresh-state').textContent = '正在更新…';
  try {
    const result = await api('/api/hosts');
    if (!state.session) return;
    state.hosts = result.hosts || [];
    renderHosts(); updateHostSelects();
    $('refresh-state').textContent = '更新于 ' + time(new Date().toISOString()).split(' ')[1];
  } finally { state.refreshing = false; }
}

function updateHostSelects() {
  for (const id of ['terminal-host', 'logs-host', 'audit-host']) {
    const select = $(id); const previous = select.value;
    select.replaceChildren();
    if (id === 'audit-host') { const option = element('option', '', '全部主机'); option.value = ''; select.append(option); }
    for (const host of state.hosts) { const option = element('option', '', hostName(host)); option.value = hostName(host); select.append(option); }
    if ([...select.options].some((option) => option.value === previous)) select.value = previous;
    select.disabled = !state.hosts.length && id !== 'audit-host';
  }
  $('terminal-open').disabled = !state.hosts.length;
  $('logs-connect').disabled = !state.hosts.length;
}

function metric(label, value, text) {
  const node = element('div', 'host-metric');
  const heading = element('div', 'metric-label'); const number = element('strong', '', text === undefined ? percent(value) : text);
  if (Number(value) > 85) number.className = Number(value) > 95 ? 'danger-text' : 'warning-text';
  heading.append(element('span', '', label), number); node.append(heading);
  const bar = element('div', 'metric-bar'); const fill = element('div', 'metric-bar-fill' + (Number(value) > 95 ? ' danger' : Number(value) > 85 ? ' warning' : ''));
  fill.style.setProperty('--meter', Math.min(100, Math.max(0, Number(value) || 0)) + '%'); bar.append(fill); node.append(bar); return node;
}

function renderHosts() {
  const all = state.hosts; const online = all.filter((host) => hostStatus(host).online);
  const cpu = online.map((host) => hostStatus(host).cpu_usage_percent).filter((value) => value !== null && value !== undefined && Number.isFinite(Number(value)));
  $('nav-host-count').textContent = all.length; $('summary-total').textContent = all.length; $('summary-online').textContent = online.length;
  $('summary-online-note').textContent = all.length ? online.length + ' / ' + all.length + ' 台主机可访问' : '等待添加主机';
  $('summary-alerts').textContent = all.filter(hostAlert).length; $('summary-cpu').textContent = cpu.length ? percent(cpu.reduce((sum, value) => sum + Number(value), 0) / cpu.length) : '—';
  const selectedTag = $('host-tag').value; const tags = [...new Set(all.flatMap((host) => host.tags || []))].sort();
  $('host-tag').replaceChildren(); const defaultTag = element('option', '', '全部标签'); defaultTag.value = ''; $('host-tag').append(defaultTag);
  for (const tag of tags) { const option = element('option', '', tag); option.value = tag; $('host-tag').append(option); }
  if (tags.includes(selectedTag)) $('host-tag').value = selectedTag;
  const query = $('host-search').value.trim().toLowerCase(); const tag = $('host-tag').value;
  const visible = all.filter((host) => (!tag || (host.tags || []).includes(tag)) && [hostName(host), host.address, host.description].join(' ').toLowerCase().includes(query));
  $('host-result-count').textContent = visible.length + ' 台'; $('host-grid').replaceChildren(); $('hosts-empty').hidden = all.length > 0;
  for (const host of visible) {
    const name = hostName(host); const s = hostStatus(host); const card = element('article', 'host-card');
    const main = element('div', 'host-card-main'); main.tabIndex = 0; main.setAttribute('role', 'button'); main.setAttribute('aria-label', '查看 ' + name + ' 的状态'); main.addEventListener('click', () => openDetail(name)); main.addEventListener('keydown', (event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDetail(name); } });
    const heading = element('div', 'host-card-heading'); const title = element('div'); title.append(element('h3', '', name), element('div', 'host-address', (host.address || '—') + ':' + (host.port || 22)));
    heading.append(title, badge(s.online ? '在线' : '离线', s.online ? 'online' : 'offline')); main.append(heading, element('p', 'host-description', host.description || s.os_version || '暂无描述'));
    const tagRow = element('div', 'tags'); for (const item of host.tags || []) tagRow.append(element('span', 'tag', item)); main.append(tagRow);
    const metrics = element('div', 'host-metrics'); metrics.append(metric('CPU', s.cpu_usage_percent), metric('内存', s.memory ? s.memory.used_percent : null), metric('磁盘最高', (s.disks || []).length ? highestDisk(s) : null), metric('负载 / 1 分钟', null, s.load && s.load.length ? Number(s.load[0]).toFixed(2) : '—')); main.append(metrics);
    const health = element('div', 'host-health-line'); const failures = (s.failed_services || []).length; const servicesKnown = s.failed_services_available === true; health.append(element('span', servicesKnown && failures ? 'danger-text' : '', servicesKnown ? (failures ? failures + ' 个异常服务' : '未发现异常服务') : '服务状态未提供'), element('span', '', s.online ? (s.ssh_latency_ms || 0) + ' ms · SSH' : 'SSH 不可达')); main.append(health);
    if (s.last_error) main.title = s.last_error;
    const footer = element('div', 'host-card-actions'); footer.append(element('span', '', time(s.last_success || s.collected_at)), button('终端 ↗', 'compact secondary', () => openTerminalFor(name)));
    card.append(main, footer); $('host-grid').append(card);
  }
  if (all.length && !visible.length) $('host-grid').append(element('div', 'table-empty', '没有符合搜索或标签条件的主机'));
}

function fact(label, value) { const node = element('div', 'detail-fact'); node.append(element('span', '', label), element('strong', '', value === null || value === undefined || value === '' ? '—' : value)); return node; }
function table(headers, rows) { const container = element('div', 'table-scroll'); const node = element('table'); const head = element('thead'); const headRow = element('tr'); for (const name of headers) headRow.append(element('th', '', name)); head.append(headRow); const body = element('tbody'); for (const values of rows) { const row = element('tr'); for (const value of values) row.append(element('td', '', value)); body.append(row); } node.append(head, body); container.append(node); return container; }
function section(title, content) { const node = element('section', 'detail-section'); node.append(element('h3', '', title), content); return node; }

async function openDetail(name, refresh = false) {
  state.detailHost = name; const host = state.hosts.find((item) => hostName(item) === name) || { name };
  $('detail-title').textContent = name; $('detail-address').textContent = host.address ? host.address + ':' + (host.port || 22) + ' · ' + (host.username || '') : '';
  $('detail-body').replaceChildren(element('p', 'muted', '正在读取主机状态…')); showDialog('detail-dialog');
  try {
    const s = await api(route('/api/hosts', name) + (refresh ? '?refresh=true' : ''));
    if (state.detailHost !== name || !$('detail-dialog').open) return;
    const body = $('detail-body'); body.replaceChildren();
    if (!s.online) body.append(element('div', 'notice error', '当前主机离线。' + (s.last_error || '请检查 SSH 连接。') + ' 最近成功采集：' + time(s.last_success)));
    if (s.partial) body.append(element('div', 'notice warning', '部分指标暂不可用：' + (s.warnings || []).join('；')));
    const facts = element('div', 'detail-facts'); facts.append(fact('系统 / 主机名', (s.os_version || '—') + ' · ' + (s.hostname || name)), fact('内核', s.kernel), fact('运行时长', uptime(s.uptime_seconds)), fact('CPU / 核数', percent(s.cpu_usage_percent) + ' · ' + (s.cpu_cores === null || s.cpu_cores === undefined ? '—' : s.cpu_cores) + ' 核'), fact('内存', s.memory ? bytes(s.memory.used_bytes) + ' / ' + bytes(s.memory.total_bytes) : '—'), fact('Swap', s.swap ? bytes(s.swap.used_bytes) + ' / ' + bytes(s.swap.total_bytes) : '—'), fact('负载 / 1、5、15 分钟', (s.load || []).map((value) => Number(value).toFixed(2)).join(' / ') || '—'), fact('SSH 延迟', s.ssh_latency_ms === null || s.ssh_latency_ms === undefined ? '—' : s.ssh_latency_ms + ' ms'), fact('最近采集', time(s.collected_at))); body.append(facts);
    body.append(section('挂载磁盘', (s.disks || []).length ? table(['挂载点', '类型', '已用 / 总量', '使用率'], s.disks.map((disk) => [disk.mountpoint, disk.type, bytes(disk.used_bytes) + ' / ' + bytes(disk.total_bytes), percent(disk.used_percent)])) : element('p', 'muted small', '暂无磁盘数据')));
    const failed = element('ul', 'failed-services'); for (const service of s.failed_services || []) failed.append(element('li', '', service)); body.append(section('失败的 systemd 服务', s.failed_services_available !== true ? element('p', 'muted small', '服务器未提供 systemd 服务状态') : failed.childNodes.length ? failed : element('p', 'muted small', '未发现失败服务')));
    const processes = element('div', 'detail-processes'); for (const [key, title] of [['top_cpu', 'CPU 占用前 5'], ['top_memory', '内存占用前 5']]) { const items = s[key] || []; processes.append(section(title, items.length ? table(['PID', '进程', 'CPU', '内存'], items.map((process) => [process.pid, process.command, percent(process.cpu_percent), percent(process.memory_percent)])) : element('p', 'muted small', '暂无进程数据'))); } body.append(processes);
  } catch (error) { $('detail-body').replaceChildren(element('div', 'notice error', error.message)); }
}

function websocketURL(path, params) { const url = new URL(path, window.location.href); url.protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'; for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== null && value !== '') url.searchParams.set(key, String(value)); return url.href; }
function terminalTheme() { return { background: '#101715', foreground: '#c9dcd1', cursor: '#78e2c0', selectionBackground: '#2b5545', black: '#111916', brightBlack: '#52675b', green: '#78e2c0', brightGreen: '#a5efcf', red: '#f28d86', brightRed: '#ffc0b5', yellow: '#edbb68', brightYellow: '#f5db9c', blue: '#83b6dc', brightBlue: '#b7d8ef', magenta: '#c7a8df', brightMagenta: '#dec8ee', cyan: '#8bcec6', brightCyan: '#a8e9e1', white: '#c9dcd1', brightWhite: '#eef5ef' }; }
function fitActiveTerminal() { const session = state.terminals.get(state.activeTerminal); if (!session || state.view !== 'terminal') return; requestAnimationFrame(() => { try { session.fit.fit(); if (session.socket.readyState === WebSocket.OPEN) session.socket.send(JSON.stringify({ type: 'resize', cols: session.term.cols, rows: session.term.rows })); } catch (_) { /* The pane can be hidden during a view change. */ } }); }
function selectTerminal(id) { state.activeTerminal = id; for (const [key, session] of state.terminals) { session.pane.hidden = key !== id; session.tab.classList.toggle('active', key === id); session.tab.setAttribute('aria-selected', String(key === id)); } fitActiveTerminal(); const active = state.terminals.get(id); if (active) active.term.focus(); }
function closeTerminal(id) { const session = state.terminals.get(id); if (!session) return; session.socket.close(); session.term.dispose(); session.pane.remove(); session.tab.remove(); state.terminals.delete(id); if (state.activeTerminal === id) selectTerminal([...state.terminals.keys()].at(-1) || null); $('terminal-empty').hidden = state.terminals.size > 0; $('terminal-count').textContent = state.terminals.size + ' 个会话'; }
async function openTerminalFor(name) { await showView('terminal'); $('terminal-host').value = name; createTerminal(name); }

function createTerminal(name) {
  if (!name || !state.session) return;
  if (state.terminals.size >= 16) { toast('请先关闭部分终端；最多同时打开 16 个标签。', true); return; }
  const id = 'terminal-' + (++state.terminalSequence); const pane = element('div', 'terminal-pane'); const tab = element('div', 'terminal-tab'); tab.setAttribute('role', 'tab'); tab.tabIndex = 0;
  const dot = element('span', 'status-dot neutral'); tab.append(dot, element('span', '', name)); const close = element('button', 'icon-button', '×'); close.type = 'button'; close.setAttribute('aria-label', '关闭 ' + name + ' 终端'); close.addEventListener('click', (event) => { event.stopPropagation(); closeTerminal(id); }); tab.append(close); tab.addEventListener('click', () => selectTerminal(id)); tab.addEventListener('keydown', (event) => { if (event.key === 'Enter') selectTerminal(id); }); $('terminal-tabs').append(tab); $('terminal-panes').append(pane); $('terminal-empty').hidden = true;
  const term = new Terminal({ cursorBlink: true, fontSize: 13, fontFamily: 'SFMono-Regular, Consolas, "Liberation Mono", monospace', theme: terminalTheme(), scrollback: 5000, convertEol: false }); const fit = new FitAddon.FitAddon(); term.loadAddon(fit); term.open(pane); fit.fit();
  const socket = new WebSocket(websocketURL('/ws/terminal', { host: name, csrf: state.session.csrf, cols: term.cols, rows: term.rows })); socket.binaryType = 'arraybuffer';
  const session = { id, name, pane, tab, term, fit, socket }; state.terminals.set(id, session); selectTerminal(id); $('terminal-count').textContent = state.terminals.size + ' 个会话';
  term.onData((data) => { if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'input', data })); });
  socket.addEventListener('open', () => { dot.className = 'status-dot'; term.focus(); fitActiveTerminal(); });
  socket.addEventListener('message', (event) => { if (typeof event.data === 'string') { try { const message = JSON.parse(event.data); if (message.type === 'error') term.writeln('\r\n\x1b[31m' + (message.error.message || '终端连接失败') + '\x1b[0m'); } catch (_) { term.write(event.data); } } else term.write(new Uint8Array(event.data)); });
  socket.addEventListener('close', () => { if (!state.terminals.has(id)) return; dot.className = 'status-dot offline'; term.writeln('\r\n\x1b[90m[会话已结束；关闭标签后可重新连接]\x1b[0m'); });
  socket.addEventListener('error', () => { if (state.terminals.has(id)) toast(name + ' 终端连接失败，请检查登录状态与主机连通性。', true); });
}

function stopLogs(showStatus = true) { if (state.logSocket) { const socket = state.logSocket; state.logSocket = null; socket.close(); } $('logs-stop').disabled = true; $('logs-pause').disabled = true; if (showStatus) { $('logs-status').textContent = '跟踪已停止'; $('logs-dot').className = 'status-dot neutral'; } }
function appendLog(text) { state.logText += text; if (state.logText.length > 1048576) state.logText = state.logText.slice(-1048576); const lines = state.logText.split('\n'); if (lines.length > 2000) state.logText = lines.slice(-2000).join('\n'); if (!state.logPaused && !state.logScheduled) { state.logScheduled = true; requestAnimationFrame(() => { state.logScheduled = false; renderLog(); }); } }
function renderLog() {
  const output = $('logs-output'); const nearEnd = output.scrollHeight - output.scrollTop - output.clientHeight < 70; const keyword = $('logs-highlight').value; output.replaceChildren();
  if (!keyword) output.textContent = state.logText;
  else { let start = 0; const haystack = state.logText.toLocaleLowerCase(); const needle = keyword.toLocaleLowerCase(); let index = haystack.indexOf(needle); let matches = 0; while (index !== -1 && matches < 3000) { output.append(document.createTextNode(state.logText.slice(start, index)), element('mark', '', state.logText.slice(index, index + keyword.length))); start = index + keyword.length; index = haystack.indexOf(needle, start); matches++; } output.append(document.createTextNode(state.logText.slice(start))); }
  $('logs-lines').textContent = (state.logText ? state.logText.split('\n').length : 0) + ' 行'; if (nearEnd || !output.scrollTop) output.scrollTop = output.scrollHeight;
}
function startLogs() {
  const host = $('logs-host').value; const target = $('logs-target').value.trim(); if (!host || !target || !state.session) return;
  stopLogs(false); state.logPaused = false; state.logText = ''; renderLog(); $('logs-pause').textContent = '暂停'; $('logs-status').textContent = '正在连接…'; $('logs-dot').className = 'status-dot neutral';
  const params = { host, csrf: state.session.csrf, grep: $('logs-grep').value, ignore_case: $('logs-ignore-case').checked };
  params[$('logs-mode').value] = target;
  const socket = new WebSocket(websocketURL('/ws/logs', params)); socket.binaryType = 'arraybuffer'; state.logSocket = socket; const streamDecoder = new TextDecoder();
  socket.addEventListener('open', () => { if (state.logSocket !== socket) return; $('logs-status').textContent = '实时跟踪 · ' + host; $('logs-dot').className = 'status-dot'; $('logs-stop').disabled = false; $('logs-pause').disabled = false; });
  socket.addEventListener('message', (event) => { if (state.logSocket !== socket) return; if (typeof event.data === 'string') { try { const message = JSON.parse(event.data); if (message.type === 'error') { appendLog('\n[错误] ' + message.error.message + '\n'); toast(message.error.message, true); } } catch (_) { appendLog(event.data); } } else appendLog(streamDecoder.decode(event.data, { stream: true })); });
  socket.addEventListener('close', () => { if (state.logSocket !== socket) return; appendLog(streamDecoder.decode()); state.logSocket = null; $('logs-status').textContent = '跟踪已结束'; $('logs-dot').className = 'status-dot neutral'; $('logs-stop').disabled = true; $('logs-pause').disabled = true; });
  socket.addEventListener('error', () => { if (state.logSocket === socket) toast('日志连接失败，请检查主机、路径和登录状态。', true); });
}

function auditSource(source) { return source === 'mcp' ? ['AI / MCP', 'ai'] : source === 'terminal' ? ['终端', ''] : ['网页', '']; }
function auditStatus(event) { if (event.error) return ['失败', 'error']; if (event.action.endsWith('.started') || event.action.endsWith('.start')) return ['已开始', '']; if (event.exit_code !== null && event.exit_code !== undefined) return event.exit_code === 0 ? ['成功 · 0', 'online'] : ['退出 · ' + event.exit_code, 'warning']; return ['已记录', '']; }
async function loadAudit() {
  const params = new URLSearchParams({ limit: state.auditLimit, offset: state.auditOffset });
  for (const field of ['source', 'host', 'actor', 'keyword']) if ($('audit-' + field).value) params.set(field, $('audit-' + field).value);
  for (const field of ['since', 'until']) if ($('audit-' + field).value) params.set(field, new Date($('audit-' + field).value + '+08:00').toISOString());
  const result = await api('/api/audit?' + params); const events = result.events || []; state.auditTotal = Number(result.total) || 0; $('audit-rows').replaceChildren(); $('audit-empty').hidden = events.length > 0;
  for (const event of events) { const row = element('tr'); row.append(element('td', '', time(event.ts))); const actor = element('td'); const [sourceLabel, sourceKind] = auditSource(event.source); actor.append(badge(sourceLabel, sourceKind), element('span', 'actor-name', event.actor)); row.append(actor, element('td', '', event.host || '网关')); const action = element('td'); action.append(element('strong', '', event.action), element('span', 'command-preview', event.command || '—')); row.append(action); const resultCell = element('td'); const [resultLabel, resultKind] = auditStatus(event); resultCell.append(badge(resultLabel, resultKind)); row.append(resultCell, element('td', 'muted', event.duration_ms + ' ms')); const more = element('td'); more.append(button('详情 ↗', 'compact secondary', () => showAudit(event))); row.append(more); $('audit-rows').append(row); }
  $('audit-total').textContent = state.auditTotal + ' 条记录'; $('audit-page').textContent = Math.floor(state.auditOffset / state.auditLimit) + 1; $('audit-prev').disabled = state.auditOffset === 0; $('audit-next').disabled = state.auditOffset + state.auditLimit >= state.auditTotal;
}
function showAudit(event) { const content = $('audit-detail'); content.replaceChildren(); const facts = element('div', 'detail-facts'); facts.append(fact('时间', time(event.ts)), fact('来源 / 使用者', auditSource(event.source)[0] + ' · ' + event.actor), fact('客户端 IP', event.client_ip), fact('主机 / 操作', (event.host || '网关') + ' · ' + event.action), fact('退出码 / 耗时', (event.exit_code === null ? '—' : event.exit_code) + ' / ' + event.duration_ms + ' ms'), fact('原始输出大小', bytes(event.output_bytes))); content.append(facts, section('执行命令', element('pre', 'code-box', event.command || '此操作无远端命令'))); if (event.error) content.append(element('div', 'notice error', event.error)); content.append(section('输出摘要', element('pre', 'code-box', event.output_excerpt || '无输出摘要'))); showDialog('audit-dialog'); }

async function loadSettings() { if (!isAdmin()) return; state.settings = await api('/api/settings'); renderSettings(); }
function settingView(name) { state.setting = name; for (const node of document.querySelectorAll('.settings-section')) node.hidden = node.id !== 'setting-' + name; for (const node of document.querySelectorAll('[data-setting]')) node.classList.toggle('active', node.dataset.setting === name); }
function renderSettings() {
  const settings = state.settings || {}; const hosts = settings.hosts || []; const tokens = settings.tokens || []; const users = settings.users || [];
  $('settings-host-rows').replaceChildren(); $('settings-token-rows').replaceChildren(); $('settings-user-rows').replaceChildren(); $('settings-key-list').replaceChildren(); $('settings-host-empty').hidden = hosts.length > 0; $('settings-token-empty').hidden = tokens.length > 0;
  for (const host of hosts) { const row = element('tr'); const title = element('td'); title.append(element('strong', '', host.name), element('div', 'muted small', host.description)); row.append(title, element('td', 'host-address', host.address + ':' + host.port), element('td', '', host.username)); const tags = element('td'); const tagRow = element('div', 'tags'); for (const tag of host.tags || []) tagRow.append(element('span', 'tag', tag)); tags.append(tagRow); row.append(tags); const actions = element('td'); const group = element('div', 'row-actions'); group.append(button('测试', 'compact secondary', () => testHost(host.name)), button('编辑', 'compact secondary', () => editHost(host)), button('删除', 'compact danger', () => removeHost(host.name))); actions.append(group); row.append(actions); $('settings-host-rows').append(row); }
  for (const token of tokens) { const row = element('tr'); row.append(element('td', '', token.name), element('td', 'muted', 'MCP · Bearer Token')); const actions = element('td'); actions.append(button('撤销', 'compact danger', () => revokeToken(token.name))); row.append(actions); $('settings-token-rows').append(row); }
  for (const user of users) { const row = element('tr'); row.append(element('td', '', user.name), element('td', '', user.admin ? '管理员' : '操作员'), element('td', 'muted', time(user.created_at))); const actions = element('td'); const group = element('div', 'row-actions'); group.append(button('修改密码', 'compact secondary', () => editUser(user)), button('删除', 'compact danger', () => removeUser(user.name))); actions.append(group); row.append(actions); $('settings-user-rows').append(row); }
  const keys = settings.host_keys || [];
  for (const host of hosts) { const key = keys.find((item) => item.host === host.name); const card = element('article', 'key-card' + (key && key.changed ? ' changed' : '')); const info = element('div'); info.append(element('h3', '', host.name + (key && key.changed ? ' · 指纹已变化' : ''))); if (key) { info.append(element('p', '', key.address), element('code', '', '当前呈现：' + (key.fingerprint || '—'))); if (key.previous_fingerprint) info.append(element('code', '', '原先信任：' + key.previous_fingerprint)); info.append(element('p', '', '最近看到：' + time(key.last_seen))); } else info.append(element('p', '', '尚无指纹记录；完成首次连接测试后会自动记录。')); card.append(info, key && key.changed ? button('核对并确认更新', 'danger', () => confirmKey(host.name, key.fingerprint)) : button('测试连接', 'secondary', () => testHost(host.name))); $('settings-key-list').append(card); }
  if (!hosts.length) $('settings-key-list').append(element('div', 'table-empty', '添加主机后可查看 SSH 指纹'));
  const server = settings.server || {}; $('settings-server-note').textContent = '监听地址：' + (server.listen || '—') + ' · 允许来源：' + (server.allowed_cidrs || []).join('、') + ' · HTTPS：' + (server.tls && server.tls.enabled ? '已启用' : '未启用') + '。监听地址与 TLS 参数请在配置文件中修改后重启服务。'; settingView(state.setting);
}

function editHost(host = null) { state.hostEdit = host ? host.name : ''; const form = $('host-form'); form.reset(); form.elements.name.value = host ? host.name : ''; form.elements.name.disabled = Boolean(host); form.elements.address.value = host ? host.address : ''; form.elements.port.value = host ? host.port : 22; form.elements.username.value = host ? host.username : ''; form.elements.tags.value = host ? (host.tags || []).join(', ') : ''; form.elements.description.value = host ? host.description || '' : ''; form.elements.sudo_password_inject.checked = Boolean(host && host.sudo_password_inject); form.elements.password.required = !host; $('host-dialog-title').textContent = host ? '编辑主机 · ' + host.name : '添加主机'; $('host-password-label').textContent = host ? 'SSH 密码（留空则保留）' : 'SSH 密码'; showDialog('host-dialog'); }
async function saveHost(event) { event.preventDefault(); const form = $('host-form'); await withBusy(form.querySelector('[type=submit]'), async () => { const body = { name: state.hostEdit || form.elements.name.value.trim(), address: form.elements.address.value.trim(), port: Number(form.elements.port.value), username: form.elements.username.value.trim(), sudo_password_inject: form.elements.sudo_password_inject.checked, tags: form.elements.tags.value.split(',').map((tag) => tag.trim()).filter(Boolean), description: form.elements.description.value.trim() }; if (form.elements.password.value) body.password = form.elements.password.value; await api(state.hostEdit ? route('/api/hosts', state.hostEdit) : '/api/hosts', { method: state.hostEdit ? 'PUT' : 'POST', body }); form.elements.password.value = ''; closeDialog($('host-dialog')); toast('主机已保存，连接配置自动生效。'); await Promise.all([loadSettings(), refreshHosts()]); }); }
async function testHost(name) { try { const result = await api(route('/api/hosts', name) + '/test', { method: 'POST', body: {} }); toast(name + ' 连接成功 · ' + result.latency_ms + ' ms'); $('audit-detail').replaceChildren(section('连通性测试 · ' + name, element('pre', 'code-box', JSON.stringify(result, null, 2)))); showDialog('audit-dialog'); await loadSettings(); } catch (error) { toast(name + '：' + error.message, true); await loadSettings().catch(() => {}); } }
function confirmAction(title, message, detail = '') { if (confirmResolve) confirmResolve(false); $('confirm-title').textContent = title; $('confirm-message').textContent = message; $('confirm-detail').textContent = detail; $('confirm-detail').hidden = !detail; showDialog('confirm-dialog'); return new Promise((resolve) => { confirmResolve = resolve; }); }
async function removeHost(name) { if (!await confirmAction('删除主机', '删除 ' + name + ' 后，网关将断开其 SSH 连接，相关终端会话也会结束。历史审计记录会保留。')) return; try { await api(route('/api/hosts', name), { method: 'DELETE' }); toast('主机已删除。'); await Promise.all([loadSettings(), refreshHosts()]); } catch (error) { toast(error.message, true); } }
async function confirmKey(name, fingerprint) { if (!fingerprint) { toast('尚未获取服务器呈现的指纹，请先测试连接。', true); return; } if (!await confirmAction('确认更新 SSH 指纹', '先通过可信途径核对服务器身份。确认后，' + name + ' 将信任下方指纹并替换原记录。', fingerprint)) return; try { await api(route('/api/hosts', name) + '/key-confirm', { method: 'POST', body: { fingerprint } }); toast('主机指纹已更新。'); await loadSettings(); } catch (error) { toast(error.message, true); } }
async function revokeToken(name) { if (!await confirmAction('撤销 MCP Token', '撤销 ' + name + ' 后，使用此 Token 的 AI 工具将立即失去网关访问权限。')) return; try { await api(route('/api/tokens', name), { method: 'DELETE' }); toast('Token 已撤销。'); await loadSettings(); } catch (error) { toast(error.message, true); } }
function editUser(user = null) { state.userEdit = user ? user.name : ''; const form = $('user-form'); form.reset(); form.elements.name.value = user ? user.name : ''; form.elements.name.disabled = Boolean(user); $('user-name-label').hidden = Boolean(user); $('user-admin-label').hidden = Boolean(user); $('user-dialog-title').textContent = user ? '修改密码 · ' + user.name : '添加用户'; showDialog('user-dialog'); }
async function removeUser(name) { if (!await confirmAction('删除网页用户', '删除 ' + name + ' 后，该用户的现有登录会话会失效。此操作不能删除最后一位管理员。')) return; try { await api(route('/api/users', name), { method: 'DELETE' }); toast('用户已删除。'); await loadSettings(); } catch (error) { toast(error.message, true); } }

function applyTheme(theme) { const safe = theme === 'light' ? 'light' : 'dark'; document.documentElement.dataset.theme = safe; $('theme-button').textContent = safe === 'dark' ? '☼ 切换浅色模式' : '☾ 切换深色模式'; try { localStorage.setItem('tailgate-theme', safe); } catch (_) { /* Storage may be disabled by the browser. */ } }
function bindEvents() {
  for (const node of document.querySelectorAll('[data-view]')) node.addEventListener('click', () => showView(node.dataset.view));
  for (const node of document.querySelectorAll('[data-setting]')) node.addEventListener('click', () => settingView(node.dataset.setting));
  for (const node of document.querySelectorAll('[data-go-settings]')) node.addEventListener('click', async () => { state.setting = node.dataset.goSettings; await showView('settings'); editHost(); });
  for (const node of document.querySelectorAll('[data-close-dialog]')) node.addEventListener('click', () => closeDialog(node.closest('dialog')));
  $('token-result-dialog').addEventListener('close', () => { $('token-result').value = ''; });
  $('host-dialog').addEventListener('close', () => { $('host-form').elements.password.value = ''; });
  $('user-dialog').addEventListener('close', () => { $('user-form').elements.password.value = ''; });
  $('confirm-dialog').addEventListener('close', () => { if (confirmResolve) { confirmResolve(false); confirmResolve = null; } });
  $('confirm-cancel').addEventListener('click', () => $('confirm-dialog').close());
  $('confirm-ok').addEventListener('click', () => { const resolve = confirmResolve; confirmResolve = null; $('confirm-dialog').close(); if (resolve) resolve(true); });
  $('login-form').addEventListener('submit', async (event) => { event.preventDefault(); const submit = event.currentTarget.querySelector('[type=submit]'); submit.disabled = true; $('login-error').textContent = ''; try { const session = await api('/api/login', { method: 'POST', body: { username: $('login-username').value.trim(), password: $('login-password').value } }); await enterApp(session); } catch (error) { $('login-error').textContent = error.message; } finally { $('login-password').value = ''; submit.disabled = false; } });
  $('logout-button').addEventListener('click', async () => { try { await api('/api/logout', { method: 'POST', body: {} }); } catch (error) { toast(error.message, true); } finally { showLogin(); } });
  $('theme-button').addEventListener('click', () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
  $('compact-theme').addEventListener('click', () => $('theme-button').click());
  $('compact-logout').addEventListener('click', () => $('logout-button').click());
  $('refresh-button').addEventListener('click', () => withBusy($('refresh-button'), async () => { if (state.view === 'settings') await loadSettings(); else if (state.view === 'audit') await loadAudit(); else await refreshHosts(); }));
  $('host-search').addEventListener('input', renderHosts); $('host-tag').addEventListener('change', renderHosts);
  $('overview-add-host').addEventListener('click', async () => { state.setting = 'hosts'; await showView('settings'); editHost(); });
  $('settings-add-host').addEventListener('click', () => editHost()); $('host-form').addEventListener('submit', saveHost);
  $('detail-refresh').addEventListener('click', () => withBusy($('detail-refresh'), () => openDetail(state.detailHost, true)));
  $('detail-terminal').addEventListener('click', () => { $('detail-dialog').close(); openTerminalFor(state.detailHost); });
  $('detail-logs').addEventListener('click', async () => { $('detail-dialog').close(); await showView('logs'); $('logs-host').value = state.detailHost; });
  $('terminal-open').addEventListener('click', () => createTerminal($('terminal-host').value));
  $('logs-form').addEventListener('submit', (event) => { event.preventDefault(); startLogs(); });
  $('logs-mode').addEventListener('change', () => { const unit = $('logs-mode').value === 'unit'; $('logs-target-label').textContent = unit ? 'systemd unit' : '文件路径'; $('logs-target').value = unit ? 'nginx.service' : '/var/log/syslog'; $('logs-target').placeholder = unit ? 'nginx.service' : '/var/log/syslog'; if (unit) $('logs-target').removeAttribute('list'); else $('logs-target').setAttribute('list', 'log-paths'); });
  $('logs-stop').addEventListener('click', () => stopLogs()); $('logs-clear').addEventListener('click', () => { state.logText = ''; renderLog(); }); $('logs-highlight').addEventListener('input', renderLog);
  $('logs-pause').addEventListener('click', () => { state.logPaused = !state.logPaused; $('logs-pause').textContent = state.logPaused ? '继续' : '暂停'; $('logs-buffer-note').textContent = state.logPaused ? '显示已暂停，后台仍接收日志；最多缓存最近 2,000 行 / 1 MiB。' : '最多保留最近 2,000 行 / 1 MiB，避免长时间跟踪占用过多内存'; if (!state.logPaused) renderLog(); });
  $('audit-form').addEventListener('submit', (event) => { event.preventDefault(); state.auditOffset = 0; loadAudit().catch((error) => toast(error.message, true)); });
  $('audit-ai-only').addEventListener('click', () => { $('audit-source').value = 'mcp'; state.auditOffset = 0; loadAudit().catch((error) => toast(error.message, true)); });
  $('audit-prev').addEventListener('click', () => { state.auditOffset = Math.max(0, state.auditOffset - state.auditLimit); loadAudit().catch((error) => toast(error.message, true)); });
  $('audit-next').addEventListener('click', () => { state.auditOffset += state.auditLimit; loadAudit().catch((error) => toast(error.message, true)); });
  $('settings-add-token').addEventListener('click', () => { $('token-form').reset(); showDialog('token-dialog'); });
  $('token-form').addEventListener('submit', async (event) => { event.preventDefault(); const form = event.currentTarget; await withBusy(form.querySelector('[type=submit]'), async () => { const result = await api('/api/tokens', { method: 'POST', body: { name: form.elements.name.value.trim() } }); $('token-dialog').close(); $('token-result').value = result.token; $('token-result-label').firstChild.textContent = result.name + ' · Token'; showDialog('token-result-dialog'); await loadSettings(); }); });
  $('token-copy').addEventListener('click', async () => { try { if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText($('token-result').value); else { $('token-result').select(); if (!document.execCommand('copy')) throw new Error('请选中 Token 后手动复制。'); } toast('Token 已复制。'); } catch (error) { $('token-result').select(); toast(error.message, true); } });
  $('settings-add-user').addEventListener('click', () => editUser());
  $('user-form').addEventListener('submit', async (event) => { event.preventDefault(); const form = event.currentTarget; await withBusy(form.querySelector('[type=submit]'), async () => { const body = state.userEdit ? { password: form.elements.password.value } : { name: form.elements.name.value.trim(), password: form.elements.password.value, admin: form.elements.admin.checked }; const path = state.userEdit ? route('/api/users', state.userEdit) + '/password' : '/api/users'; await api(path, { method: 'POST', body }); form.elements.password.value = ''; $('user-dialog').close(); toast('用户信息已保存。'); await loadSettings(); }); });
  window.addEventListener('resize', fitActiveTerminal);
  if (typeof ResizeObserver !== 'undefined') new ResizeObserver(fitActiveTerminal).observe($('terminal-panes'));
  window.addEventListener('beforeunload', closeAllConnections);
  window.setInterval(() => { if (state.session && state.view === 'overview' && !document.hidden) refreshHosts().catch((error) => { $('refresh-state').textContent = '更新失败'; if (error.code !== 'unauthorized') console.warn('Host refresh failed'); }); }, 15000);
}

async function initialize() { let theme = 'dark'; try { theme = localStorage.getItem('tailgate-theme') || 'dark'; } catch (_) { /* Use the default when storage is unavailable. */ } applyTheme(theme); bindEvents(); try { const session = await api('/api/session'); await enterApp(session); } catch (_) { showLogin(); } }
initialize();
