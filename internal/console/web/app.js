'use strict';
const $ = (id) => document.getElementById(id);
const elements = {
  status: $('connection-status'), fields: $('policy-fields'), input: $('domain-input'),
  list: $('domain-list'), cookies: $('strip-cookies'), save: $('save'), discard: $('discard'),
};
let saved = null;
let draft = { denyDomains: [], stripRequestCookies: false };
let online = false;
let saving = false;
let epoch = 0;
let refreshTimer;
let refreshing = false;
const clone = (policy) => ({ denyDomains: [...policy.denyDomains], stripRequestCookies: policy.stripRequestCookies });
const dirty = () => saved !== null && JSON.stringify(draft) !== JSON.stringify(saved);
const number = (value) => new Intl.NumberFormat().format(value);
const text = (id, value) => { $(id).textContent = value; };

function updateActions() {
  elements.fields.disabled = !online || saving || saved === null;
  elements.save.disabled = !online || saving || !dirty();
  elements.discard.disabled = !online || saving || !dirty();
  elements.save.textContent = saving ? 'Saving…' : 'Save changes';
  text('dirty-note', dirty() ? 'You have unsaved changes.' : 'Changes apply to new requests.');
}
function renderPolicy() {
  elements.cookies.checked = draft.stripRequestCookies;
  elements.list.replaceChildren();
  for (const domain of draft.denyDomains) {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.textContent = domain;
    const remove = document.createElement('button');
    remove.type = 'button'; remove.className = 'remove-rule'; remove.textContent = '×';
    remove.setAttribute('aria-label', `Remove ${domain}`);
    remove.addEventListener('click', () => {
      draft.denyDomains = draft.denyDomains.filter((rule) => rule !== domain);
      clearMessage(); renderPolicy(); elements.input.focus();
    });
    row.append(name, remove); elements.list.append(row);
  }
  $('empty-rules').hidden = draft.denyDomains.length !== 0;
  text('rule-count', `${draft.denyDomains.length} ${draft.denyDomains.length === 1 ? 'rule' : 'rules'}`);
  updateActions();
}
function clearMessage() { $('save-message').hidden = true; }
function message(value, error = false) {
  text('save-message', value); $('save-message').classList.toggle('error', error); $('save-message').hidden = false;
}
function domainError(value) {
  text('domain-error', value); $('domain-error').hidden = !value;
  elements.input.setAttribute('aria-invalid', value ? 'true' : 'false');
}
function validDomain(value) {
  if (!value || value.length > 253) return false;
  if (value.includes(':')) {
    try { return new URL(`http://[${value}]/`).hostname.startsWith('['); } catch { return false; }
  }
  return value.split('.').every((label) => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}
function addDomain() {
  const value = elements.input.value.trim().toLowerCase().replace(/\.$/, '');
  if (!validDomain(value)) { domainError('Enter a valid hostname or IP address, without a URL or wildcard.'); elements.input.focus(); return; }
  if (draft.denyDomains.includes(value)) { domainError('This domain is already in your rules.'); return; }
  if (draft.denyDomains.length >= 1000) { domainError('Use at most 1,000 domain rules.'); return; }
  draft.denyDomains.push(value); elements.input.value = ''; domainError(''); clearMessage(); renderPolicy(); elements.input.focus();
}
$('add-domain').addEventListener('click', addDomain);
elements.input.addEventListener('keydown', (event) => { if (event.key === 'Enter') { event.preventDefault(); addDomain(); } });
elements.input.addEventListener('input', () => domainError(''));
elements.cookies.addEventListener('change', () => { draft.stripRequestCookies = elements.cookies.checked; clearMessage(); updateActions(); });
elements.discard.addEventListener('click', () => { draft = clone(saved); domainError(''); elements.input.value = ''; clearMessage(); renderPolicy(); });

$('policy-form').addEventListener('submit', async (event) => {
  event.preventDefault(); if (!online || saving || !dirty()) return;
  if (elements.input.value.trim()) { domainError('Add this domain or clear the input before saving.'); elements.input.focus(); return; }
  saving = true; epoch++; clearMessage(); updateActions();
  try {
    const response = await fetch('/api/policy', {
      method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-NaviScope-Token': document.querySelector('meta[name="nscope-token"]').content },
      body: JSON.stringify(draft), signal: AbortSignal.timeout(5000), cache: 'no-store',
    });
    if (!response.ok) throw new Error((await response.text()).trim());
    saved = await response.json(); draft = clone(saved); renderPolicy(); message('Changes saved. New requests use these rules.');
  } catch (error) {
    message(`Changes were not saved. ${error.name === 'TimeoutError' || error instanceof TypeError ? 'Check the connection and try again.' : error.message}`, true);
  } finally { saving = false; epoch++; updateActions(); }
});

function uptime(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
}
function renderState(state, loadEpoch) {
  online = state.stats.running;
  elements.status.textContent = online ? 'Proxy ready' : 'Proxy stopping';
  elements.status.className = online ? 'status ready' : 'status offline';
  $('connection-error').hidden = online;
  text('route-state', online ? 'Listening on loopback' : 'Not listening');
  text('listen-badge', state.config.listenAddress); text('proxy-address', state.config.listenAddress);
  $('copy-address').disabled = false;
  text('uptime', uptime(state.stats.uptimeSeconds));
  text('http-count', number(state.stats.httpRequests)); text('connect-count', number(state.stats.connectRequests));
  text('blocked-count', number(state.stats.blocked)); text('active-count', number(state.stats.activeHTTP + state.stats.activeTunnels));
  text('activity-note', `${number(state.stats.activeHTTP)} active HTTP requests · ${number(state.stats.activeTunnels)} open HTTPS tunnels`);
  text('updated', `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`);
  text('connect-ports', state.config.connectPorts.join(', ')); text('http-timeout', state.config.requestTimeout);
  text('tunnel-timeout', state.config.tunnelTimeout); text('error-count', number(state.stats.upstreamErrors));
  if (loadEpoch === epoch && !saving && !dirty() && (saved === null || JSON.stringify(state.policy) !== JSON.stringify(saved))) { saved = clone(state.policy); draft = clone(saved); renderPolicy(); }
  updateActions();
}
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  clearTimeout(refreshTimer); const loadEpoch = epoch;
  try {
    const response = await fetch('/api/state', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error('Status unavailable');
    renderState(await response.json(), loadEpoch);
  } catch {
    online = false; elements.status.textContent = 'Connection lost'; elements.status.className = 'status offline';
    $('connection-error').hidden = false; text('route-state', 'Connection unavailable'); text('updated', 'Connection lost · values may be out of date'); updateActions();
  } finally { refreshing = false; refreshTimer = setTimeout(refresh, 2000); }
}
$('retry').addEventListener('click', refresh);
$('copy-address').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('proxy-address').textContent); text('copy-message', 'Proxy address copied.'); }
  catch { text('copy-message', 'Select the address above and copy it manually.'); }
});
window.addEventListener('beforeunload', (event) => { if (dirty()) { event.preventDefault(); event.returnValue = ''; } });
document.querySelectorAll('.nav-link').forEach((link) => {
  link.addEventListener('click', () => {
    document.querySelectorAll('.nav-link').forEach((item) => item.removeAttribute('aria-current'));
    link.setAttribute('aria-current', 'location');
  });
});
refresh();
