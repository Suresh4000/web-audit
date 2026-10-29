const form = document.querySelector('#audit-form');
const input = document.querySelector('#url-input');
const button = document.querySelector('#audit-button');
const statusPanel = document.querySelector('#status-panel');
const statusTitle = document.querySelector('#status-title');
const statusBadge = document.querySelector('#status-badge');
const statusMessage = document.querySelector('#status-message');
const progressBar = document.querySelector('#progress-bar');
const results = document.querySelector('#results');
const jsonButton = document.querySelector('#download-json');
let latestResult = null;

function setStatus(title, badge, message, progress) {
  statusPanel.hidden = false;
  statusTitle.textContent = title;
  statusBadge.textContent = badge;
  statusMessage.textContent = message;
  progressBar.style.width = `${progress}%`;
}
function setText(id, value) { document.getElementById(id).textContent = value ?? 'Not found'; }
function formatBytes(bytes) { return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`; }
function renderFindings(findings) {
  const list = document.querySelector('#findings-list');
  list.replaceChildren();
  document.querySelector('#finding-count').textContent = `${findings.length} item${findings.length === 1 ? '' : 's'}`;
  if (!findings.length) {
    const empty = document.createElement('div'); empty.className = 'empty-findings'; empty.textContent = 'No findings returned for the checks performed.'; list.append(empty); return;
  }
  for (const finding of findings) {
    const row = document.createElement('div'); row.className = 'finding';
    const severity = document.createElement('span'); severity.className = `severity ${finding.severity}`; severity.textContent = finding.severity.toUpperCase();
    const message = document.createElement('p'); message.textContent = finding.message;
    row.append(severity, message); list.append(row);
  }
}
function renderResult(data) {
  latestResult = data;
  results.hidden = false;
  setText('stat-status', data.http.statusCode);
  setText('stat-status-note', data.http.statusMessage || 'HTTP response');
  setText('stat-time', `${data.http.responseTimeMs} ms`);
  setText('stat-findings', data.findings.length);
  setText('stat-redirects', data.http.redirects.length);
  setText('page-title', data.page.title || 'Untitled page');
  setText('content-type', data.http.contentType || 'Unknown content type');
  setText('final-url', data.finalUrl);
  setText('meta-description', data.page.metaDescription || 'Not found');
  setText('h1-headings', data.page.h1Headings.length ? data.page.h1Headings.join(' · ') : 'Not found');
  setText('html-lang', data.page.htmlLang || 'Not found');
  setText('viewport-meta', data.page.viewportMeta ? 'Present' : 'Missing');
  setText('response-size', formatBytes(data.http.bytesReceived) + (data.http.bodyTruncated ? ' (truncated)' : ''));
  renderFindings(data.findings);
}
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  results.hidden = true; latestResult = null; button.disabled = true;
  const buttonText = button.querySelector('span'); buttonText.textContent = 'Auditing…';
  setStatus('Checking website', 'RUNNING', 'Validating URL, resolving public DNS, and requesting the website…', 22);
  try {
    const response = await fetch('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: input.value.trim() }) });
    setStatus('Analysing response', 'RUNNING', 'HTTP response received. Preparing metadata checks and findings…', 72);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Audit failed with HTTP ${response.status}.`);
    renderResult(data);
    setStatus('Audit completed', 'COMPLETED', `Finished ${new Date(data.auditedAt).toLocaleString()}. Review the findings below.`, 100);
  } catch (error) {
    setStatus('Audit failed', 'FAILED', error.message || 'Could not complete the audit. Check the URL and server logs.', 100);
  } finally {
    button.disabled = false; buttonText.textContent = 'Run audit';
  }
});
jsonButton.addEventListener('click', () => {
  if (!latestResult) return;
  const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
  anchor.href = url; anchor.download = 'website-audit-report.json'; anchor.click(); URL.revokeObjectURL(url);
});
