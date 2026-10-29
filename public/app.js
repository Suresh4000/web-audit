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
const filterSelect = document.querySelector('#finding-filter');
let latestResult = null;
let activeFilter = 'all';

function setStatus(title, badge, message, progress) {
  statusPanel.hidden = false;
  statusTitle.textContent = title;
  statusBadge.textContent = badge;
  statusMessage.textContent = message;
  progressBar.style.width = `${progress}%`;
}
function setText(id, value) { document.getElementById(id).textContent = value ?? 'Not available'; }
function formatBytes(bytes) { return bytes < 1024 ? `${bytes} B` : `${(bytes / 1024).toFixed(1)} KB`; }
function create(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}
function renderScores(data) {
  const grid = document.querySelector('#score-grid');
  grid.replaceChildren();
  const categories = [
    ['overall', 'Overall score', data.overallScore],
    ['seo', 'SEO', data.scores?.seo?.score],
    ['performance', 'Performance', data.scores?.performance?.score],
    ['security', 'Security', data.scores?.security?.score],
    ['accessibility', 'Accessibility', data.scores?.accessibility?.score]
  ];
  for (const [key, label, score] of categories) {
    const card = create('article', `score-card score-${score === null || score === undefined ? 'na' : score >= 80 ? 'good' : score >= 50 ? 'mid' : 'low'}`);
    const top = create('div', 'score-top');
    top.append(create('span', '', label), create('span', 'score-label', score == null ? 'N/T' : score >= 80 ? 'Good' : score >= 50 ? 'Needs work' : 'Poor'));
    const value = create('strong', 'score-value', score == null ? '—' : String(score));
    if (score != null) value.append(create('small', '', '/100'));
    const track = create('div', 'score-track');
    const fill = create('div', 'score-fill');
    fill.style.width = `${score ?? 0}%`;
    track.append(fill);
    const detail = key === 'overall' ? 'Average of available category scores' : (() => {
      const s = data.scores?.[key];
      return s ? `${s.passed} passed · ${s.failed} failed` : 'No checks available';
    })();
    card.append(top, value, track, create('small', 'score-detail', detail));
    grid.append(card);
  }
}
function renderFindings(findings) {
  const list = document.querySelector('#findings-list');
  list.replaceChildren();
  const filtered = activeFilter === 'all' ? findings : findings.filter(f => f.severity === activeFilter || f.category.toLowerCase() === activeFilter);
  document.querySelector('#finding-count').textContent = `${filtered.length} of ${findings.length} findings`;
  if (!filtered.length) {
    list.append(create('div', 'empty-findings', 'No findings match this filter.'));
    return;
  }
  for (const finding of filtered) {
    const row = create('article', 'finding');
    const side = create('div', 'finding-side');
    side.append(create('span', `severity ${finding.severity}`, finding.severity.toUpperCase()), create('span', 'finding-category', finding.category));
    const content = create('div', 'finding-content');
    content.append(create('h4', '', finding.title || finding.code), create('p', '', finding.message));
    if (finding.evidence) content.append(create('div', 'finding-evidence', `Evidence: ${finding.evidence}`));
    if (finding.recommendation) content.append(create('div', 'finding-fix', `Recommended fix: ${finding.recommendation}`));
    row.append(side, content);
    list.append(row);
  }
}
function renderChecks(checks) {
  const list = document.querySelector('#checks-list');
  list.replaceChildren();
  for (const check of checks || []) {
    const row = create('div', 'check-row');
    const status = create('span', `check-status ${check.status}`, check.status === 'passed' ? 'PASS' : check.status === 'failed' ? 'REVIEW' : 'NOT TESTED');
    row.append(status, create('span', 'check-name', check.title), create('span', 'check-category', check.category));
    if (check.evidence) row.append(create('span', 'check-evidence', check.evidence));
    list.append(row);
  }
  setText('check-count', `${(checks || []).length} checks`);
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
  setText('h1-headings', data.page.h1Headings?.length ? data.page.h1Headings.join(' · ') : 'Not found');
  setText('html-lang', data.page.htmlLang || 'Not found');
  setText('viewport-meta', data.page.viewportMeta ? 'Present' : 'Missing');
  setText('response-size', formatBytes(data.http.bytesReceived) + (data.http.bodyTruncated ? ' (truncated)' : ''));
  setText('image-summary', data.page.images ? `${data.page.images.total} images · ${data.page.images.missingAlt} missing alt` : 'Not tested');
  setText('link-summary', data.page.links ? `${data.page.links.internal} internal · ${data.page.links.external} external` : 'Not tested');
  setText('canonical-url', data.page.canonical || 'Not found');
  setText('robots-meta', data.page.robotsMeta || 'Not found');
  setText('og-summary', data.page.openGraphTitle || data.page.openGraphDescription ? 'Present' : 'Missing');
  setText('structured-data', data.page.structuredData ? 'JSON-LD detected' : 'Not detected');
  setText('server-header', data.http.headers?.server || 'Not disclosed');
  setText('cache-header', data.http.headers?.cacheControl || 'Not set');
  const counts = data.severityCounts || {};
  for (const level of ['high', 'medium', 'low', 'info']) setText(`count-${level}`, counts[level] ?? data.findings.filter(f => f.severity === level).length);
  renderScores(data);
  renderFindings(data.findings || []);
  renderChecks(data.checks || []);
  const limitations = document.querySelector('#limitations-list');
  limitations.replaceChildren();
  for (const note of data.limitations || []) limitations.append(create('li', '', note));
  document.querySelector('#checks-section').hidden = !(data.checks?.length);
}
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  results.hidden = true;
  latestResult = null;
  button.disabled = true;
  const buttonText = button.querySelector('span');
  buttonText.textContent = 'Auditing…';
  setStatus('Checking website', 'RUNNING', 'Validating URL and public DNS, then inspecting the HTTP response and returned HTML…', 20);
  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: input.value.trim() })
    });
    setStatus('Analysing website signals', 'RUNNING', 'Scoring SEO, performance indicators, security headers, and accessibility signals…', 72);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Audit failed with HTTP ${response.status}.`);
    activeFilter = 'all';
    filterSelect.value = 'all';
    renderResult(data);
    setStatus('Audit completed', 'COMPLETED', `Finished ${new Date(data.auditedAt).toLocaleString()}. Review the scores and prioritised recommendations below.`, 100);
  } catch (error) {
    setStatus('Audit failed', 'FAILED', error.message || 'Could not complete the audit. Check the URL and server logs.', 100);
  } finally {
    button.disabled = false;
    buttonText.textContent = 'Run full audit';
  }
});
filterSelect.addEventListener('change', () => {
  activeFilter = filterSelect.value;
  if (latestResult) renderFindings(latestResult.findings || []);
});
jsonButton.addEventListener('click', () => {
  if (!latestResult) return;
  const blob = new Blob([JSON.stringify(latestResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'website-audit-report.json';
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
