import http from 'node:http';
import https from 'node:https';
import { performance } from 'node:perf_hooks';
import { parseAndValidateUrl, resolveAndValidateHost } from './url-security.js';

const DEFAULT_TIMEOUT_MS = positiveInt(process.env.REQUEST_TIMEOUT_MS, 10000);
const DEFAULT_MAX_BYTES = positiveInt(process.env.MAX_RESPONSE_BYTES, 1500000);
const DEFAULT_MAX_REDIRECTS = positiveInt(process.env.MAX_REDIRECTS, 5);

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function requestOnce(url, addresses, { timeoutMs, maxBytes }) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const pinned = addresses[0];
    let settled = false;
    const started = performance.now();
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      error ? reject(error) : resolve(value);
    };

    const req = transport.request(url, {
      method: 'GET',
      headers: {
        'user-agent': 'WebsiteAuditStudio/1.0 (+website-quality-audit)',
        accept: 'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5',
        'accept-encoding': 'identity',
        connection: 'close'
      },
      timeout: timeoutMs,
      // Pin the socket to the public address validated immediately before this request.
      lookup: (_hostname, options, callback) => {
        if (typeof options === 'function') {
          callback = options;
          options = {};
        }
        if (options?.all) callback(null, [{ address: pinned.address, family: pinned.family }]);
        else callback(null, pinned.address, pinned.family);
      },
      maxHeaderSize: 32 * 1024
    }, (res) => {
      const chunks = [];
      let bytes = 0;
      let truncated = false;
      res.on('data', (chunk) => {
        if (bytes >= maxBytes) {
          truncated = true;
          res.destroy();
          finish(null, makeResult(res, chunks, bytes, truncated, started));
          return;
        }
        const remaining = maxBytes - bytes;
        if (chunk.length > remaining) {
          chunks.push(chunk.subarray(0, remaining));
          bytes += remaining;
          truncated = true;
          res.destroy();
          finish(null, makeResult(res, chunks, bytes, truncated, started));
          return;
        }
        chunks.push(chunk);
        bytes += chunk.length;
      });
      res.on('end', () => finish(null, makeResult(res, chunks, bytes, truncated, started)));
      res.on('error', (error) => { if (!settled) finish(error); });
    });
    req.on('timeout', () => req.destroy(new Error(`Request timed out after ${timeoutMs} ms.`)));
    req.on('error', (error) => finish(error));
    req.end();
  });
}

function makeResult(res, chunks, bytes, truncated, started) {
  return {
    statusCode: res.statusCode ?? 0,
    statusMessage: res.statusMessage ?? '',
    headers: res.headers,
    body: Buffer.concat(chunks).toString('utf8'),
    bytesReceived: bytes,
    bodyTruncated: truncated,
    responseTimeMs: Math.round(performance.now() - started)
  };
}

function stripTags(value) {
  return value.replace(/<script\\b[^>]*>[\\s\\S]*?<\\/script\\s*>/gi, ' ')
    .replace(/<style\\b[^>]*>[\\s\\S]*?<\\/style\\s*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\\s+/g, ' ');
}

function cleanText(value) {
  return value == null ? null : stripTags(value).trim();
}

function attr(tag, name) {
  const matches = [...tag.matchAll(/([^\s=]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)];
  const match = matches.find(item => item[1].toLowerCase() === name.toLowerCase());
  return match ? (match[2] ?? match[3] ?? match[4] ?? null) : null;
}

function extractPage(html, contentType, baseUrl) {
  const isHtml = /text\/html|application\/xhtml\+xml/i.test(contentType);
  if (!isHtml) return { isHtml: false, title: null, titleLength: 0, metaDescription: null, metaDescriptionLength: 0, h1Headings: [], h2Count: 0, htmlLang: null, viewportMeta: false, canonical: null, robotsMeta: null, openGraphTitle: null, openGraphDescription: null, images: { total: 0, missingAlt: 0 }, links: { internal: 0, external: 0, empty: 0 }, mixedContent: 0, structuredData: false, formCount: 0 };

  const tags = [...html.matchAll(/<meta\b[^>]*>/gi)].map(m => m[0]);
  const meta = (name) => {
    const tag = tags.find(t => (attr(t, 'name') || '').toLowerCase() === name.toLowerCase());
    return tag ? attr(tag, 'content') : null;
  };
  const property = (name) => {
    const tag = tags.find(t => (attr(t, 'property') || '').toLowerCase() === name.toLowerCase());
    return tag ? attr(tag, 'content') : null;
  };
  const title = cleanText(html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i)?.[1]);
  const description = cleanText(meta('description'));
  const htmlOpen = html.match(/<html\b[^>]*>/i)?.[0] ?? '';
  const canonicalTag = [...html.matchAll(/<link\b[^>]*>/gi)].map(m => m[0]).find(t => (attr(t, 'rel') || '').toLowerCase().split(/\s+/).includes('canonical'));
  const images = [...html.matchAll(/<img\b[^>]*>/gi)].map(m => m[0]);
  const links = [...html.matchAll(/<a\b[^>]*>/gi)].map(m => m[0]);
  const h1Headings = [...html.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1\s*>/gi)].map(m => cleanText(m[1])).filter(Boolean);
  const h2Count = [...html.matchAll(/<h2\b/gi)].length;
  const baseHost = new URL(baseUrl).hostname;
  let external = 0;
  let empty = 0;
  let internal = 0;
  for (const tag of links) {
    const href = attr(tag, 'href');
    if (!href || !href.trim() || href.trim() === '#') { empty++; continue; }
    if (/^(javascript:|mailto:|tel:|#)/i.test(href.trim())) continue;
    try {
      const u = new URL(href, baseUrl);
      if (u.hostname === baseHost) internal++;
      else external++;
    } catch { /* Ignore malformed hrefs; never request them from this check. */ }
  }
  const mixedContent = [...html.matchAll(/(?:src|href)\s*=\s*(["'])http:\/\//gi)].length;
  return {
    isHtml: true,
    title,
    titleLength: title?.length ?? 0,
    metaDescription: description,
    metaDescriptionLength: description?.length ?? 0,
    h1Headings,
    h2Count,
    htmlLang: attr(htmlOpen, 'lang'),
    viewportMeta: tags.some(t => (attr(t, 'name') || '').toLowerCase() === 'viewport'),
    canonical: canonicalTag ? attr(canonicalTag, 'href') : null,
    robotsMeta: meta('robots'),
    openGraphTitle: property('og:title'),
    openGraphDescription: property('og:description'),
    images: { total: images.length, missingAlt: images.filter(t => attr(t, 'alt') === null).length },
    links: { internal, external, empty },
    mixedContent,
    structuredData: /<script\b[^>]*type\s*=\s*(["'])application\/ld\+json\1/i.test(html),
    formCount: [...html.matchAll(/<form\b/gi)].length
  };
}

function makeFinding(category, severity, code, title, message, recommendation, evidence = null) {
  return { category, severity, code, title, message, recommendation, evidence };
}

function buildAudit(page, response, finalUrl, redirects, maxBytes) {
  const findings = [];
  const checks = [];
  const check = (category, code, title, passed, severity, message, recommendation, evidence, weight = 1) => {
    const status = passed === null ? 'not-tested' : passed ? 'passed' : 'failed';
    checks.push({ category, code, title, status, weight, evidence: evidence ?? null });
    if (passed === false) findings.push(makeFinding(category, severity, code, title, message, recommendation, evidence ?? null));
  };
  const isHtml = page.isHtml;
  check('SEO', 'http-status', 'Successful HTTP response', response.statusCode >= 200 && response.statusCode < 400, 'high', `The server returned HTTP ${response.statusCode}.`, 'Fix server errors and ensure the page returns the intended status code.', `HTTP ${response.statusCode}`, 2);
  check('SEO', 'title', 'Page title', isHtml ? Boolean(page.title) : null, 'high', 'No page title was found.', 'Add a unique, descriptive title that explains the page and its primary topic.', page.title || 'No title tag', 2);
  check('SEO', 'title-length', 'Title length', isHtml ? page.titleLength >= 15 && page.titleLength <= 60 : null, 'low', `The title is ${page.titleLength} characters; titles outside roughly 15–60 characters may be unclear or truncated.`, 'Write a concise, descriptive title. Treat this range as a guideline, not a strict ranking rule.', `${page.titleLength} characters`);
  check('SEO', 'meta-description', 'Meta description', isHtml ? Boolean(page.metaDescription) : null, 'medium', 'No meta description was found.', 'Add a useful page-specific description summarising the page and its value.', 'No meta description', 2);
  check('SEO', 'meta-description-length', 'Meta description length', isHtml && page.metaDescription ? page.metaDescriptionLength >= 70 && page.metaDescriptionLength <= 160 : null, 'low', 'The meta description is unusually short or long.', 'Aim for a clear snippet of roughly 70–160 characters; search engines may rewrite snippets.', `${page.metaDescriptionLength} characters`);
  check('SEO', 'h1', 'Primary heading', isHtml ? page.h1Headings.length === 1 : null, 'medium', page.h1Headings.length === 0 ? 'No H1 heading was found.' : `Found ${page.h1Headings.length} H1 headings; confirm the page has a clear primary heading.`, 'Use a clear primary page heading and maintain a logical H1/H2 hierarchy.', `${page.h1Headings.length} H1 heading(s)`);
  check('SEO', 'canonical', 'Canonical URL', isHtml ? Boolean(page.canonical) : null, 'low', 'No canonical link was found.', 'Add a canonical URL when appropriate to identify the preferred version of this page.', 'No canonical link');
  check('SEO', 'open-graph', 'Social sharing metadata', isHtml ? Boolean(page.openGraphTitle && page.openGraphDescription) : null, 'low', 'Open Graph title or description is missing.', 'Add og:title and og:description (and preferably og:image) for more predictable social previews.', `og:title: ${page.openGraphTitle ? 'present' : 'missing'}; og:description: ${page.openGraphDescription ? 'present' : 'missing'}`);
  check('SEO', 'structured-data', 'Structured data', isHtml ? page.structuredData : null, 'info', 'No JSON-LD structured data was detected in the returned HTML.', 'Consider relevant Schema.org JSON-LD (for example Organization, LocalBusiness, Product, or Article) when it fits the page.', 'JSON-LD not detected');
  check('Accessibility', 'html-lang', 'Document language', isHtml ? Boolean(page.htmlLang) : null, 'medium', 'The HTML element has no lang attribute.', 'Set an accurate lang attribute on the html element so assistive technology can identify the page language.', 'html lang missing');
  check('Accessibility', 'viewport', 'Mobile viewport', isHtml ? page.viewportMeta : null, 'medium', 'No viewport meta tag was found.', 'Add a responsive viewport meta tag to help the page render correctly on mobile devices.', 'viewport meta missing');
  check('Accessibility', 'image-alt', 'Image alternative text', isHtml ? page.images.missingAlt === 0 : null, 'medium', `${page.images.missingAlt} of ${page.images.total} image(s) have no alt attribute.`, 'Provide meaningful alt text for informative images and alt="" for decorative images.', `${page.images.missingAlt}/${page.images.total} images missing alt`);
  check('Accessibility', 'heading-structure', 'Heading structure', isHtml ? !(page.h1Headings.length === 0 && page.h2Count > 0) : null, 'low', 'H2 headings exist without an H1 in the returned HTML.', 'Review the heading hierarchy so page sections are structured clearly.', `${page.h1Headings.length} H1; ${page.h2Count} H2`);
  const headers = response.headers;
  check('Security', 'https', 'HTTPS transport', finalUrl.protocol === 'https:', 'high', 'The final page uses unencrypted HTTP.', 'Enable HTTPS and redirect HTTP requests to the secure canonical URL.', finalUrl.protocol);
  check('Security', 'hsts', 'Strict-Transport-Security', finalUrl.protocol === 'https:' ? Boolean(headers['strict-transport-security']) : null, 'medium', 'The HTTPS response does not include Strict-Transport-Security.', 'Configure HSTS after confirming HTTPS works across the domain and relevant subdomains.', headers['strict-transport-security'] || 'Header missing');
  check('Security', 'content-security-policy', 'Content-Security-Policy', Boolean(headers['content-security-policy']), 'medium', 'Content-Security-Policy header is missing.', 'Define a Content-Security-Policy appropriate for the site to reduce certain injection risks.', 'Header missing');
  check('Security', 'frame-protection', 'Clickjacking protection', Boolean(headers['x-frame-options'] || /frame-ancestors/i.test(headers['content-security-policy'] || '')), 'low', 'No X-Frame-Options or CSP frame-ancestors directive was detected.', 'Use CSP frame-ancestors or X-Frame-Options if the site should not be embedded by other origins.', 'No recognised frame restriction');
  check('Security', 'nosniff', 'X-Content-Type-Options', String(headers['x-content-type-options'] || '').toLowerCase() === 'nosniff', 'low', 'X-Content-Type-Options: nosniff is missing.', 'Set X-Content-Type-Options: nosniff to reduce MIME-sniffing risks.', headers['x-content-type-options'] || 'Header missing');
  check('Security', 'referrer-policy', 'Referrer-Policy', Boolean(headers['referrer-policy']), 'low', 'Referrer-Policy header is missing.', 'Set a policy such as strict-origin-when-cross-origin that matches the site’s privacy needs.', 'Header missing');
  check('Performance', 'response-time', 'Server response time', response.responseTimeMs <= 800, 'medium', `The measured HTTP response took ${response.responseTimeMs} ms.`, 'Investigate server latency, caching, backend queries, and network conditions if this repeats above 800 ms.', `${response.responseTimeMs} ms`, 2);
  check('Performance', 'response-size', 'HTML response size', response.bytesReceived <= 500000, 'low', `The returned response is ${response.bytesReceived} bytes, which is relatively large for an initial HTML document.`, 'Reduce unnecessary HTML and inline assets, compress responses, and defer non-critical resources where appropriate.', `${response.bytesReceived} bytes`);
  check('Performance', 'mixed-content', 'Mixed-content references', isHtml ? page.mixedContent === 0 : null, 'medium', `${page.mixedContent} HTTP resource reference(s) were found in an HTTPS page.`, 'Change HTTP resource URLs to HTTPS to avoid browser blocking and insecure subrequests.', `${page.mixedContent} HTTP reference(s)`);
  check('SEO', 'redirect-chain', 'Redirect chain', redirects.length <= 1, 'low', `The request followed ${redirects.length} redirect(s).`, 'Link directly to the final canonical URL and remove unnecessary redirect hops.', `${redirects.length} redirect(s)`);
  if (response.bodyTruncated) findings.push(makeFinding('General', 'info', 'response-truncated', 'Response was truncated', `Analysis was limited to the first ${maxBytes} response bytes; checks may miss markup later in the document.`, 'Increase the response limit only if appropriate, or treat missing checks as incomplete for large pages.', `Maximum ${maxBytes} bytes`));

  const categories = ['SEO', 'Performance', 'Security', 'Accessibility'];
  const scores = {};
  for (const category of categories) {
    const relevant = checks.filter(c => c.category === category && c.status !== 'not-tested');
    const total = relevant.reduce((sum, c) => sum + c.weight, 0);
    const earned = relevant.filter(c => c.status === 'passed').reduce((sum, c) => sum + c.weight, 0);
    scores[category.toLowerCase()] = { score: total ? Math.round(earned / total * 100) : null, passed: relevant.filter(c => c.status === 'passed').length, failed: relevant.filter(c => c.status === 'failed').length, notTested: checks.filter(c => c.category === category && c.status === 'not-tested').length, total: relevant.length };
  }
  const scoreValues = Object.values(scores).filter(s => s.score !== null).map(s => s.score);
  const overallScore = scoreValues.length ? Math.round(scoreValues.reduce((a, b) => a + b, 0) / scoreValues.length) : null;
  const severityCounts = Object.fromEntries(['high', 'medium', 'low', 'info'].map(level => [level, findings.filter(f => f.severity === level).length]));
  return { overallScore, scores, checks, findings, severityCounts };
}

export async function runHttpAudit(inputUrl, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  let currentUrl = parseAndValidateUrl(inputUrl);
  const redirects = [];
  const visited = new Set();
  let response;
  for (let redirectCount = 0; ; redirectCount += 1) {
    if (visited.has(currentUrl.href)) throw new Error('Redirect loop detected.');
    visited.add(currentUrl.href);
    const addresses = await resolveAndValidateHost(currentUrl.hostname);
    response = await requestOnce(currentUrl, addresses, { timeoutMs, maxBytes });
    const location = response.headers.location;
    if (![301, 302, 303, 307, 308].includes(response.statusCode) || !location) break;
    if (redirectCount >= maxRedirects) throw new Error(`Redirect limit exceeded (${maxRedirects}).`);
    let nextUrl;
    try { nextUrl = parseAndValidateUrl(new URL(location, currentUrl).href); }
    catch (error) { throw new Error(`Unsafe or invalid redirect destination: ${error.message}`); }
    redirects.push({ statusCode: response.statusCode, from: currentUrl.href, to: nextUrl.href });
    currentUrl = nextUrl;
  }
  const contentType = String(response.headers['content-type'] ?? '');
  const page = extractPage(response.body, contentType, currentUrl.href);
  const analysis = buildAudit(page, response, currentUrl, redirects, maxBytes);
  return {
    inputUrl,
    finalUrl: currentUrl.href,
    auditedAt: new Date().toISOString(),
    status: 'completed',
    overallScore: analysis.overallScore,
    scores: analysis.scores,
    checks: analysis.checks,
    severityCounts: analysis.severityCounts,
    http: {
      statusCode: response.statusCode,
      statusMessage: response.statusMessage,
      responseTimeMs: response.responseTimeMs,
      contentType: contentType || null,
      bytesReceived: response.bytesReceived,
      bodyTruncated: response.bodyTruncated,
      headers: {
        server: response.headers.server ?? null,
        cacheControl: response.headers['cache-control'] ?? null,
        contentSecurityPolicy: response.headers['content-security-policy'] ?? null,
        strictTransportSecurity: response.headers['strict-transport-security'] ?? null,
        xFrameOptions: response.headers['x-frame-options'] ?? null,
        xContentTypeOptions: response.headers['x-content-type-options'] ?? null,
        referrerPolicy: response.headers['referrer-policy'] ?? null
      },
      redirects
    },
    page,
    findings: analysis.findings,
    limitations: [
      'This is an HTTP and returned-HTML audit. It does not execute JavaScript or render the page in a browser.',
      'Performance signals are response-time and response-size heuristics, not Core Web Vitals or Lighthouse measurements.',
      'Accessibility checks are static indicators and do not replace a browser-based WCAG audit.',
      'SEO and HTML checks use lightweight regular expressions; they are not a substitute for a standards-compliant HTML parser.',
      'Missing security headers are configuration indicators, not proof that a site is exploitable.',
      'Application-level SSRF controls are not a substitute for outbound network/egress restrictions in production.'
    ]
  };
}
