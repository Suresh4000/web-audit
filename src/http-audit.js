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
        'user-agent': 'WebsiteAuditStudio/0.1 (+local-development-audit)',
        accept: 'text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5',
        'accept-encoding': 'identity',
        connection: 'close'
      },
      timeout: timeoutMs,
      // Pin the socket to an IP validated above to reduce DNS-rebinding risk.
lookup: (_hostname, options, callback) => {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  if (options?.all) {
    callback(null, [
      { address: pinned.address, family: pinned.family }
    ]);
  } else {
    callback(null, pinned.address, pinned.family);
  }
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
      res.on('error', (error) => {
        if (!settled) finish(error);
      });
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

function extractFindings(html, contentType) {
  const isHtml = /text\/html|application\/xhtml\+xml/i.test(contentType ?? '');
  if (!isHtml) return { isHtml: false, title: null, metaDescription: null, h1Headings: [], htmlLang: null, viewportMeta: false };

  const title = html.match(/<title\b[^>]*>([\s\S]*?)<\/title\s*>/i)?.[1];
  const metaDescription = [...html.matchAll(/<meta\b[^>]*>/gi)]
    .map((match) => match[0])
    .find((tag) => /\bname\s*=\s*(["'])description\1/i.test(tag))
    ?.match(/\bcontent\s*=\s*(["'])([\s\S]*?)\1/i)?.[2] ?? null;
  const h1Headings = [...html.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1\s*>/gi)]
    .map((match) => stripTags(match[1]).trim())
    .filter(Boolean);
  const htmlOpen = html.match(/<html\b[^>]*>/i)?.[0] ?? '';
  const htmlLang = htmlOpen.match(/\blang\s*=\s*(["'])(.*?)\1/i)?.[2] ?? null;
  const viewportMeta = [...html.matchAll(/<meta\b[^>]*>/gi)].some((match) =>
    /\bname\s*=\s*(["'])viewport\1/i.test(match[0])
  );

  return {
    isHtml: true,
    title: cleanText(title),
    metaDescription: cleanText(metaDescription),
    h1Headings,
    htmlLang,
    viewportMeta
  };
}

function stripTags(value) {
  return value.replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, ' ');
}

function cleanText(value) {
  return value == null ? null : stripTags(value).trim();
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

    // Resolve and validate every hop, including redirect targets.
const addresses = await resolveAndValidateHost(currentUrl.hostname);
    console.log('DNS addresses:', JSON.stringify(addresses));
    response = await requestOnce(currentUrl, addresses, { timeoutMs, maxBytes });

    const location = response.headers.location;
    if (![301, 302, 303, 307, 308].includes(response.statusCode) || !location) break;
    if (redirectCount >= maxRedirects) throw new Error(`Redirect limit exceeded (${maxRedirects}).`);

    let nextUrl;
    try {
      nextUrl = parseAndValidateUrl(new URL(location, currentUrl).href);
    } catch (error) {
      throw new Error(`Unsafe or invalid redirect destination: ${error.message}`);
    }
    redirects.push({ statusCode: response.statusCode, from: currentUrl.href, to: nextUrl.href });
    currentUrl = nextUrl;
  }

  const contentType = String(response.headers['content-type'] ?? '');
  const htmlChecks = extractFindings(response.body, contentType);
  const findings = [];
  const add = (severity, code, message) => findings.push({ severity, code, message });

  if (response.statusCode >= 400) add('high', 'http-error-status', `The server returned HTTP ${response.statusCode}.`);
  if (response.statusCode >= 200 && response.statusCode < 400) add('info', 'http-reachable', `The website responded with HTTP ${response.statusCode}.`);
  if (currentUrl.protocol !== 'https:') add('medium', 'not-https', 'The final page URL uses HTTP instead of HTTPS.');
  if (!/^text\/html|application\/xhtml\+xml/i.test(contentType)) {
    add('low', 'non-html-content', `The response content type is ${contentType || 'missing'}, so HTML checks were limited.`);
  } else {
    if (!htmlChecks.title) add('medium', 'missing-title', 'No page title was found.');
    if (!htmlChecks.metaDescription) add('low', 'missing-meta-description', 'No meta description was found.');
    if (htmlChecks.h1Headings.length === 0) add('low', 'missing-h1', 'No H1 heading was found.');
    if (htmlChecks.h1Headings.length > 1) add('low', 'multiple-h1', `Found ${htmlChecks.h1Headings.length} H1 headings; review whether the heading structure is intentional.`);
    if (!htmlChecks.viewportMeta) add('low', 'missing-viewport', 'No viewport meta tag was found.');
    if (!htmlChecks.htmlLang) add('low', 'missing-html-lang', 'The HTML element has no lang attribute.');
  }
  if (response.bodyTruncated) add('info', 'response-truncated', `Analysis was limited to the first ${maxBytes} response bytes.`);

  return {
    inputUrl,
    finalUrl: currentUrl.href,
    auditedAt: new Date().toISOString(),
    status: 'completed',
    http: {
      statusCode: response.statusCode,
      statusMessage: response.statusMessage,
      responseTimeMs: response.responseTimeMs,
      contentType: contentType || null,
      bytesReceived: response.bytesReceived,
      bodyTruncated: response.bodyTruncated,
      redirects
    },
    page: htmlChecks,
    findings,
    limitations: [
      'This is an initial HTTP-only audit; it does not execute JavaScript or render the page in a browser.',
      'HTML checks use lightweight regular expressions and are not a substitute for a standards-compliant HTML parser.',
      'Application-level SSRF controls are not a substitute for outbound network/egress restrictions in production.'
    ]
  };
}
