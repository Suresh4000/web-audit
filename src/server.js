import express from 'express';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { runHttpAudit } from './http-audit.js';
import { parseAndValidateUrl } from './url-security.js';

const app = express();
const here = dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.PORT ?? '3000', 10);
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));

app.get('/health', (_req, res) => res.json({ status: 'ok', service: 'Website Audit Studio', phase: 1 }));

app.post('/api/audit', async (req, res) => {
  const inputUrl = req.body?.url;
  try {
    // Validate before starting any network request; runHttpAudit repeats validation on redirects.
    parseAndValidateUrl(inputUrl);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  try {
    const result = await runHttpAudit(inputUrl);
    return res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Audit failed unexpectedly.';
    const status = /timed out/i.test(message) ? 504 : 502;
    return res.status(status).json({ error: message, status: 'failed' });
  }
});

app.use(express.static(join(here, '..', 'public')));

app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'Request body is too large.' });
  if (error instanceof SyntaxError) return res.status(400).json({ error: 'Request body must be valid JSON.' });
  return res.status(500).json({ error: 'Internal server error.' });
});

app.listen(port, '127.0.0.1', () => {
  console.log(`Website Audit Studio running at http://127.0.0.1:${port}`);
  console.log('Local-development MVP only. Do not expose publicly without production hardening.');
});
