import test from 'node:test';
import assert from 'node:assert/strict';
import { parseAndValidateUrl, isPublicIp, resolveAndValidateHost } from '../src/url-security.js';

test('accepts an explicit public HTTPS URL and removes fragment', () => {
  const url = parseAndValidateUrl('https://example.com/path#section');
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'example.com');
  assert.equal(url.hash, '');
});

test('rejects unsupported protocols and embedded credentials', () => {
  assert.throws(() => parseAndValidateUrl('file:///etc/passwd'), /Only HTTP and HTTPS/);
  assert.throws(() => parseAndValidateUrl('https://user:pass@example.com'), /usernames or passwords/);
});

test('rejects local and internal hostnames', () => {
  for (const value of ['http://localhost', 'http://service.local', 'http://db.internal', 'http://printer']) {
    assert.throws(() => parseAndValidateUrl(value), /Local and internal|fully qualified/);
  }
});

test('rejects non-public IPv4 and IPv6 addresses', () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '192.168.1.2', '169.254.1.1', '224.0.0.1', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1']) {
    assert.equal(isPublicIp(address), false, `${address} should be blocked`);
  }
  assert.equal(isPublicIp('8.8.8.8'), true);
  assert.equal(isPublicIp('2606:4700:4700::1111'), true);
});

test('DNS validation rejects a hostname if any answer is unsafe', async () => {
  const resolver = async () => [
    { address: '93.184.216.34', family: 4 },
    { address: '127.0.0.1', family: 4 }
  ];
  await assert.rejects(() => resolveAndValidateHost('example.com', resolver), /private or reserved/);
});

test('DNS validation returns public answers for connection pinning', async () => {
  const expected = [{ address: '93.184.216.34', family: 4 }];
  const result = await resolveAndValidateHost('example.com', async () => expected);
  assert.deepEqual(result, expected);
});
