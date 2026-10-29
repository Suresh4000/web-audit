import dns from 'node:dns/promises';
import net from 'node:net';

const BLOCKED_SUFFIXES = [
  '.localhost', '.local', '.internal', '.home', '.lan', '.test', '.invalid', '.example'
];

export function parseAndValidateUrl(input) {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new Error('Enter a website URL.');
  }
  if (input.length > 2048) throw new Error('URL is too long (maximum 2048 characters).');

  let url;
  try {
    url = new URL(input.trim());
  } catch {
    // Do not silently guess a scheme; explicit HTTP(S) makes intent clear.
    throw new Error('Enter a valid URL beginning with http:// or https://.');
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('Only HTTP and HTTPS URLs are allowed.');
  }
  if (url.username || url.password) throw new Error('URLs containing usernames or passwords are not allowed.');
  if (!url.hostname) throw new Error('The URL must include a hostname.');

  const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (hostname === 'localhost' || BLOCKED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error('Local and internal hostnames are not allowed.');
  }

  if (net.isIP(hostname)) {
    if (!isPublicIp(hostname)) throw new Error('Private, loopback, link-local, and reserved IP addresses are not allowed.');
  } else {
    // Reject single-label names (e.g. "database"), which commonly resolve internally.
    if (!hostname.includes('.') || hostname.length > 253) {
      throw new Error('Use a public, fully qualified website hostname.');
    }
    if (hostname.split('.').some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) {
      throw new Error('The URL contains an invalid hostname.');
    }
  }

  url.hash = '';
  return url;
}

function ipv4ToNumber(address) {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]);
}

function ipv6ToBigInt(address) {
  let input = address.toLowerCase().split('%')[0];
  if (input.includes('.')) {
    const lastColon = input.lastIndexOf(':');
    const ipv4 = ipv4ToNumber(input.slice(lastColon + 1));
    if (ipv4 === null) return null;
    input = `${input.slice(0, lastColon)}:${((ipv4 >>> 16) & 0xffff).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  if ((input.match(/::/g) ?? []).length > 1) return null;
  const hasCompression = input.includes('::');
  const halves = input.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = hasCompression && halves[1] ? halves[1].split(':') : (!hasCompression && halves[1] ? halves[1].split(':') : []);
  if (left.concat(right).some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  let words;
  if (hasCompression) {
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    words = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    words = left;
    if (words.length !== 8) return null;
  }
  return words.reduce((value, word) => (value << 16n) | BigInt(`0x${word}`), 0n);
}

function inV4Cidr(address, network, prefix) {
  const ip = ipv4ToNumber(address);
  const base = ipv4ToNumber(network);
  if (ip === null || base === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return ((ip >>> 0) & mask) === ((base >>> 0) & mask);
}

function inV6Cidr(value, network, prefix) {
  const base = ipv6ToBigInt(network);
  if (value === null || base === null) return false;
  const shift = BigInt(128 - prefix);
  return (value >> shift) === (base >> shift);
}

export function isPublicIp(address) {
  if (typeof address !== 'string') return false;
  const version = net.isIP(address);
  if (version === 4) {
    const blocked = [
      ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
      ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24],
      ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]
    ];
    return !blocked.some(([network, prefix]) => inV4Cidr(address, network, prefix));
  }
  if (version === 6) {
    const value = ipv6ToBigInt(address);
    if (value === null) return false;
    // Only globally routable unicast space (2000::/3) is eligible. Explicitly
    // exclude documentation, benchmarking, transition, and other special ranges.
    if (!inV6Cidr(value, '2000::', 3)) return false;
    const blocked = [
      ['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]
    ];
    return !blocked.some(([network, prefix]) => inV6Cidr(value, network, prefix));
  }
  return false;
}

export async function resolveAndValidateHost(hostname, resolver = dns.lookup) {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (net.isIP(normalized)) {
    if (!isPublicIp(normalized)) throw new Error('Destination IP address is not public.');
    return [{ address: normalized, family: net.isIP(normalized) }];
  }

  let records;
  try {
    records = await resolver(normalized, { all: true, verbatim: true });
  } catch {
    throw new Error('Could not resolve the website hostname.');
  }
  if (!Array.isArray(records) || records.length === 0) throw new Error('The website hostname has no IP addresses.');

  // Reject the entire hostname if even one answer is unsafe; do not just pick a public answer.
  for (const record of records) {
    if (!isPublicIp(record.address)) throw new Error('Hostname resolves to a private or reserved IP address; request blocked.');
  }
  return records;
}
