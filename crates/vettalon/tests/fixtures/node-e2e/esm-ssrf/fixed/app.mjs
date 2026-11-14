import dns from 'node:dns/promises';
import net from 'node:net';

function isBlocked(address) {
  if (net.isIP(address) === 4) {
    const [a, b] = address.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  if (net.isIP(address) !== 6) return true;
  const host = new URL('http://[' + address + ']/').hostname.slice(1, -1);
  const halves = host.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const words = halves.length === 2
    ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right]
    : left;
  const parts = words.map(word => parseInt(word, 16));
  return parts.every(part => part === 0) ||
    (parts.slice(0, 7).every(part => part === 0) && parts[7] === 1) ||
    (parts.slice(0, 5).every(part => part === 0) && parts[5] === 0xffff) ||
    (parts[0] & 0xfe00) === 0xfc00 || (parts[0] & 0xffc0) === 0xfe80;
}

async function checkedUrl(input) {
  const url = new URL(input);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Unsupported protocol');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const addresses = net.isIP(host)
    ? [{ address: host }]
    : await dns.lookup(host, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some(({ address }) => isBlocked(address))) {
    throw new Error('Blocked address');
  }
  return url;
}

export async function run(url) {
  const response = await fetch(await checkedUrl(url), { redirect: 'error' });
  return await response.text();
}
