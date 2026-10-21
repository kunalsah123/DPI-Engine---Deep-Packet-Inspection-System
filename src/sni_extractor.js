'use strict';
const { classifyDomain } = require('./types');

function extractSni(payload) {
  try {
    let offset = 0;
    if (payload[offset] === 0x16) {
      if (payload.length < 9 || payload[offset + 5] !== 1) return null;
      offset += 9;
    } else if (payload[offset] === 1 && payload.length > 5) offset += 4;
    else return null;
    offset += 2 + 32;
    let size = payload[offset++]; offset += size;
    size = payload.readUInt16BE(offset); offset += 2 + size;
    size = payload[offset++]; offset += size;
    if (offset + 2 > payload.length) return null;
    const extensionsEnd = Math.min(payload.length, offset + 2 + payload.readUInt16BE(offset)); offset += 2;
    while (offset + 4 <= extensionsEnd) {
      const type = payload.readUInt16BE(offset), length = payload.readUInt16BE(offset + 2); offset += 4;
      if (offset + length > extensionsEnd) return null;
      if (type === 0 && length >= 5) {
        const listLength = payload.readUInt16BE(offset);
        let cursor = offset + 2, end = Math.min(offset + length, cursor + listLength);
        while (cursor + 3 <= end) {
          const nameType = payload[cursor++], nameLength = payload.readUInt16BE(cursor); cursor += 2;
          if (cursor + nameLength > end) return null;
          if (nameType === 0) return payload.toString('utf8', cursor, cursor + nameLength).toLowerCase();
          cursor += nameLength;
        }
      }
      offset += length;
    }
  } catch { return null; }
  return null;
}

function extractHttpHost(payload) {
  const text = payload.toString('latin1');
  return text.match(/(?:^|\r\n)Host:\s*([^\r\n]+)/i)?.[1]?.trim().toLowerCase() || null;
}
function extractDnsQuery(payload) {
  try {
    if (payload.length < 17 || (payload[2] & 0x80)) return null;
    let offset = 12; const labels = [];
    while (offset < payload.length) {
      const size = payload[offset++];
      if (size === 0) break;
      if ((size & 0xc0) !== 0 || offset + size > payload.length) return null;
      labels.push(payload.toString('ascii', offset, offset + size)); offset += size;
    }
    return labels.length ? labels.join('.').toLowerCase() : null;
  } catch { return null; }
}
function inspectPayload(packet) {
  const payload = packet.payload || Buffer.alloc(0);
  const sni = packet.protocol === 6 ? extractSni(payload) : null;
  if (sni) return { domain: sni, app: classifyDomain(sni), kind: 'TLS' };
  const host = extractHttpHost(payload);
  if (host) return { domain: host, app: classifyDomain(host, 'HTTP'), kind: 'HTTP' };
  if (packet.protocol === 17 && (packet.srcPort === 53 || packet.dstPort === 53)) {
    const domain = extractDnsQuery(payload);
    if (domain) return { domain, app: 'DNS', kind: 'DNS' };
  }
  if (packet.protocol === 6 && (packet.srcPort === 443 || packet.dstPort === 443)) return { domain: null, app: 'HTTPS', kind: 'TLS' };
  if (packet.protocol === 17 && (packet.srcPort === 443 || packet.dstPort === 443)) return { domain: null, app: 'QUIC', kind: 'QUIC' };
  if (packet.protocol === 6 && (packet.srcPort === 80 || packet.dstPort === 80)) return { domain: null, app: 'HTTP', kind: 'HTTP' };
  return { domain: null, app: 'Unknown', kind: 'Unknown' };
}
module.exports = { extractSni, extractHttpHost, extractDnsQuery, inspectPayload };
