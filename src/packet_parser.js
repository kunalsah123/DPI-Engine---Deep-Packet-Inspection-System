'use strict';

function formatIPv6(bytes) {
  const words = [];
  for (let i = 0; i < 16; i += 2) words.push(bytes.readUInt16BE(i).toString(16));
  let bestStart = -1, bestLength = 1;
  for (let i = 0; i < words.length;) {
    if (words[i] !== '0') { i++; continue; }
    let end = i; while (end < words.length && words[end] === '0') end++;
    if (end - i > bestLength) { bestStart = i; bestLength = end - i; }
    i = end;
  }
  if (bestStart < 0) return words.join(':');
  const left = words.slice(0, bestStart).join(':'), right = words.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

function parsePacket(frame, linkType = 1) {
  let offset, etherType;
  if (linkType === 1) {
    if (frame.length < 14) return {};
    offset = 14; etherType = frame.readUInt16BE(12);
    while ([0x8100, 0x88a8, 0x9100].includes(etherType)) {
      if (frame.length < offset + 4) return {};
      etherType = frame.readUInt16BE(offset + 2); offset += 4;
    }
  } else if ([101, 228, 229].includes(linkType)) {
    offset = 0; etherType = (frame[0] >> 4) === 6 ? 0x86dd : 0x0800;
  } else return { unsupportedLink: true };

  let src, dst, protocol, ipEnd;
  if (etherType === 0x0800) {
    if (frame.length < offset + 20 || (frame[offset] >> 4) !== 4) return {};
    const ipStart = offset, headerLength = (frame[offset] & 15) * 4;
    if (headerLength < 20 || frame.length < offset + headerLength) return {};
    const totalLength = frame.readUInt16BE(offset + 2);
    ipEnd = Math.min(frame.length, offset + (totalLength || frame.length - offset));
    src = [...frame.subarray(offset + 12, offset + 16)].join('.');
    dst = [...frame.subarray(offset + 16, offset + 20)].join('.');
    protocol = frame[offset + 9];
    const fragmentOffset = frame.readUInt16BE(ipStart + 6) & 0x1fff;
    offset += headerLength;
    if (fragmentOffset !== 0) return { src, dst, protocol, fragmented: true };
  } else if (etherType === 0x86dd) {
    if (frame.length < offset + 40 || (frame[offset] >> 4) !== 6) return {};
    src = formatIPv6(frame.subarray(offset + 8, offset + 24));
    dst = formatIPv6(frame.subarray(offset + 24, offset + 40));
    protocol = frame[offset + 6];
    ipEnd = Math.min(frame.length, offset + 40 + frame.readUInt16BE(offset + 4));
    offset += 40;
    let extensionCount = 0;
    while ([0, 43, 60, 51].includes(protocol) && extensionCount++ < 8) {
      if (offset + 2 > ipEnd) return { src, dst, protocol };
      const next = frame[offset];
      const size = protocol === 51 ? (frame[offset + 1] + 2) * 4 : (frame[offset + 1] + 1) * 8;
      if (offset + size > ipEnd) return { src, dst, protocol };
      protocol = next; offset += size;
    }
    if (protocol === 44) return { src, dst, protocol, fragmented: true };
  } else return { etherType };

  let srcPort = 0, dstPort = 0, payload = Buffer.alloc(0), tcpFlags = 0;
  if (protocol === 6) {
    if (offset + 20 > ipEnd) return { src, dst, protocol };
    srcPort = frame.readUInt16BE(offset); dstPort = frame.readUInt16BE(offset + 2);
    tcpFlags = frame[offset + 13];
    const tcpHeaderLength = (frame[offset + 12] >> 4) * 4;
    if (tcpHeaderLength < 20 || offset + tcpHeaderLength > ipEnd) return { src, dst, protocol, srcPort, dstPort, tcpFlags };
    payload = frame.subarray(offset + tcpHeaderLength, ipEnd);
  } else if (protocol === 17) {
    if (offset + 8 > ipEnd) return { src, dst, protocol };
    srcPort = frame.readUInt16BE(offset); dstPort = frame.readUInt16BE(offset + 2);
    const udpLength = frame.readUInt16BE(offset + 4);
    payload = frame.subarray(offset + 8, Math.min(ipEnd, offset + Math.max(8, udpLength)));
  }
  return { src, dst, protocol, srcPort, dstPort, tcpFlags, payload, etherType };
}

module.exports = { parsePacket, formatIPv6 };
