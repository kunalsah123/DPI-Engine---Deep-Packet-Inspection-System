#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function ip4(address) { return Buffer.from(address.split('.').map(Number)); }
function ethernet(src, dst) { return Buffer.concat([Buffer.from(dst.split(':').map(x => parseInt(x, 16))), Buffer.from(src.split(':').map(x => parseInt(x, 16))), Buffer.from([8, 0])]); }
function ipv4(src, dst, protocol, payloadLength, id) {
  const h = Buffer.alloc(20); h[0] = 0x45; h.writeUInt16BE(20 + payloadLength, 2); h.writeUInt16BE(id & 0xffff, 4); h.writeUInt16BE(0x4000, 6); h[8] = 64; h[9] = protocol; ip4(src).copy(h, 12); ip4(dst).copy(h, 16); return h;
}
function tcp(srcPort, dstPort, seq, ack, flags) {
  const h = Buffer.alloc(20); h.writeUInt16BE(srcPort, 0); h.writeUInt16BE(dstPort, 2); h.writeUInt32BE(seq >>> 0, 4); h.writeUInt32BE(ack >>> 0, 8); h[12] = 0x50; h[13] = flags; h.writeUInt16BE(65535, 14); return h;
}
function udp(srcPort, dstPort, length) { const b = Buffer.alloc(8); b.writeUInt16BE(srcPort, 0); b.writeUInt16BE(dstPort, 2); b.writeUInt16BE(length + 8, 4); return b; }
function tlsHello(domain) {
  const name = Buffer.from(domain), entry = Buffer.concat([Buffer.from([0]), u16(name.length), name]);
  const sni = Buffer.concat([u16(entry.length), entry]); const ext = Buffer.concat([u16(0), u16(sni.length), sni]);
  const extensions = Buffer.concat([u16(ext.length), ext]);
  const body = Buffer.concat([Buffer.from([3,3]), Buffer.alloc(32, 7), Buffer.from([0]), u16(4), Buffer.from([0x13,1,0x13,2]), Buffer.from([1,0]), extensions]);
  const handshake = Buffer.concat([Buffer.from([1, (body.length >>> 16) & 255, (body.length >>> 8) & 255, body.length & 255]), body]);
  return Buffer.concat([Buffer.from([0x16,3,1]), u16(handshake.length), handshake]);
}
function u16(n) { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; }
function dnsQuery(domain, id) {
  const labels = domain.split('.').map(x => Buffer.concat([Buffer.from([Buffer.byteLength(x)]), Buffer.from(x)]));
  const q = Buffer.concat([...labels, Buffer.from([0]), Buffer.from([0,1,0,1])]);
  const h = Buffer.alloc(12); h.writeUInt16BE(id, 0); h.writeUInt16BE(0x0100, 2); h.writeUInt16BE(1, 4); return Buffer.concat([h, q]);
}
function packet(srcMac, dstMac, srcIp, dstIp, proto, transport, payload, id) {
  const data = Buffer.concat([ethernet(srcMac, dstMac), ipv4(srcIp, dstIp, proto, transport.length + payload.length, id), transport, payload]);
  const header = Buffer.alloc(16); header.writeUInt32LE(1700000000 + id, 0); header.writeUInt32LE(0, 4); header.writeUInt32LE(data.length, 8); header.writeUInt32LE(data.length, 12); return Buffer.concat([header, data]);
}
function main() {
  const records = []; let id = 1, seq = 1000;
  const srcMac = '00:11:22:33:44:55', dstMac = 'aa:bb:cc:dd:ee:ff', local = '192.168.1.100';
  const sites = [['142.250.185.206','www.youtube.com'], ['157.240.1.35','www.facebook.com'], ['www.google.com','142.250.185.110'], ['140.82.114.4','github.com']];
  for (const [ip, domain] of sites) {
    const srcPort = 50000 + id;
    records.push(packet(srcMac,dstMac,local,ip,6,tcp(srcPort,443,seq,0,2),Buffer.alloc(0),id++));
    const hello = tlsHello(domain);
    records.push(packet(srcMac,dstMac,local,ip,6,tcp(srcPort,443,seq+1,1,0x18),hello,id++)); seq += 10000;
  }
  const http = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DPI-Test/1.0\r\n\r\n');
  records.push(packet(srcMac,dstMac,local,'93.184.216.34',6,tcp(51000,80,seq,0,0x18),http,id++));
  for (const domain of ['www.google.com','www.youtube.com','api.twitter.com','github.com']) {
    const q = dnsQuery(domain,id); records.push(packet(srcMac,dstMac,local,'8.8.8.8',17,udp(52000+id,53,q.length),q,id++));
  }
  for (let i=0;i<5;i++) records.push(packet(srcMac,dstMac,'192.168.1.50','172.217.0.100',6,tcp(53000+i,443,seq+i,0,2),Buffer.alloc(0),id++));
  const global = Buffer.alloc(24); global.writeUInt32LE(0xa1b2c3d4,0); global.writeUInt16LE(2,4); global.writeUInt16LE(4,6); global.writeUInt32LE(65535,16); global.writeUInt32LE(1,20);
  const out = path.resolve(process.argv[2] || 'test_dpi.pcap'); fs.writeFileSync(out,Buffer.concat([global,...records])); console.log(`Created ${out} (${records.length} packets)`);
}
main();
