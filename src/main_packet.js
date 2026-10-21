#!/usr/bin/env node
'use strict';
const { readPcapFile } = require('./pcap_reader');
const { parsePacket } = require('./packet_parser');

function run(args = process.argv.slice(2)) {
  const [filename, maxArg] = args;
  if (!filename || args.includes('--help') || args.includes('-h')) {
    console.log('Usage: node src/main_packet.js <capture.pcap> [max-packets]');
    return null;
  }
  const maxPackets = maxArg ? Number(maxArg) : Infinity;
  if (!(maxPackets > 0)) throw new Error('max-packets must be a positive number.');
  const capture = readPcapFile(filename), packets = capture.packets.slice(0, maxPackets);
  let errors = 0;
  packets.forEach((record, index) => {
    const parsed = parsePacket(record.data, capture.linkType);
    console.log(`\n--- Packet #${index + 1} | ${record.seconds}.${String(record.fraction).padStart(6, '0')} | ${record.capturedLength} bytes ---`);
    if (!parsed.src || !parsed.protocol) { console.log(`Unparsed or non-IP frame (link type ${capture.linkType})`); errors++; return; }
    console.log(`${parsed.src}:${parsed.srcPort || '-'} -> ${parsed.dst}:${parsed.dstPort || '-'} (${parsed.protocol === 6 ? 'TCP' : parsed.protocol === 17 ? 'UDP' : `IP protocol ${parsed.protocol}`})`);
    if (parsed.tcpFlags !== undefined) console.log(`TCP flags: 0x${parsed.tcpFlags.toString(16).padStart(2, '0')}`);
    const payload = parsed.payload || Buffer.alloc(0);
    if (payload.length) console.log(`Payload: ${payload.length} bytes | ${payload.subarray(0, 32).toString('hex').match(/.{1,2}/g)?.join(' ') || ''}${payload.length > 32 ? ' ...' : ''}`);
  });
  console.log(`\nSummary: ${packets.length} packets displayed, ${errors} unparsed/non-IP frames.`);
  return { packets: packets.length, errors };
}
if (require.main === module) {
  try { run(); } catch (error) { console.error(`Error: ${error.message}`); process.exitCode = 1; }
}
module.exports = { run };
