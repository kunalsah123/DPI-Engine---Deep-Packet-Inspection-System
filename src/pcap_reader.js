'use strict';
const fs = require('node:fs');

function parsePcap(buffer) {
  if (!Buffer.isBuffer(buffer)) buffer = Buffer.from(buffer);
  if (buffer.length < 24) throw new Error('File is too short to contain a PCAP global header.');
  const magic = buffer.subarray(0, 4).toString('hex');
  const formats = {
    d4c3b2a1: [true, false], a1b2c3d4: [false, false],
    '4d3cb2a1': [true, true], 'a1b23c4d': [false, true]
  };
  const format = formats[magic];
  if (!format) throw new Error(`Unsupported PCAP magic number: ${magic}`);
  const [littleEndian, nanosecondTimestamps] = format;
  const read32 = littleEndian ? 'readUInt32LE' : 'readUInt32BE';
  const network = buffer[read32](20);
  const packets = [];
  let offset = 24;
  while (offset < buffer.length) {
    if (offset + 16 > buffer.length) throw new Error(`Truncated packet header at byte ${offset}.`);
    const seconds = buffer[read32](offset);
    const fraction = buffer[read32](offset + 4);
    const capturedLength = buffer[read32](offset + 8);
    const originalLength = buffer[read32](offset + 12);
    offset += 16;
    if (capturedLength > buffer.length - offset) throw new Error(`Truncated packet data at byte ${offset}.`);
    const data = buffer.subarray(offset, offset + capturedLength);
    const record = buffer.subarray(offset - 16, offset + capturedLength);
    packets.push({ seconds, fraction, capturedLength, originalLength, data, record });
    offset += capturedLength;
  }
  return { packets, littleEndian, nanosecondTimestamps, network, linkType: network };
}

function readPcapFile(filename) {
  const buffer = fs.readFileSync(filename);
  return { buffer, ...parsePcap(buffer) };
}
function writePcapBuffer(original, records) { return Buffer.concat([original.subarray(0, 24), ...records]); }
function writePcapFile(filename, original, records) { fs.writeFileSync(filename, writePcapBuffer(original, records)); }

module.exports = { parsePcap, readPcapFile, writePcapBuffer, writePcapFile };
