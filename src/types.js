'use strict';

const APPLICATION_SIGNATURES = [
  ['YouTube', /youtube|ytimg|youtu\.be/], ['Google', /google|gstatic|googleapis|ggpht|gvt1/],
  ['Facebook', /facebook|fbcdn|fb\.com|fbsbx|meta\.com/], ['Instagram', /instagram|cdninstagram/],
  ['WhatsApp', /whatsapp|wa\.me/], ['Twitter/X', /twitter|twimg|x\.com|t\.co/],
  ['Netflix', /netflix|nflxvideo|nflximg/], ['Amazon', /amazon|cloudfront|amazonaws|aws/],
  ['Microsoft', /microsoft|msn\.com|office|azure|live\.com|outlook|bing/],
  ['Apple', /apple|icloud|mzstatic|itunes/], ['Telegram', /telegram|t\.me/],
  ['TikTok', /tiktok|musical\.ly|bytedance/], ['Spotify', /spotify|scdn\.co/],
  ['Zoom', /zoom/], ['Discord', /discord/], ['GitHub', /github/], ['Cloudflare', /cloudflare|cf-/]
];

function classifyDomain(domain, fallback = 'HTTPS') {
  if (!domain) return 'Unknown';
  const name = String(domain).toLowerCase();
  return APPLICATION_SIGNATURES.find(([, pattern]) => pattern.test(name))?.[0] || fallback;
}

function normalize(value) { return String(value ?? '').trim().toLowerCase(); }
function tupleKey(packet) { return `${packet.src}|${packet.srcPort}|${packet.dst}|${packet.dstPort}|${packet.protocol}`; }
function reverseTupleKey(packet) { return `${packet.dst}|${packet.dstPort}|${packet.src}|${packet.srcPort}|${packet.protocol}`; }
function canonicalTupleKey(packet) { return [tupleKey(packet), reverseTupleKey(packet)].sort().join('<>'); }

module.exports = { APPLICATION_SIGNATURES, classifyDomain, normalize, tupleKey, reverseTupleKey, canonicalTupleKey };
