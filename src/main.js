#!/usr/bin/env node
'use strict';
const { DPIEngine } = require('./dpi_engine');
const { RuleManager } = require('./rule_manager');

function parseArgs(args) {
  const options = { blocks: { app: [], ip: [], domain: [], port: [] }, maxPackets: Infinity };
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (['--block-app', '--block-ip', '--block-domain', '--block-port'].includes(arg)) {
      const value = args[++i]; if (!value) throw new Error(`Missing value for ${arg}`);
      options.blocks[arg.slice(8)].push(value);
    } else if (arg === '--max-packets') {
      options.maxPackets = Number(args[++i]);
      if (!Number.isInteger(options.maxPackets) || options.maxPackets < 1) throw new Error('--max-packets must be a positive integer.');
    } else if (arg === '--json') options.json = true;
    else if (arg === '--lbs') options.loadBalancers = Number(args[++i]);
    else if (arg === '--fps') options.fastPathsPerBalancer = Number(args[++i]);
    else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else positional.push(arg);
  }
  [options.input, options.output] = positional;
  if (!options.help && !options.input) throw new Error('Input PCAP path is required.');
  return options;
}
function help() {
  return `Packet Analyzer DPI (Node.js)\n\nUsage: npm start -- <input.pcap> [output.pcap] [options]\n\nOptions:\n  --block-app <name>     Drop flows matching an application (repeatable)\n  --block-ip <address>   Drop packets from a source IP (repeatable)\n  --block-domain <text>  Drop flows whose detected domain contains text\n  --block-port <port>    Drop packets with this source or destination port\n  --max-packets <count>  Process at most count packets\n  --lbs <count>          Number of logical load-balancer shards (default: 1)\n  --fps <count>          Fast-path shards per load balancer (default: 1)\n  --json                 Print machine-readable JSON summary\n  -h, --help             Show help\n\nWithout an output path the capture is analyzed without writing a filtered PCAP.\n`;
}
function printReport(result) {
  console.log(`DPI Engine — Node.js\nInput: ${result.input}${result.output ? `\nOutput: ${result.output}` : ''}`);
  console.log(`Packets: ${result.stats.totalPackets} | TCP: ${result.stats.tcpPackets} | UDP: ${result.stats.udpPackets} | Bytes: ${result.stats.totalBytes}`);
  console.log(`Forwarded: ${result.forwardedPackets} | Dropped: ${result.stats.dropped} | Flows: ${result.flows}`);
  if (Object.keys(result.applications).length) { console.log('\nApplications:'); for (const [app, count] of Object.entries(result.applications).sort((a, b) => b[1] - a[1])) console.log(`  ${app.padEnd(14)} ${count}`); }
  if (Object.keys(result.domains).length) { console.log('\nDetected domains:'); for (const [domain, count] of Object.entries(result.domains).sort((a, b) => b[1] - a[1])) console.log(`  ${domain} (${count})`); }
  if (result.stats.unsupportedLink) console.log(`\nUnsupported link-layer packets passed through: ${result.stats.unsupportedLink}`);
}
function run(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  if (options.help) { console.log(help()); return null; }
  const rules = new RuleManager(options.blocks);
  const engine = new DPIEngine({ ruleManager: rules, loadBalancers: options.loadBalancers || 1, fastPathsPerBalancer: options.fastPathsPerBalancer || 1 });
  const result = engine.processFile(options.input, options.output, { maxPackets: options.maxPackets });
  if (options.json) console.log(JSON.stringify(result, null, 2)); else printReport(result);
  return result;
}
if (require.main === module) {
  try { run(); }
  catch (error) { console.error(`Error: ${error.message}\n\n${help()}`); process.exitCode = 1; }
}
module.exports = { parseArgs, help, run, printReport };
