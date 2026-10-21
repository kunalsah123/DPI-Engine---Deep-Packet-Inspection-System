'use strict';
const path = require('node:path');
const { readPcapFile, writePcapFile } = require('./pcap_reader');
const { parsePacket } = require('./packet_parser');
const { RuleManager } = require('./rule_manager');
const { ConnectionTracker } = require('./connection_tracker');
const { LoadBalancer } = require('./load_balancer');
const { FastPath } = require('./fast_path');

class DPIEngine {
  constructor(config = {}) {
    this.config = { loadBalancers: config.loadBalancers || 1, fastPathsPerBalancer: config.fastPathsPerBalancer || 1, maxConnections: config.maxConnections || 100000, ...config };
    this.rules = config.ruleManager || new RuleManager(config.blocks);
    this.tracker = new ConnectionTracker({ maxConnections: this.config.maxConnections, timeoutMs: this.config.flowTimeoutMs });
    this.loadBalancer = new LoadBalancer(this.config);
    this.applications = Object.create(null); this.domains = Object.create(null); this.blockedReasons = Object.create(null);
    this.stats = { totalPackets: 0, totalBytes: 0, tcpPackets: 0, udpPackets: 0, dropped: 0, parseErrors: 0, unsupportedLink: 0 };
    this.fastPaths = Array.from(
      { length: this.config.loadBalancers * this.config.fastPathsPerBalancer },
      () => new FastPath({ rules: this.rules, tracker: this.tracker, onDecision: decision => this.recordDecision(decision) })
    );
  }
  recordDecision(decision) {
    const app = decision.app || 'Unknown'; this.applications[app] = (this.applications[app] || 0) + 1;
    if (decision.domain) this.domains[decision.domain] = (this.domains[decision.domain] || 0) + 1;
    if (decision.action === 'drop') {
      this.stats.dropped++;
      const reason = `${decision.reason.type} ${decision.reason.detail}`;
      this.blockedReasons[reason] = (this.blockedReasons[reason] || 0) + 1;
    }
  }
  processFile(inputFile, outputFile, { maxPackets = Infinity } = {}) {
    const input = path.resolve(inputFile), output = outputFile ? path.resolve(outputFile) : null;
    if (output && input === output) throw new Error('Input and output paths must be different.');
    const capture = readPcapFile(input);
    const packets = capture.packets.slice(0, maxPackets), forwardedRecords = [];
    for (const record of packets) {
      this.stats.totalPackets++; this.stats.totalBytes += record.capturedLength;
      const packet = parsePacket(record.data, capture.linkType);
      if (packet.unsupportedLink) { this.stats.unsupportedLink++; forwardedRecords.push(record.record); continue; }
      if (packet.protocol === 6) this.stats.tcpPackets++;
      if (packet.protocol === 17) this.stats.udpPackets++;
      if (!packet.src || ![6, 17].includes(packet.protocol)) { forwardedRecords.push(record.record); continue; }
      packet.packetBytes = record.capturedLength;
      const route = this.loadBalancer.route(packet);
      const fastPathId = route.loadBalancer * this.config.fastPathsPerBalancer + route.fastPath;
      const decision = this.fastPaths[fastPathId].process(packet);
      if (decision.action === 'forward') forwardedRecords.push(record.record);
    }
    if (output) writePcapFile(output, capture.buffer, forwardedRecords);
    return {
      input, output,
      pcap: { version: `${capture.littleEndian ? 'LE' : 'BE'}${capture.nanosecondTimestamps ? ' nanosecond' : ''}`, linkType: capture.linkType },
      stats: { ...this.stats }, forwardedPackets: forwardedRecords.length,
      applications: { ...this.applications }, domains: { ...this.domains },
      blockedReasons: { ...this.blockedReasons }, flows: this.tracker.flows.size,
      flowStats: this.tracker.stats(), workers: this.loadBalancer.stats()
    };
  }
}
module.exports = { DPIEngine };
