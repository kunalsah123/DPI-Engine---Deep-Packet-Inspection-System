'use strict';
const { normalize } = require('./types');

class RuleManager {
  constructor(initial = {}) {
    this.blockedIPs = new Set((initial.ip || []).map(normalize));
    this.blockedApps = new Set((initial.app || []).map(normalize));
    this.blockedDomains = (initial.domain || []).map(normalize);
    this.blockedPorts = new Set((initial.port || []).map(Number));
  }
  addIP(value) { this.blockedIPs.add(normalize(value)); }
  addApp(value) { this.blockedApps.add(normalize(value)); }
  addDomain(value) { this.blockedDomains.push(normalize(value)); }
  addPort(value) {
    const port = Number(value);
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`Invalid port: ${value}`);
    this.blockedPorts.add(port);
  }
  removeIP(value) { return this.blockedIPs.delete(normalize(value)); }
  removeApp(value) { return this.blockedApps.delete(normalize(value)); }
  removeDomain(value) { const before = this.blockedDomains.length; this.blockedDomains = this.blockedDomains.filter(item => item !== normalize(value)); return this.blockedDomains.length !== before; }
  removePort(value) { return this.blockedPorts.delete(Number(value)); }
  check(packet, flow) {
    if (this.blockedIPs.has(normalize(packet.src))) return { type: 'ip', detail: packet.src };
    if (this.blockedPorts.has(packet.srcPort) || this.blockedPorts.has(packet.dstPort)) return { type: 'port', detail: String(this.blockedPorts.has(packet.dstPort) ? packet.dstPort : packet.srcPort) };
    if (flow.domain) {
      const pattern = this.blockedDomains.find(rule => flow.domain.includes(rule));
      if (pattern) return { type: 'domain', detail: flow.domain };
    }
    if (flow.app && this.blockedApps.has(normalize(flow.app))) return { type: 'app', detail: flow.app };
    return null;
  }
  toJSON() { return { ip: [...this.blockedIPs], app: [...this.blockedApps], domain: [...this.blockedDomains], port: [...this.blockedPorts] }; }
}
module.exports = { RuleManager };
