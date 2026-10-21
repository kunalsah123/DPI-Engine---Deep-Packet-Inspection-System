'use strict';
const { canonicalTupleKey } = require('./types');

class ConnectionTracker {
  constructor({ maxConnections = 100000, timeoutMs = 300000 } = {}) {
    this.maxConnections = maxConnections; this.timeoutMs = timeoutMs;
    this.flows = new Map(); this.totalSeen = 0;
  }
  getOrCreate(packet, now = Date.now()) {
    const key = canonicalTupleKey(packet);
    let flow = this.flows.get(key);
    if (!flow) {
      if (this.flows.size >= this.maxConnections) this.evictOldest();
      flow = { key, app: null, domain: null, blocked: false, packets: 0, bytes: 0, firstSeen: now, lastSeen: now };
      this.flows.set(key, flow); this.totalSeen++;
    }
    flow.packets++; flow.bytes += packet.packetBytes || 0; flow.lastSeen = now;
    return flow;
  }
  get(packet) { return this.flows.get(canonicalTupleKey(packet)) || null; }
  close(packet) { return this.flows.delete(canonicalTupleKey(packet)); }
  cleanupStale(now = Date.now()) {
    let removed = 0;
    for (const [key, flow] of this.flows) if (now - flow.lastSeen > this.timeoutMs) { this.flows.delete(key); removed++; }
    return removed;
  }
  evictOldest() {
    let oldestKey = null, oldestTime = Infinity;
    for (const [key, flow] of this.flows) if (flow.lastSeen < oldestTime) { oldestKey = key; oldestTime = flow.lastSeen; }
    if (oldestKey !== null) this.flows.delete(oldestKey);
  }
  stats() {
    let classified = 0, blocked = 0;
    for (const flow of this.flows.values()) { if (flow.app || flow.domain) classified++; if (flow.blocked) blocked++; }
    return { activeConnections: this.flows.size, totalConnectionsSeen: this.totalSeen, classifiedConnections: classified, blockedConnections: blocked };
  }
  values() { return [...this.flows.values()]; }
}
module.exports = { ConnectionTracker };
