'use strict';
const { inspectPayload } = require('./sni_extractor');

class FastPath {
  constructor({ rules, tracker, onDecision } = {}) {
    this.rules = rules; this.tracker = tracker; this.onDecision = onDecision || (() => {});
    this.stats = { processed: 0, forwarded: 0, dropped: 0 };
  }
  process(packet) {
    this.stats.processed++;
    if (!packet.src || ![6, 17].includes(packet.protocol)) { this.stats.forwarded++; return { action: 'forward', reason: null, flow: null, app: 'Unknown', domain: null }; }
    const flow = this.tracker.getOrCreate(packet);
    const inspection = inspectPayload(packet);
    if (inspection.domain) flow.domain = inspection.domain;
    if (inspection.app !== 'Unknown' && (!flow.app || inspection.domain)) flow.app = inspection.app;
    const reason = flow.blocked ? { type: 'flow', detail: 'previously blocked flow' } : this.rules.check(packet, flow);
    if (reason) flow.blocked = true;
    const action = reason ? 'drop' : 'forward';
    this.stats[action === 'drop' ? 'dropped' : 'forwarded']++;
    const decision = { action, reason, flow, app: flow.app || inspection.app, domain: flow.domain };
    this.onDecision(decision, packet);
    return decision;
  }
}
module.exports = { FastPath };
