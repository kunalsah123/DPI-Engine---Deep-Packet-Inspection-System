'use strict';
const { canonicalTupleKey } = require('./types');

function hashString(value) {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i++) { hash ^= value.charCodeAt(i); hash = Math.imul(hash, 16777619); }
  return hash >>> 0;
}
class LoadBalancer {
  constructor({ loadBalancers = 1, fastPathsPerBalancer = 1 } = {}) {
    if (loadBalancers < 1 || fastPathsPerBalancer < 1) throw new Error('Load balancer and fast path counts must be positive.');
    this.loadBalancers = loadBalancers; this.fastPathsPerBalancer = fastPathsPerBalancer;
    this.dispatchCounts = Array(loadBalancers).fill(0);
    this.fastPathCounts = Array.from({ length: loadBalancers }, () => Array(fastPathsPerBalancer).fill(0));
  }
  route(packet) {
    const hash = hashString(canonicalTupleKey(packet));
    const lb = hash % this.loadBalancers;
    const fp = Math.floor(hash / this.loadBalancers) % this.fastPathsPerBalancer;
    this.dispatchCounts[lb]++; this.fastPathCounts[lb][fp]++;
    return { loadBalancer: lb, fastPath: fp };
  }
  stats() { return { loadBalancers: this.dispatchCounts.map((packets, id) => ({ id, packets })), fastPaths: this.fastPathCounts.flatMap((items, lb) => items.map((packets, fp) => ({ id: lb * this.fastPathsPerBalancer + fp, loadBalancer: lb, packets }))) }; }
}
module.exports = { LoadBalancer, hashString };
