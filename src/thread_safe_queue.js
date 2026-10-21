'use strict';

class ThreadSafeQueue {
  constructor(maxSize = 10000) {
    if (!Number.isInteger(maxSize) || maxSize < 1) throw new Error('Queue maxSize must be a positive integer.');
    this.maxSize = maxSize; this.items = []; this.waitingReaders = []; this.waitingWriters = []; this.closed = false;
  }
  async push(item) {
    if (this.closed) throw new Error('Queue is closed.');
    if (this.waitingReaders.length) { this.waitingReaders.shift().resolve(item); return; }
    while (this.items.length >= this.maxSize && !this.closed) await new Promise((resolve, reject) => this.waitingWriters.push({ resolve, reject }));
    if (this.closed) throw new Error('Queue is closed.');
    this.items.push(item);
  }
  async pop() {
    if (this.items.length) { const value = this.items.shift(); this.releaseWriter(); return value; }
    if (this.closed) return null;
    return new Promise(resolve => this.waitingReaders.push({ resolve }));
  }
  releaseWriter() { this.waitingWriters.shift()?.resolve(); }
  close() {
    this.closed = true;
    for (const reader of this.waitingReaders.splice(0)) reader.resolve(null);
    for (const writer of this.waitingWriters.splice(0)) writer.reject(new Error('Queue is closed.'));
  }
  get size() { return this.items.length; }
}
module.exports = { ThreadSafeQueue };
