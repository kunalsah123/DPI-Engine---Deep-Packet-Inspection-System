'use strict';
// Backward-compatible entry point for the former single-threaded implementation.
const { run } = require('./main');
module.exports = { run };
if (require.main === module) run();
