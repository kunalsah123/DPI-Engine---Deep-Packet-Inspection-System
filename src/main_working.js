'use strict';
// Backward-compatible entry point; packet processing is implemented by DPIEngine.
const { run } = require('./main');
module.exports = { run };
if (require.main === module) run();
