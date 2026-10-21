'use strict';
const { parseArgs, help, run, printReport } = require('./main');
module.exports = { parseArgs, help, run, printReport };
if (require.main === module) run();
