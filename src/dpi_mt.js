#!/usr/bin/env node
'use strict';
const { run: runCli } = require('./main');
function run(args = process.argv.slice(2)) {
  const hasLbs = args.includes('--lbs'), hasFps = args.includes('--fps');
  return runCli([...(hasLbs ? [] : ['--lbs', '2']), ...(hasFps ? [] : ['--fps', '2']), ...args]);
}
if (require.main === module) {
  try { run(); } catch (error) { console.error(`Error: ${error.message}`); process.exitCode = 1; }
}
module.exports = { run };
