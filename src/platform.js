'use strict';

const LINK_TYPES = Object.freeze({ NULL: 0, ETHERNET: 1, RAW: 101, IPV4: 228, IPV6: 229 });
function isSupportedLinkType(linkType) { return [LINK_TYPES.ETHERNET, LINK_TYPES.RAW, LINK_TYPES.IPV4, LINK_TYPES.IPV6].includes(linkType); }
function describePlatform() { return { os: process.platform, arch: process.arch, node: process.version, liveCapture: false }; }
module.exports = { LINK_TYPES, isSupportedLinkType, describePlatform };
