// Dev placeholder: Metro's symbolicator sometimes attempts to read an InternalBytecode.js
// file when symbolicating native error stacks. Some environments don't provide it and
// Metro throws ENOENT. This empty module prevents that error during development.

// NOTE: This file is a harmless shim for development only. It should not be required
// for production builds. If your toolchain later provides a real InternalBytecode
// implementation, you can remove this file.

module.exports = {};
