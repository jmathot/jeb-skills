// Local-directory discovery resolves index.js; package consumers use exports.
// Both entrypoints load the same compiled plugin definition.
export { default } from "./dist/index.js"
