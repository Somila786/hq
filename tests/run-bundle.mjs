// Runs the full suite against dist/worker.js (the single-file dashboard build)
// instead of src/. Exists as its own file rather than an inline env var so the
// npm script works identically on Windows, macOS and Linux.
//
//   npm run test:bundle
//
// A pass here means the pasted-into-the-dashboard build behaves exactly like
// the source tree. If it fails while `npm test` passes, the bundler in
// tests/bundle.mjs is at fault, not the app.

process.env.TEST_TARGET = "../dist/worker.js";
await import("./run.mjs");
