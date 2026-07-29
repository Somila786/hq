// Test-only D1 adapter.
//
// Wraps Node's built-in `node:sqlite` so it matches Cloudflare D1's
// `.prepare().bind().first()/.all()/.run()` API exactly. Tests therefore
// exercise the real `src/` code against a real SQLite engine rather than a
// mock or a reimplementation of the query layer.
//
// Deliberately dependency-free -- see CLAUDE.md, "Testing".

import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const SCHEMA = readFileSync(join(HERE, "..", "schema.sql"), "utf8");

// node:sqlite only accepts null | number | bigint | string | Uint8Array.
// D1 is more forgiving (booleans and undefined arrive from form handling),
// so normalise here rather than contorting the application code.
function normalize(v) {
  if (v === undefined) return null;
  if (typeof v === "boolean") return v ? 1 : 0;
  return v;
}

class D1Statement {
  constructor(db, sql, params = []) {
    this.db = db;
    this.sql = sql;
    this.params = params;
  }

  // D1's bind() is non-mutating: it returns a new bound statement.
  bind(...args) {
    return new D1Statement(this.db, this.sql, args.map(normalize));
  }

  async first(column) {
    const row = this.db.prepare(this.sql).get(...this.params);
    if (row === undefined) return null;
    return column === undefined ? row : row[column];
  }

  async all() {
    const results = this.db.prepare(this.sql).all(...this.params);
    return { results, success: true, meta: {} };
  }

  async run() {
    const info = this.db.prepare(this.sql).run(...this.params);
    return {
      success: true,
      meta: {
        changes: Number(info.changes),
        last_row_id: Number(info.lastInsertRowid),
      },
    };
  }
}

class D1Database {
  constructor(db) {
    this.db = db;
  }
  prepare(sql) {
    return new D1Statement(this.db, sql);
  }
  async batch(statements) {
    const out = [];
    for (const s of statements) out.push(await s.run());
    return out;
  }
  async exec(sql) {
    this.db.exec(sql);
  }
}

// A fresh in-memory database with the live schema applied.
export function makeEnv() {
  const db = new DatabaseSync(":memory:");
  db.exec(SCHEMA);
  return { DB: new D1Database(db), __raw: db };
}
