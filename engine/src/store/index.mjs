// Storage adapters and a small factory.
import { EngineError } from '../errors.mjs';
import { createMemoryStore } from './memory.mjs';
import { createFileStore } from './file.mjs';
import { createSqliteStore, sqliteAvailable } from './sqlite.mjs';

export { createMemoryStore, createFileStore, createSqliteStore, sqliteAvailable };

/** openStore('memory') | { type: 'memory' } | { type: 'file', dir } | { type: 'sqlite', path?, db?, prefix? } */
export function openStore(spec) {
  if (spec === 'memory') return createMemoryStore();
  if (spec && typeof spec === 'object') {
    if (spec.type === 'memory') return createMemoryStore();
    if (spec.type === 'file') return createFileStore(spec.dir);
    if (spec.type === 'sqlite') return createSqliteStore({ path: spec.path, db: spec.db, prefix: spec.prefix });
  }
  throw new EngineError('bad_store', 'unknown store specification');
}
