// One error type for the whole engine: a stable machine code, a plain message and an HTTP status.
export class EngineError extends Error {
  constructor(code, message, status = 400) { super(message || code); this.name = 'EngineError'; this.code = code; this.status = status; }
}
export const fail = (code, message, status) => { throw new EngineError(code, message, status); };
