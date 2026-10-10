// View-models: the screens' state and intents, free of the DOM so vitest can drive them against
// MockCore. A screen renders `state` and calls the actions; `subscribe` re-renders on change.
export class Vm<S extends object> {
  private listeners = new Set<() => void>();
  constructor(public state: S) {}
  set(patch: Partial<S>) { Object.assign(this.state, patch); for (const l of this.listeners) l(); }
  subscribe(l: () => void): () => void { this.listeners.add(l); return () => this.listeners.delete(l); }
}
