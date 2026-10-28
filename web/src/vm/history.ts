// History (history.dart): one list, both assets, verdict labels, memos; pages of the core.
import type { Core, HistoryRow } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";
export interface HistoryState { rows: HistoryRow[]; page: number; more: boolean; error: string; open: HistoryRow | null }
export class HistoryVm extends Vm<HistoryState> {
  constructor(private core: Core) { super({ rows: [], page: 0, more: true, error: "", open: null }); }
  async load(page = 0) {
    try {
      const rows = await this.core.history(page);
      this.set({ rows: page === 0 ? rows : [...this.state.rows, ...rows], page, more: rows.length > 0, error: "" });
    } catch (e) { this.set({ error: messageOf(e) }); }
  }
  more() { return this.state.more ? this.load(this.state.page + 1) : Promise.resolve(); }
  openRow(row: HistoryRow | null) { this.set({ open: row }); }
}
