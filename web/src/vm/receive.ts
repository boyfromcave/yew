// Receive (receive.dart): Private / Public / YED; the address, a QR, a new private address.
import type { AddressKind, Core } from "../core";
import { messageOf } from "../core";
import { Vm } from "./base";
export interface ReceiveState { kind: AddressKind; address: string; error: string }
export class ReceiveVm extends Vm<ReceiveState> {
  constructor(private core: Core) { super({ kind: "shielded", address: "", error: "" }); }
  async show(kind: AddressKind) {
    this.set({ kind });
    try { this.set({ address: await this.core.receive_address(kind), error: "" }); } catch (e) { this.set({ address: "", error: messageOf(e) }); }
  }
  async fresh() {
    try { this.set({ address: await this.core.new_shielded_address(), kind: "shielded", error: "" }); } catch (e) { this.set({ error: messageOf(e) }); }
  }
}
