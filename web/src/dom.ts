// A tiny DOM helper and a hash router: enough for six screens, no framework (plan W1: "plain
// TS + a tiny router"). CSP: no inline scripts or style attributes; classes only, and the few
// dynamic sizes go through the CSSOM (`el.style.width`), which the policy allows.
type Child = Node | string | null | undefined | false | Child[];
type Attrs = Record<string, unknown> & { class?: string; on?: Record<string, EventListener> };

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs | null = null, ...children: Child[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "on") for (const [ev, fn] of Object.entries(v as Record<string, EventListener>)) el.addEventListener(ev, fn);
    else if (k === "class") el.className = v as string;
    else if (k in el && k !== "list") (el as unknown as Record<string, unknown>)[k] = v;
    else el.setAttribute(k, String(v));
  }
  append(el, children);
  return el;
}
function append(el: Node, children: Child[]) {
  for (const c of children) {
    if (c == null || c === false) continue;
    if (Array.isArray(c)) append(el, c);
    else el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
}
export function clear(el: Element) { while (el.firstChild) el.removeChild(el.firstChild); }

export type Route = { name: string; arg: string };
export function currentRoute(): Route {
  const [name = "home", arg = ""] = location.hash.replace(/^#\/?/, "").split("/");
  return { name: name || "home", arg: decodeURIComponent(arg) };
}
export function go(name: string, arg = "") { location.hash = arg ? `/${name}/${encodeURIComponent(arg)}` : `/${name}`; }
export function onRoute(fn: (r: Route) => void) { addEventListener("hashchange", () => fn(currentRoute())); fn(currentRoute()); }

export async function copy(text: string, btn?: HTMLButtonElement) {
  try { await navigator.clipboard.writeText(text); if (btn) { const t = btn.textContent; btn.textContent = "Copied"; setTimeout(() => (btn.textContent = t), 1200); } } catch { /* clipboard refused: the text is selectable */ }
}

/** Append children (nulls and nested arrays allowed) to a root. */
export function mount(root: Element, ...children: Child[]) { append(root, children); }
