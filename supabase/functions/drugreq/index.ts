// ระบบเบิกยาห้องยา (Fixed stock) — Backend: Supabase Edge Function + Postgres
// Design & Developed by ภก.วทัญญู โตเจริญนิรัติศัย
// ใช้บัญชีพนักงานชุดเดียวกับระบบเบิกพัสดุห้องยา (docs coll='staff') แต่สิทธิ์แยกในตาราง fs_roles
// POST text/plain JSON {a:'action', token, ...}
import postgres from 'npm:postgres@3.4.4';

const sql = postgres(Deno.env.get('SUPABASE_DB_URL')!, { max: 3, prepare: false, idle_timeout: 20 });

const DEFAULT_PW = '12345678';
const TOKEN_MS = 12 * 3600 * 1000;
const RANK: Record<string, number> = { user: 1, pharm: 2, admin: 3 };

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
};
const out = (o: unknown) =>
  new Response(JSON.stringify(o), { headers: { ...CORS, 'Content-Type': 'application/json; charset=utf-8' } });

class E extends Error {}
const fail = (code: string): never => { throw new E(code); };

// ---------- crypto / auth (เข้ากันได้กับระบบเบิกพัสดุ) ----------
const enc = new TextEncoder();
const hex = (b: ArrayBuffer) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha = async (s: string) => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
let KEY: CryptoKey | null = null;
async function sign(s: string) {
  if (!KEY) {
    const r = await sql`select v from kv where k='SECRET'`;
    KEY = await crypto.subtle.importKey('raw', enc.encode('fs|' + r[0].v), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  }
  return hex(await crypto.subtle.sign('HMAC', KEY, enc.encode(s)));
}
async function getStaff(id: string) {
  const r = await sql`select data from docs where coll='staff' and id=${id}`;
  return r.length ? r[0].data : null;
}
async function roleOf(id: string) {
  const r = await sql`select role from fs_roles where emp_id=${id}`;
  return r.length ? r[0].role : 'user';
}
async function mkToken(id: string, st: any) {
  const ts = Date.now();
  return ts + '.' + id + '.' + (await sign(ts + '|' + id + '|' + (st.passHash || 'default')));
}
const pubUser = (id: string, st: any, role: string) => ({
  id, first: st.first || '', last: st.last || '', role, mustChange: !st.passHash,
});
async function auth(token: string) {
  const t = String(token || '').split('.');
  if (t.length !== 3) return null;
  if (Date.now() - Number(t[0]) > TOKEN_MS) return null;
  const st = await getStaff(t[1]);
  if (!st) return null;
  if ((await sign(t[0] + '|' + t[1] + '|' + (st.passHash || 'default'))) !== t[2]) return null;
  const role = await roleOf(t[1]);
  return { id: t[1], st, role, name: `${st.first || ''} ${st.last || ''}`.trim() || t[1] };
}
type Me = NonNullable<Awaited<ReturnType<typeof auth>>>;
const need = (me: Me, r: string) => { if (RANK[me.role] < RANK[r]) fail('forbidden'); };

async function login(req: any) {
  const id = String(req.id || '').replace(/\D/g, ''), h = String(req.h || '');
  const now = Date.now();
  const f = await sql`select n, until_ms from fails where id=${id}`;
  if (f.length && Number(f[0].until_ms) > now && f[0].n >= 8) return { ok: false, code: 'locked' };
  const st = await getStaff(id);
  let good = false;
  if (st) good = st.passHash ? st.passHash === h : h === (await sha('ch9sup|' + id + '|' + DEFAULT_PW));
  if (!good) {
    const n = f.length && Number(f[0].until_ms) > now ? f[0].n + 1 : 1;
    await sql`insert into fails(id,n,until_ms) values (${id},${n},${now + 600000})
              on conflict (id) do update set n=excluded.n, until_ms=excluded.until_ms`;
    return { ok: false, code: st ? 'bad_pw' : 'no_user' };
  }
  if (f.length) await sql`delete from fails where id=${id}`;
  const role = await roleOf(id);
  return { ok: true, token: await mkToken(id, st), user: pubUser(id, st, role) };
}

async function changePw(me: Me, req: any) {
  const h = String(req.h || '');
  if (!/^[0-9a-f]{64}$/.test(h)) fail('bad_request');
  return await sql.begin(async (q: any) => {
    await q`select pg_advisory_xact_lock(90210)`; // lock เดียวกับระบบเบิกพัสดุ
    const r = await q`select data from docs where coll='staff' and id=${me.id}`;
    const st = r[0].data;
    st.passHash = h; st.pwChangedAt = Date.now();
    await q`update docs set data=${JSON.stringify(st)}::text::jsonb, ver=${Date.now()} where coll='staff' and id=${me.id}`;
    await q`insert into colver(coll,ver) values ('staff',1) on conflict (coll) do update set ver = colver.ver + 1`;
    return { ok: true, token: await mkToken(me.id, st), user: pubUser(me.id, st, me.role) };
  });
}

const log = (q: any, me: Me, action: string, detail: unknown) =>
  q`insert into fs_log(emp_id, action, detail) values (${me.id}, ${action}, ${JSON.stringify(detail)}::text::jsonb)`;

// ---------- สูตรยอดเติม (เหมือนคอลัมน์ U ใน Excel) ----------
// G = Fixed (หน่วยจ่าย), K = ของที่มี (BF+ฉุกเฉิน-คืน), L = ยอดใช้, D = หน่วยจ่ายต่อหน่วยเบิก
function suggest(G: number, K: number, L: number, D: number) {
  if (!(G > 0)) return 0;
  const rem = K - L;
  if (D > G) return rem > G / 2 ? 0 : 1;
  if (G - rem <= 0) return 0;
  return Math.round((G - rem) / D);
}
const num = (v: unknown) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };
const code = (v: unknown) => String(v ?? '').trim().toUpperCase();
const dateOrNull = (v: unknown) => (/^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) ? String(v) : null);

// ---------- อ่านข้อมูล ----------
async function boot(me: Me, req: any) {
  const rooms = await sql`select code, name, sort, active from fs_rooms order by sort, code`;
  const since = req.since ? new Date(Number(req.since)) : null;
  const drugs = since
    ? await sql`select code, ps_code, name, pack::float8 pack, unit, supplier, buy, active, extract(epoch from updated_at)*1000 as u from fs_drugs where updated_at > ${since}`
    : await sql`select code, ps_code, name, pack::float8 pack, unit, supplier, buy, active, extract(epoch from updated_at)*1000 as u from fs_drugs`;
  const cnt = await sql`select count(*)::int n from fs_drugs`;
  const names: Record<string, string> = {};
  for (const s of await sql`select id, coalesce(data->>'first','') || ' ' || coalesce(data->>'last','') n from docs where coll='staff'`) names[s.id] = s.n.trim();
  return { ok: true, user: pubUser(me.id, me.st, me.role), rooms, drugs, drugCount: cnt[0].n, full: !since, names };
}

async function roomData(_me: Me, req: any) {
  const room = String(req.room || '');
  const fixed = await sql`select code, qty::float8 qty from fs_fixed where room=${room} and qty > 0`;
  const balance = await sql`select code, qty::float8 qty from fs_balance where room=${room}`;
  const moves = await sql`select id, code, kind, qty::float8 qty, note, created_by, created_at from fs_moves where room=${room} and round_id is null order by created_at desc`;
  const rounds = await sql`
    select r.id, r.room, r.period_start, r.period_end, r.req_date, r.status, r.note, r.created_by, r.created_at,
           r.approved_by, r.approved_at, r.received_by, r.received_at, r.usage_file,
           (select count(*)::int from fs_round_lines l where l.round_id=r.id and coalesce(l.adjust,l.suggest) > 0) as n_items
    from fs_rounds r where r.room=${room} order by r.created_at desc limit ${Math.min(num(req.limit) || 30, 200)}`;
  return { ok: true, fixed, balance, moves, rounds };
}

async function getRound(_me: Me, req: any) {
  const id = num(req.id);
  const r = await sql`select * from fs_rounds where id=${id}`;
  if (!r.length) fail('not_found');
  const lines = await sql`select code, fixed::float8 fixed, bf::float8 bf, emerg::float8 emerg, ret::float8 ret, usage::float8 usage,
                          suggest::float8 suggest, adjust::float8 adjust, cf::float8 cf from fs_round_lines where round_id=${id}`;
  const moves = await sql`select id, code, kind, qty::float8 qty, note, created_by, created_at from fs_moves where round_id=${id} order by created_at`;
  return { ok: true, round: r[0], lines, moves };
}

async function staffList(me: Me) {
  need(me, 'admin');
  const rows = await sql`select d.id, d.data->>'first' first, d.data->>'last' last, coalesce(r.role,'user') role
                         from docs d left join fs_roles r on r.emp_id=d.id where d.coll='staff' order by d.id`;
  return { ok: true, staff: rows };
}

async function usageReport(_me: Me, req: any) {
  const room = String(req.room || ''), n = Math.min(Math.max(num(req.n) || 8, 1), 52);
  const rows = await sql`
    with rr as (select id from fs_rounds where room=${room} and status in ('approved','received') order by created_at desc limit ${n})
    select l.code, count(*)::int rounds, avg(l.usage)::float8 avg, min(l.usage)::float8 min, max(l.usage)::float8 max,
           sum(case when l.fixed > 0 and l.bf + l.emerg - l.ret - l.usage < 0 then 1 else 0 end)::int short
    from fs_round_lines l join rr on rr.id=l.round_id group by l.code`;
  const cnt = await sql`select count(*)::int n from (select 1 from fs_rounds where room=${room} and status in ('approved','received') order by created_at desc limit ${n}) x`;
  return { ok: true, rows, rounds: cnt[0].n };
}

// ---------- รอบเบิก ----------
async function createRound(me: Me, req: any) {
  const room = String(req.room || '');
  const usageIn = req.usage || {};
  return await sql.begin(async (q: any) => {
    await q`select pg_advisory_xact_lock(hashtext('fs_room_' || ${room}))`;
    const rm = await q`select code from fs_rooms where code=${room} and active`;
    if (!rm.length) fail('bad_room');
    const open = await q`select id from fs_rounds where room=${room} and status='submitted'`;
    if (open.length) fail('open_round:' + open[0].id);

    const drugs = new Map<string, number>();
    for (const d of await q`select code, pack::float8 pack from fs_drugs`) drugs.set(d.code, d.pack > 0 ? d.pack : 1);
    const fixed = new Map<string, number>(), bal = new Map<string, number>();
    for (const r of await q`select code, qty::float8 qty from fs_fixed where room=${room}`) fixed.set(r.code, r.qty);
    for (const r of await q`select code, qty::float8 qty from fs_balance where room=${room}`) bal.set(r.code, r.qty);
    const moves = await q`select id, code, kind, qty::float8 qty from fs_moves where room=${room} and round_id is null`;
    const em = new Map<string, number>(), rt = new Map<string, number>();
    for (const m of moves) {
      const t = m.kind === 'emerg' ? em : rt;
      t.set(m.code, (t.get(m.code) || 0) + m.qty);
    }
    const usage = new Map<string, number>(), unknown: string[] = [];
    for (const k of Object.keys(usageIn)) {
      const c = code(k), v = num(usageIn[k]);
      if (!c) continue;
      if (!drugs.has(c)) { unknown.push(c); continue; }
      usage.set(c, (usage.get(c) || 0) + v);
    }
    const codes = new Set<string>();
    for (const [c, v] of fixed) if (v > 0) codes.add(c);
    for (const c of [...usage.keys(), ...bal.keys(), ...em.keys(), ...rt.keys()]) codes.add(c);

    const r = await q`insert into fs_rounds(room, period_start, period_end, req_date, note, usage_file, created_by)
      values (${room}, ${dateOrNull(req.period_start)}, ${dateOrNull(req.period_end)},
              coalesce(${dateOrNull(req.req_date)}::date, (now() at time zone 'Asia/Bangkok')::date), ${req.note || null}, ${req.file || null}, ${me.id})
      returning id`;
    const id = r[0].id;
    const lines = [];
    for (const c of codes) {
      const G = fixed.get(c) || 0;
      const bf = bal.has(c) ? bal.get(c)! : G; // ยังไม่มียอดยกมา = ถือว่าเริ่มเต็ม Fixed
      const e = em.get(c) || 0, t = rt.get(c) || 0, L = usage.get(c) || 0;
      lines.push({ round_id: id, code: c, fixed: G, bf, emerg: e, ret: t, usage: L, suggest: suggest(G, bf + e - t, L, drugs.get(c)!) });
    }
    for (let i = 0; i < lines.length; i += 1000) {
      const chunk = lines.slice(i, i + 1000);
      await q`insert into fs_round_lines ${q(chunk, 'round_id', 'code', 'fixed', 'bf', 'emerg', 'ret', 'usage', 'suggest')}`;
    }
    if (moves.length) await q`update fs_moves set round_id=${id} where id in ${q(moves.map((m: any) => m.id))}`;
    await log(q, me, 'createRound', { id, room, lines: lines.length, unknown: unknown.length });
    return { ok: true, id, lines: lines.length, unknown };
  });
}

async function lockRound(q: any, id: number) {
  const r = await q`select * from fs_rounds where id=${id} for update`;
  if (!r.length) fail('not_found');
  return r[0];
}

async function saveAdjust(me: Me, req: any) {
  need(me, 'pharm');
  const id = num(req.id), ch = req.changes || {};
  return await sql.begin(async (q: any) => {
    const r = await lockRound(q, id);
    if (r.status !== 'submitted') fail('bad_status');
    let n = 0;
    for (const k of Object.keys(ch)) {
      const v = ch[k] === null || ch[k] === '' ? null : Math.max(0, num(ch[k]));
      const u = await q`update fs_round_lines set adjust=${v} where round_id=${id} and code=${code(k)}`;
      n += u.count;
    }
    // ยาที่ไม่อยู่ในรอบ แต่อยากเบิกเพิ่ม
    for (const a of req.add || []) {
      const c = code(a.code), v = Math.max(0, num(a.qty));
      const d = await q`select 1 from fs_drugs where code=${c}`;
      if (!d.length) fail('unknown_drug:' + c);
      await q`insert into fs_round_lines(round_id, code, fixed, bf, suggest, adjust)
              values (${id}, ${c}, coalesce((select qty from fs_fixed where room=${r.room} and code=${c}),0),
                      coalesce((select qty from fs_balance where room=${r.room} and code=${c}),0), 0, ${v})
              on conflict (round_id, code) do update set adjust=excluded.adjust`;
      n++;
    }
    if (n) await log(q, me, 'adjust', { id, n });
    return { ok: true, n };
  });
}

async function approve(me: Me, req: any) {
  need(me, 'pharm');
  const id = num(req.id);
  return await sql.begin(async (q: any) => {
    const r = await lockRound(q, id);
    if (r.status !== 'submitted') fail('bad_status');
    await q`update fs_round_lines l set cf = l.bf + l.emerg - l.ret - l.usage + coalesce(l.adjust, l.suggest) * coalesce(nullif(d.pack,0),1)
            from fs_drugs d where d.code=l.code and l.round_id=${id}`;
    await q`insert into fs_balance(room, code, qty, updated_at)
            select ${r.room}, code, cf, now() from fs_round_lines where round_id=${id}
            on conflict (room, code) do update set qty=excluded.qty, updated_at=now()`;
    await q`update fs_rounds set status='approved', approved_by=${me.id}, approved_at=now() where id=${id}`;
    await log(q, me, 'approve', { id });
    return { ok: true };
  });
}

async function receive(me: Me, req: any) {
  const id = num(req.id);
  return await sql.begin(async (q: any) => {
    const r = await lockRound(q, id);
    if (r.status !== 'approved') fail('bad_status');
    await q`update fs_rounds set status='received', received_by=${me.id}, received_at=now() where id=${id}`;
    await log(q, me, 'receive', { id });
    return { ok: true };
  });
}

async function cancelRound(me: Me, req: any) {
  const id = num(req.id);
  return await sql.begin(async (q: any) => {
    const r = await lockRound(q, id);
    if (r.status !== 'submitted') fail('bad_status');
    if (r.created_by !== me.id) need(me, 'pharm');
    await q`update fs_moves set round_id=null where round_id=${id}`;
    await q`update fs_rounds set status='cancelled', cancelled_by=${me.id}, cancelled_at=now() where id=${id}`;
    await log(q, me, 'cancel', { id });
    return { ok: true };
  });
}

// ---------- เบิกฉุกเฉิน / ส่งคืน ----------
async function addMove(me: Me, req: any) {
  const room = String(req.room || ''), c = code(req.code), qty = num(req.qty);
  const kind = req.kind === 'return' ? 'return' : 'emerg';
  if (!(qty > 0)) fail('bad_qty');
  const d = await sql`select 1 from fs_drugs where code=${c}`;
  if (!d.length) fail('unknown_drug:' + c);
  const r = await sql`insert into fs_moves(room, code, kind, qty, note, created_by) values (${room}, ${c}, ${kind}, ${qty}, ${req.note || null}, ${me.id}) returning id`;
  return { ok: true, id: r[0].id };
}
async function delMove(me: Me, req: any) {
  const id = num(req.id);
  const r = await sql`select created_by, round_id from fs_moves where id=${id}`;
  if (!r.length) fail('not_found');
  if (r[0].round_id) fail('in_round');
  if (r[0].created_by !== me.id) need(me, 'pharm');
  await sql`delete from fs_moves where id=${id}`;
  return { ok: true };
}

// ---------- ข้อมูลหลัก (admin) ----------
async function importDrugs(me: Me, req: any) {
  need(me, 'admin');
  const rows = (req.rows || []).map((r: any) => ({
    code: code(r.code), ps_code: r.ps_code ? String(r.ps_code).trim() : null, name: String(r.name || r.code || '').trim(),
    pack: num(r.pack) > 0 ? num(r.pack) : 1, unit: r.unit ? String(r.unit).trim() : null,
    supplier: r.supplier === 'tam' ? 'tam' : 'main', buy: !!r.buy, active: r.active !== false,
  })).filter((r: any) => r.code && r.name);
  const seen = new Set<string>(), uniq = rows.filter((r: any) => !seen.has(r.code) && seen.add(r.code));
  return await sql.begin(async (q: any) => {
    for (let i = 0; i < uniq.length; i += 1000) {
      const chunk = uniq.slice(i, i + 1000);
      if (req.keepFlags) {
        await q`insert into fs_drugs ${q(chunk, 'code', 'ps_code', 'name', 'pack', 'unit', 'supplier', 'buy', 'active')}
                on conflict (code) do update set ps_code=excluded.ps_code, name=excluded.name, pack=excluded.pack, unit=excluded.unit, updated_at=now()`;
      } else {
        await q`insert into fs_drugs ${q(chunk, 'code', 'ps_code', 'name', 'pack', 'unit', 'supplier', 'buy', 'active')}
                on conflict (code) do update set ps_code=excluded.ps_code, name=excluded.name, pack=excluded.pack, unit=excluded.unit,
                supplier=excluded.supplier, buy=excluded.buy, active=excluded.active, updated_at=now()`;
      }
    }
    await log(q, me, 'importDrugs', { n: uniq.length });
    return { ok: true, n: uniq.length };
  });
}
async function setDrug(me: Me, req: any) {
  need(me, 'admin');
  const d = req.drug || {}, c = code(d.code);
  if (!c || !String(d.name || '').trim()) fail('bad_request');
  await sql`insert into fs_drugs(code, ps_code, name, pack, unit, supplier, buy, active)
            values (${c}, ${d.ps_code || null}, ${String(d.name).trim()}, ${num(d.pack) > 0 ? num(d.pack) : 1}, ${d.unit || null},
                    ${d.supplier === 'tam' ? 'tam' : 'main'}, ${!!d.buy}, ${d.active !== false})
            on conflict (code) do update set ps_code=excluded.ps_code, name=excluded.name, pack=excluded.pack, unit=excluded.unit,
            supplier=excluded.supplier, buy=excluded.buy, active=excluded.active, updated_at=now()`;
  return { ok: true };
}
async function importRoomQty(me: Me, req: any, table: 'fs_fixed' | 'fs_balance') {
  need(me, 'admin');
  const room = String(req.room || '');
  const agg = new Map<string, number>();
  for (const r of req.rows || []) {
    const c = code(r.code);
    if (c) agg.set(c, (req.sum ? agg.get(c) || 0 : 0) + num(r.qty));
  }
  return await sql.begin(async (q: any) => {
    const rm = await q`select 1 from fs_rooms where code=${room}`;
    if (!rm.length) fail('bad_room');
    const known = new Set((await q`select code from fs_drugs`).map((d: any) => d.code));
    const rows = [], unknown: string[] = [];
    for (const [c, v] of agg) { if (known.has(c)) rows.push({ room, code: c, qty: v }); else unknown.push(c); }
    if (req.replace) await q`delete from ${q(table)} where room=${room}`;
    for (let i = 0; i < rows.length; i += 1000) {
      await q`insert into ${q(table)} ${q(rows.slice(i, i + 1000), 'room', 'code', 'qty')}
              on conflict (room, code) do update set qty=excluded.qty, updated_at=now()`;
    }
    await log(q, me, 'import_' + table, { room, n: rows.length, replace: !!req.replace });
    return { ok: true, n: rows.length, unknown };
  });
}
async function setRoomQty(me: Me, req: any, table: 'fs_fixed' | 'fs_balance') {
  need(me, 'admin');
  const room = String(req.room || ''), c = code(req.code), v = num(req.qty);
  await sql`insert into ${sql(table)} (room, code, qty) values (${room}, ${c}, ${v})
            on conflict (room, code) do update set qty=excluded.qty, updated_at=now()`;
  return { ok: true };
}
async function setRole(me: Me, req: any) {
  need(me, 'admin');
  const id = String(req.emp_id || ''), role = String(req.role || '');
  if (!RANK[role]) fail('bad_request');
  if (id === me.id && role !== 'admin') {
    const n = await sql`select count(*)::int n from fs_roles where role='admin' and emp_id<>${id}`;
    if (!n[0].n) fail('last_admin');
  }
  await sql`insert into fs_roles(emp_id, role) values (${id}, ${role}) on conflict (emp_id) do update set role=excluded.role, updated_at=now()`;
  return { ok: true };
}
async function setRoom(me: Me, req: any) {
  need(me, 'admin');
  const c = String(req.code || '').trim();
  if (!c || !String(req.name || '').trim()) fail('bad_request');
  await sql`insert into fs_rooms(code, name, sort, active) values (${c}, ${String(req.name).trim()}, ${num(req.sort)}, ${req.active !== false})
            on conflict (code) do update set name=excluded.name, sort=excluded.sort, active=excluded.active`;
  return { ok: true };
}

const ACTIONS: Record<string, (me: Me, req: any) => Promise<unknown>> = {
  boot, roomData, round: getRound, staffList, usageReport,
  createRound, saveAdjust, approve, receive, cancelRound, addMove, delMove,
  importDrugs, setDrug, setRole, setRoom,
  importFixed: (me, r) => importRoomQty(me, r, 'fs_fixed'),
  importBalance: (me, r) => importRoomQty(me, r, 'fs_balance'),
  setFixed: (me, r) => setRoomQty(me, r, 'fs_fixed'),
  setBalance: (me, r) => setRoomQty(me, r, 'fs_balance'),
  changePw,
};

Deno.serve(async (r: Request) => {
  if (r.method === 'OPTIONS') return new Response(null, { headers: CORS });
  if (r.method === 'GET') return out({ ok: true, name: 'ch9-drugreq', time: Date.now() });
  let req: any;
  try { req = JSON.parse(await r.text()); } catch { return out({ ok: false, code: 'bad_request' }); }
  try {
    if (req.a === 'login') return out(await login(req));
    if (req.a === 'ping') { await sql`select 1`; return out({ ok: true }); }
    const me = await auth(req.token);
    if (!me) return out({ ok: false, code: 'auth' });
    const fn = ACTIONS[req.a];
    if (!fn) return out({ ok: false, code: 'bad_request' });
    return out(await fn(me, req));
  } catch (e) {
    if (!(e instanceof E)) console.error(e);
    return out({ ok: false, code: String((e as Error)?.message || e) });
  }
});
