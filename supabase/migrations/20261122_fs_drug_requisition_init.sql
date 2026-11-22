-- ระบบเบิกยาห้องยา (Fixed stock) — ตารางแยก prefix fs_ (อยู่ในโปรเจกต์ ch9-supply)
create table public.fs_drugs (
  code text primary key,
  ps_code text,
  name text not null,
  pack numeric not null default 1,      -- จำนวนหน่วยจ่ายต่อ 1 หน่วยเบิก (คอลัมน์ D)
  unit text,                             -- หน่วยเบิก/หน่วยนับ (คอลัมน์ E)
  supplier text not null default 'main' check (supplier in ('main','tam')),
  buy boolean not null default false,
  active boolean not null default true,
  updated_at timestamptz not null default now()
);
create table public.fs_rooms (
  code text primary key,
  name text not null,
  sort int not null default 0,
  active boolean not null default true
);
create table public.fs_fixed (
  room text not null references public.fs_rooms(code) on update cascade,
  code text not null references public.fs_drugs(code) on update cascade,
  qty numeric not null default 0,        -- Fixed stock (หน่วยจ่าย)
  updated_at timestamptz not null default now(),
  primary key (room, code)
);
create table public.fs_balance (
  room text not null references public.fs_rooms(code) on update cascade,
  code text not null references public.fs_drugs(code) on update cascade,
  qty numeric not null default 0,        -- ยอดยกไป/คงเหลือปัจจุบัน (หน่วยจ่าย)
  updated_at timestamptz not null default now(),
  primary key (room, code)
);
create table public.fs_rounds (
  id bigserial primary key,
  room text not null references public.fs_rooms(code) on update cascade,
  period_start date,
  period_end date,
  req_date date not null default (now() at time zone 'Asia/Bangkok')::date,
  status text not null default 'submitted' check (status in ('submitted','approved','received','cancelled')),
  note text,
  usage_file text,
  created_by text, created_at timestamptz not null default now(),
  approved_by text, approved_at timestamptz,
  received_by text, received_at timestamptz,
  cancelled_by text, cancelled_at timestamptz
);
create table public.fs_round_lines (
  round_id bigint not null references public.fs_rounds(id) on delete cascade,
  code text not null references public.fs_drugs(code) on update cascade,
  fixed numeric not null default 0,
  bf numeric not null default 0,
  emerg numeric not null default 0,
  ret numeric not null default 0,
  usage numeric not null default 0,
  suggest numeric not null default 0,    -- ยอดเติมที่ระบบคิด (หน่วยเบิก)
  adjust numeric,                        -- ยอดเติมที่เภสัชกรแก้ (หน่วยเบิก)
  cf numeric,
  primary key (round_id, code)
);
create table public.fs_moves (
  id bigserial primary key,
  room text not null references public.fs_rooms(code) on update cascade,
  code text not null references public.fs_drugs(code) on update cascade,
  kind text not null check (kind in ('emerg','return')),
  qty numeric not null check (qty > 0),  -- หน่วยจ่าย
  note text,
  round_id bigint references public.fs_rounds(id) on delete set null,
  created_by text, created_at timestamptz not null default now()
);
create table public.fs_roles (
  emp_id text primary key,
  role text not null check (role in ('user','pharm','admin')),
  updated_at timestamptz not null default now()
);
create table public.fs_log (
  id bigserial primary key,
  at timestamptz not null default now(),
  emp_id text, action text, detail jsonb
);
create index on public.fs_rounds (room, created_at desc);
create index on public.fs_moves (room, round_id);
create index on public.fs_round_lines (code);
alter table public.fs_drugs enable row level security;
alter table public.fs_rooms enable row level security;
alter table public.fs_fixed enable row level security;
alter table public.fs_balance enable row level security;
alter table public.fs_rounds enable row level security;
alter table public.fs_round_lines enable row level security;
alter table public.fs_moves enable row level security;
alter table public.fs_roles enable row level security;
alter table public.fs_log enable row level security;

insert into public.fs_rooms(code,name,sort) values
 ('M1','ห้องยา M1',1),('M2','ห้องยา M2',2),('PKS','ห้องยา ปกส.',3),('M4','ห้องยา M4',4);

-- ผู้ดูแลระบบเบิกพัสดุ = admin เริ่มต้นของระบบนี้ (แก้สิทธิ์แยกได้ภายหลัง)
insert into public.fs_roles(emp_id, role)
select id, 'admin' from public.docs where coll='staff' and data->>'isAdmin'='true';
