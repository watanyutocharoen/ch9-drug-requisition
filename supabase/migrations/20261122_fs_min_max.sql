-- Min-Max ต่อห้อง: qty = Max (หรือ Fixed เดิม), min_qty = จุดสั่งเติม (ว่าง = ใช้สูตร Fixed เดิม เติมให้เต็มทุกรอบ)
alter table public.fs_fixed add column if not exists min_qty numeric;
alter table public.fs_round_lines add column if not exists min numeric;
