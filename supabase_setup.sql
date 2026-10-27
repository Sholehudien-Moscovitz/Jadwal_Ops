-- Run this once in the Supabase SQL Editor.
-- Create Auth users in Supabase Dashboard > Authentication > Users first.
-- Then insert one profile row for each Auth user (example at the end).

create table if not exists public.profiles (
    user_id uuid primary key references auth.users (id) on delete cascade,
    login_name text not null unique,
    display_name text not null,
    employee_name text,
    role text not null check (role in ('SUPER_ADMIN', 'ADMIN_OPS', 'VIEWER')),
    created_at timestamptz not null default now()
);

create table if not exists public.work_schedules (
    employee_name text not null,
    work_date date not null,
    shift_name text not null check (shift_name in ('Pagi', 'Middle', 'Siang', 'OFF', 'UNASSIGNED')),
    start_time time,
    end_time time,
    updated_at timestamptz not null default now(),
    primary key (employee_name, work_date),
    check (
        (shift_name in ('Pagi', 'Middle', 'Siang') and start_time is not null and end_time is not null)
        or (shift_name in ('OFF', 'UNASSIGNED') and start_time is null and end_time is null)
    )
);

create or replace function public.current_app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
    select role from public.profiles where user_id = auth.uid()
$$;

revoke all on function public.current_app_role() from public;
grant execute on function public.current_app_role() to authenticated;

alter table public.profiles enable row level security;
alter table public.work_schedules enable row level security;

drop policy if exists "Authenticated users can view profiles" on public.profiles;
drop policy if exists "Users view own profile" on public.profiles;
create policy "Users view own profile"
    on public.profiles for select to authenticated using (user_id = auth.uid());

drop policy if exists "Super admin manages profiles" on public.profiles;
drop policy if exists "Super admin views all profiles" on public.profiles;
create policy "Super admin views all profiles"
    on public.profiles for select to authenticated using (public.current_app_role() = 'SUPER_ADMIN');

drop policy if exists "Authenticated users can view schedules" on public.work_schedules;
create policy "Authenticated users can view schedules"
    on public.work_schedules for select to authenticated using (true);

drop policy if exists "Admins manage schedules" on public.work_schedules;
create policy "Admins manage schedules"
    on public.work_schedules for all to authenticated
    using (public.current_app_role() in ('SUPER_ADMIN', 'ADMIN_OPS'))
    with check (public.current_app_role() in ('SUPER_ADMIN', 'ADMIN_OPS'));

revoke insert, update, delete on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.work_schedules to authenticated;

create or replace function public.replace_work_schedules(p_entries jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
    v_start_date date;
    v_end_date date;
begin
    if coalesce(public.current_app_role(), '') not in ('SUPER_ADMIN', 'ADMIN_OPS') then
        raise exception 'Only schedule administrators can replace schedules';
    end if;

    if jsonb_typeof(p_entries) <> 'array' or jsonb_array_length(p_entries) = 0 then
        raise exception 'Schedule import must contain at least one entry';
    end if;

    select min(entry.work_date), max(entry.work_date)
    into v_start_date, v_end_date
    from jsonb_to_recordset(p_entries) as entry(work_date date);

    if v_start_date is null or v_end_date is null then
        raise exception 'Schedule dates are invalid';
    end if;

    delete from public.work_schedules
    where work_date between v_start_date and v_end_date;

    insert into public.work_schedules (employee_name, work_date, shift_name, start_time, end_time)
    select entry.employee_name, entry.work_date, entry.shift_name, entry.start_time, entry.end_time
    from jsonb_to_recordset(p_entries) as entry(
        employee_name text,
        work_date date,
        shift_name text,
        start_time time,
        end_time time
    );
end;
$$;

revoke all on function public.replace_work_schedules(jsonb) from public;
grant execute on function public.replace_work_schedules(jsonb) to authenticated;

-- Provision each person in this order:
-- 1. Create their email/password account in Supabase Dashboard > Authentication > Users.
-- 2. Run an insert below, replacing the email and names.
-- 3. Use SUPER_ADMIN for the single system administrator, ADMIN_OPS for schedule editors,
--    and VIEWER for read-only accounts.
--
-- insert into public.profiles (user_id, login_name, display_name, employee_name, role)
-- select id, email, 'Nama User', 'Nama Karyawan di Excel', 'VIEWER'
-- from auth.users where email = 'user@example.com';