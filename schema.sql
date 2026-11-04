-- November Warriors MVP schema. Run in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default 'Warrior',
  username text unique,
  avatar_url text,
  created_at timestamptz not null default now()
);
create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  invite_code text not null unique default upper(substr(encode(gen_random_bytes(6),'hex'),1,8)),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.group_members (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check(role in ('owner','admin','member')),
  joined_at timestamptz not null default now(),
  unique(group_id,user_id)
);
create table if not exists public.challenges (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups(id) on delete cascade,
  name text not null,
  start_date date not null,
  end_date date not null,
  status text not null default 'active' check(status in ('draft','active','completed','archived')),
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  check(end_date >= start_date)
);
create table if not exists public.challenge_members (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null references public.challenges(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  unique(challenge_id,user_id)
);
create table if not exists public.habits (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null references public.challenges(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  description text,
  points_per_completion integer not null default 10 check(points_per_completion between 0 and 1000),
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);
create table if not exists public.checkins (
  id uuid primary key default gen_random_uuid(),
  challenge_id uuid not null references public.challenges(id) on delete cascade,
  habit_id uuid not null references public.habits(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  checkin_date date not null default current_date,
  created_at timestamptz not null default now(),
  unique(habit_id,checkin_date)
);
create table if not exists public.activity_events (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups(id) on delete cascade,
  challenge_id uuid references public.challenges(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  event_type text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists gm_user_idx on public.group_members(user_id);
create index if not exists gm_group_idx on public.group_members(group_id);
create index if not exists challenges_group_idx on public.challenges(group_id,created_at desc);
create index if not exists habits_challenge_user_idx on public.habits(challenge_id,user_id,is_active);
create index if not exists checkins_challenge_date_idx on public.checkins(challenge_id,checkin_date);
create index if not exists events_group_created_idx on public.activity_events(group_id,created_at desc);

-- SECURITY DEFINER helpers prevent recursive membership-table RLS checks.
create or replace function public.is_group_member(gid uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp
as $$ select exists(select 1 from public.group_members where group_id=gid and user_id=auth.uid()); $$;
create or replace function public.is_group_admin(gid uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp
as $$ select exists(select 1 from public.group_members where group_id=gid and user_id=auth.uid() and role in ('owner','admin')); $$;
create or replace function public.is_challenge_group_member(cid uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp
as $$ select exists(select 1 from public.challenges c join public.group_members gm on gm.group_id=c.group_id where c.id=cid and gm.user_id=auth.uid()); $$;
create or replace function public.can_view_profile(pid uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp
as $$ select pid=auth.uid() or exists(select 1 from public.group_members a join public.group_members b on b.group_id=a.group_id where a.user_id=auth.uid() and b.user_id=pid); $$;
revoke all on function public.is_group_member(uuid) from public,anon;
revoke all on function public.is_group_admin(uuid) from public,anon;
revoke all on function public.is_challenge_group_member(uuid) from public,anon;
revoke all on function public.can_view_profile(uuid) from public,anon;
grant execute on function public.is_group_member(uuid),public.is_group_admin(uuid),public.is_challenge_group_member(uuid),public.can_view_profile(uuid) to authenticated;

-- Automatically add the group creator as owner.
create or replace function public.add_group_creator_as_member()
returns trigger language plpgsql security definer set search_path=public,pg_temp
as $$ begin
  insert into public.group_members(group_id,user_id,role) values(new.id,new.created_by,'owner')
  on conflict(group_id,user_id) do nothing;
  return new;
end; $$;
drop trigger if exists trg_add_group_creator on public.groups;
create trigger trg_add_group_creator after insert on public.groups
for each row execute function public.add_group_creator_as_member();

-- Join by invite code; returns the group's UUID.
create or replace function public.join_group_by_code(p_code text)
returns uuid language plpgsql security definer set search_path=public,pg_temp
as $$
declare gid uuid;
begin
  if auth.uid() is null then raise exception 'Sign in first'; end if;
  select id into gid from public.groups where upper(invite_code)=upper(trim(p_code)) limit 1;
  if gid is null then raise exception 'Invalid invite code'; end if;
  insert into public.group_members(group_id,user_id,role) values(gid,auth.uid(),'member')
  on conflict(group_id,user_id) do nothing;
  return gid;
end; $$;
revoke all on function public.join_group_by_code(text) from public,anon;
grant execute on function public.join_group_by_code(text) to authenticated;

alter table public.profiles enable row level security;
alter table public.groups enable row level security;
alter table public.group_members enable row level security;
alter table public.challenges enable row level security;
alter table public.challenge_members enable row level security;
alter table public.habits enable row level security;
alter table public.checkins enable row level security;
alter table public.activity_events enable row level security;

drop policy if exists profiles_read on public.profiles;
drop policy if exists profiles_add_self on public.profiles;
drop policy if exists profiles_edit_self on public.profiles;
create policy profiles_read on public.profiles for select to authenticated using(public.can_view_profile(id));
create policy profiles_add_self on public.profiles for insert to authenticated with check(id=auth.uid());
create policy profiles_edit_self on public.profiles for update to authenticated using(id=auth.uid()) with check(id=auth.uid());

drop policy if exists groups_read on public.groups;
drop policy if exists groups_add on public.groups;
drop policy if exists groups_edit on public.groups;
create policy groups_read on public.groups for select to authenticated using(public.is_group_member(id));
create policy groups_add on public.groups for insert to authenticated with check(created_by=auth.uid());
create policy groups_edit on public.groups for update to authenticated using(public.is_group_admin(id)) with check(public.is_group_admin(id));

drop policy if exists group_members_read on public.group_members;
create policy group_members_read on public.group_members for select to authenticated using(public.is_group_member(group_id));

drop policy if exists challenges_read on public.challenges;
drop policy if exists challenges_add on public.challenges;
drop policy if exists challenges_edit on public.challenges;
create policy challenges_read on public.challenges for select to authenticated using(public.is_group_member(group_id));
create policy challenges_add on public.challenges for insert to authenticated with check(created_by=auth.uid() and public.is_group_member(group_id));
create policy challenges_edit on public.challenges for update to authenticated using(public.is_group_admin(group_id)) with check(public.is_group_admin(group_id));

drop policy if exists challenge_members_read on public.challenge_members;
drop policy if exists challenge_members_add_self on public.challenge_members;
create policy challenge_members_read on public.challenge_members for select to authenticated using(public.is_challenge_group_member(challenge_id));
create policy challenge_members_add_self on public.challenge_members for insert to authenticated with check(user_id=auth.uid() and public.is_challenge_group_member(challenge_id));

drop policy if exists habits_read on public.habits;
drop policy if exists habits_add_self on public.habits;
drop policy if exists habits_edit_self on public.habits;
drop policy if exists habits_remove_self on public.habits;
create policy habits_read on public.habits for select to authenticated using(public.is_challenge_group_member(challenge_id));
create policy habits_add_self on public.habits for insert to authenticated with check(user_id=auth.uid() and public.is_challenge_group_member(challenge_id));
create policy habits_edit_self on public.habits for update to authenticated using(user_id=auth.uid() and public.is_challenge_group_member(challenge_id)) with check(user_id=auth.uid() and public.is_challenge_group_member(challenge_id));
create policy habits_remove_self on public.habits for delete to authenticated using(user_id=auth.uid() and public.is_challenge_group_member(challenge_id));

drop policy if exists checkins_read on public.checkins;
drop policy if exists checkins_add_self on public.checkins;
drop policy if exists checkins_remove_self on public.checkins;
create policy checkins_read on public.checkins for select to authenticated using(public.is_challenge_group_member(challenge_id));
create policy checkins_add_self on public.checkins for insert to authenticated with check(
  user_id=auth.uid() and public.is_challenge_group_member(challenge_id) and
  exists(select 1 from public.habits h where h.id=checkins.habit_id and h.challenge_id=checkins.challenge_id and h.user_id=auth.uid())
);
create policy checkins_remove_self on public.checkins for delete to authenticated using(user_id=auth.uid() and public.is_challenge_group_member(challenge_id));

drop policy if exists events_read on public.activity_events;
drop policy if exists events_add_self on public.activity_events;
create policy events_read on public.activity_events for select to authenticated using(public.is_group_member(group_id));
create policy events_add_self on public.activity_events for insert to authenticated with check(
  user_id=auth.uid() and public.is_group_member(group_id) and
  (challenge_id is null or exists(select 1 from public.challenges c where c.id=activity_events.challenge_id and c.group_id=activity_events.group_id))
);

create or replace view public.challenge_leaderboard with (security_invoker=true) as
select cm.challenge_id,cm.user_id,p.display_name,p.username,
       coalesce(s.active_days,0)::integer as active_days,
       coalesce(s.total_completions,0)::integer as total_completions,
       coalesce(s.total_points,0)::bigint as total_points
from public.challenge_members cm
left join public.profiles p on p.id=cm.user_id
left join (
  select ci.challenge_id,ci.user_id,count(distinct ci.checkin_date) as active_days,
         count(*) as total_completions,coalesce(sum(h.points_per_completion),0) as total_points
  from public.checkins ci join public.habits h on h.id=ci.habit_id
  group by ci.challenge_id,ci.user_id
) s on s.challenge_id=cm.challenge_id and s.user_id=cm.user_id;

grant select,insert,update on public.profiles to authenticated;
grant select,insert,update on public.groups to authenticated;
grant select on public.group_members to authenticated;
grant select,insert,update on public.challenges to authenticated;
grant select,insert on public.challenge_members to authenticated;
grant select,insert,update,delete on public.habits to authenticated;
grant select,insert,delete on public.checkins to authenticated;
grant select,insert on public.activity_events to authenticated;
grant select on public.challenge_leaderboard to authenticated;

-- Enable Realtime publication for the two event tables if Supabase has the publication.
do $$
begin
  if exists(select 1 from pg_publication where pubname='supabase_realtime') then
    if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='checkins') then
      execute 'alter publication supabase_realtime add table public.checkins';
    end if;
    if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='activity_events') then
      execute 'alter publication supabase_realtime add table public.activity_events';
    end if;
  end if;
end $$;
