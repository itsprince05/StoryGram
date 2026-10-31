-- Story Gram schema for Supabase (PostgreSQL). Run in SQL Editor; safe to re-run.
-- RLS is on for every table with no policies: only the backend (database password) can read or write.

create table if not exists public.entries (
  id           bigint generated always as identity primary key,
  uid          text,
  name         text default 'User',
  email        text not null,
  photo        text,
  device       text not null,
  manufacturer text,
  brand        text,
  model        text,
  ip           text,
  status       text not null default 'pending'
               check (status in ('pending', 'multiple', 'expired', 'blocked', 'active')),
  created      bigint not null
);
create index if not exists idx_entries_email   on public.entries (email);
create index if not exists idx_entries_uid     on public.entries (uid);
create index if not exists idx_entries_device  on public.entries (device);
create index if not exists idx_entries_status  on public.entries (status);
create index if not exists idx_entries_created on public.entries (created);

create table if not exists public.buyers (
  id           bigint generated always as identity primary key,
  uid          text,
  name         text default 'User',
  email        text not null unique,
  photo        text,
  device       text,
  manufacturer text,
  brand        text,
  model        text,
  status       text not null default 'active' check (status in ('active', 'blocked')),
  language     text not null default 'hindi',
  validity     bigint not null default 0,      -- unix seconds, 0 = lifetime
  created      bigint not null,
  updated      bigint not null
);
create index if not exists idx_buyers_uid      on public.buyers (uid);
create index if not exists idx_buyers_device   on public.buyers (device);
create index if not exists idx_buyers_status   on public.buyers (status);
create index if not exists idx_buyers_validity on public.buyers (validity);

create table if not exists public.library (
  id        bigint generated always as identity primary key,
  uid       text not null,
  action    text not null default 'history' check (action in ('history', 'saved')),
  show_id   text not null,
  show_name text not null,
  show_url  text,
  created   bigint not null
);
create unique index if not exists uq_library_uid_action_show on public.library (uid, action, show_id);
create index if not exists idx_library_uid_action_created    on public.library (uid, action, created desc);

create table if not exists public.episodes (
  id       bigint generated always as identity primary key,
  story_id text   not null,
  number   integer not null,
  media_url text  not null default '',   -- audio / main stream
  video_url text  not null default '',   -- optional video stream
  created  bigint not null,
  constraint idx_episodes_story_number unique (story_id, number)
);
create index if not exists idx_episodes_story_id on public.episodes (story_id);
-- upgrade: old single `url` column becomes media_url
do $$
begin
  if exists (select 1 from information_schema.columns
             where table_schema = 'public' and table_name = 'episodes' and column_name = 'url') then
    alter table public.episodes rename column url to media_url;
  end if;
end $$;
alter table public.episodes add column if not exists media_url text not null default '';
alter table public.episodes add column if not exists video_url text not null default '';
alter table public.episodes alter column media_url set default '';

create table if not exists public.app (
  id       bigint generated always as identity primary key,
  version  text not null default '1' unique,
  status   text not null default 'active' check (status in ('active', 'blocked')),
  username text default 'index_guide',         -- Telegram username shown on "Contact Admin"
  created  bigint not null
);
create index if not exists idx_app_status on public.app (status);

create table if not exists public.admins (
  id       bigint generated always as identity primary key,
  name     text not null default 'Admin',
  username text not null unique,
  password text not null,                      -- bcrypt hash (PHP password_hash hashes work as-is)
  role     text not null default 'admin' check (role in ('owner', 'admin')),
  status   text not null default 'active' check (status in ('active', 'blocked')),
  created  bigint not null
);

insert into public.app (version, status, username, created)
values ('1', 'active', 'index_guide', extract(epoch from now())::bigint)
on conflict (version) do nothing;

-- lock out Supabase's public REST API
alter table public.entries  enable row level security;
alter table public.buyers   enable row level security;
alter table public.library  enable row level security;
alter table public.episodes enable row level security;
alter table public.app      enable row level security;
alter table public.admins   enable row level security;
