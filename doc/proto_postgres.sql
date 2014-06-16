CREATE TABLE meta
   (version_major integer,
	version_minor integer,
	nvts_md5sum text);

CREATE TABLE users
   (id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
	password text);

CREATE TABLE families
   (id integer PRIMARY KEY,
    name text UNIQUE NOT NULL);

CREATE TABLE nvts
   (id integer PRIMARY KEY,
	oid text UNIQUE NOT NULL,
	md5sum text NOT NULL,
	version text,
    name text,
    summary text,
    description text,
    copyright text,
	-- ...other fields from nvti...
	-- Is there some way to automate all of this (db, omp, c interface, guis)?
	family integer REFERENCES families (id) ON DELETE RESTRICT);

CREATE TABLE nvt_selectors
   (id integer,
    name text);

-- The priority field orders the sub_selectors within a selector, to allow
-- selections such as "include all tests, then exclude those in family x,
-- then include nvt y", where y is in family x.  Excluding is like
-- subtracting, the order of operations is significant.
--
CREATE TABLE nvt_sub_selectors
   (priority integer PRIMARY KEY,
	nvt_selector integer PRIMARY KEY REFERENCES nvt_selectors (id) ON DELETE RESTRICT,
	exclude boolean,
	type integer,                 -- 0 all, 1 family, 2 nvt
	family_or_nvt integer);       -- (cond type (0 empty) (1 family id) (2 nvt id))

CREATE TABLE tasks
   (id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	name text UNIQUE,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	nvt_selector integer REFERENCES nvt_selectors (id) ON DELETE RESTRICT,
	rcfile text,
	comment text);

CREATE TABLE hosts
   (id integer PRIMARY KEY,
	address text);

CREATE TABLE jobs
   (id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	name text UNIQUE,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	period integer,
	start_time date);

CREATE TABLE job_hosts
   (job integer PRIMARY KEY REFERENCES jobs (id) ON DELETE RESTRICT,
	host integer PRIMARY KEY REFERENCES hosts (id) ON DELETE RESTRICT);

CREATE TABLE scans
   (id integer PRIMARY KEY,
	job integer PRIMARY KEY REFERENCES jobs (id) ON DELETE RESTRICT,
	uuid text UNIQUE NOT NULL,
	rcfile text,
	run_status integer,
	start_time date NOT NULL,
	end_time date);

CREATE TABLE scan_hosts
   (scan integer PRIMARY KEY REFERENCES scans (id) ON DELETE RESTRICT,
	host integer PRIMARY KEY REFERENCES hosts (id) ON DELETE RESTRICT,
	start_time date,
	end_time date,
	attack_state integer,
	current_port integer,
	max_port integer);

CREATE TABLE results
   (id integer PRIMARY KEY,
	scan integer REFERENCES scans (id) ON DELETE RESTRICT,
	subnet text,
	host integer REFERENCES hosts (id) ON DELETE RESTRICT,
	port text,
	nvt integer REFERENCES nvts (id) ON DELETE RESTRICT,
	type integer,
	description text);

CREATE TABLE reports
   (id integer PRIMARY KEY,
	uuid text NOT NULL,
	date date,
	name text,
	comment text,
	description text);

CREATE TABLE report_results
   (report integer PRIMARY KEY REFERENCES reports (id) ON DELETE RESTRICT,
	result integer PRIMARY KEY REFERENCES results (id) ON DELETE RESTRICT);
