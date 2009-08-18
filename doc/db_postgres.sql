CREATE TABLE users (
	id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
	password text);

CREATE TABLE nvt_selectors (
    name text,
	exclude boolean,
	type integer,
	family_or_nvt text);

CREATE TABLE targets (
	name text PRIMARY KEY,
	hosts text);

CREATE TABLE config_preferences (
	config integer PRIMARY KEY REFERENCES configs (id) ON DELETE RESTRICT,
	type text PRIMARY KEY, -- openvasrc section name or NULL for top-level prefs
	name text PRIMARY KEY,
	value text);

CREATE TABLE configs (
	name text PRIMARY KEY,
	nvt_selector text REFERENCES nvt_selectors (name) ON DELETE RESTRICT);

CREATE TABLE tasks (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	name text,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	config integer REFERENCES configs (name) ON DELETE RESTRICT,
	target integer REFERENCES targets (name) ON DELETE RESTRICT,
	comment text);

CREATE TABLE results (
	id integer PRIMARY KEY,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	subnet text,
	host text,
	port text,
	nvt text,  -- OID of NVT
	type text,
	description text);

CREATE TABLE reports (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	date date,
	start_time date,
	end_time date,
	nbefile text,
	comment text);

CREATE TABLE report_hosts (
	id integer PRIMARY KEY,
	report integer REFERENCES reports (id) ON DELETE RESTRICT,
	host text,
	start_time date,
	end_time date);

CREATE TABLE report_results (
	report integer PRIMARY KEY REFERENCES reports (id) ON DELETE RESTRICT,
	result integer PRIMARY KEY REFERENCES results (id) ON DELETE RESTRICT);
