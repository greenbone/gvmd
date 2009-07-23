CREATE TABLE users (
	id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
	password text);

CREATE TABLE nvt_selectors (
	rowid integer PRIMARY KEY,
	id integer,
    name text,
	exclude boolean,
	type integer,
	details text);

CREATE TABLE tasks (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	name text,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	nvt_selector integer REFERENCES nvt_selectors (id) ON DELETE RESTRICT,
	rcfile text,
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
