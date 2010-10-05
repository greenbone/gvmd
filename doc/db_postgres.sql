CREATE TABLE meta (
	id integer PRIMARY KEY,
	name text UNIQUE NOT NULL,
	value text);

CREATE TABLE agents (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	comment text,
	installer text,
	installer_64 text,
	installer_filename text,
	installer_signature_64 text,
	installer_trust integer,
	installer_trust_time date,
	howto_install text,
	howto_use text);

CREATE TABLE escalator_condition_data (
	id integer PRIMARY KEY,
	escalator integer REFERENCES escalators (id) ON DELETE RESTRICT,
	name text,
	data text);

CREATE TABLE escalator_event_data (
	id integer PRIMARY KEY,
	escalator integer REFERENCES escalators (id) ON DELETE RESTRICT,
	name text,
	data text);

CREATE TABLE escalator_method_data (
	id integer PRIMARY KEY,
	escalator integer REFERENCES escalators (id) ON DELETE RESTRICT,
	name text,
	data text);

CREATE TABLE escalators (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	comment text,
	event integer,
	condition integer,
	method integer);

CREATE TABLE users (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
    name text NOT NULL,
	password text);

CREATE TABLE nvt_selectors (
	id integer PRIMARY KEY,
    name text,
	exclude boolean,
	type integer,
	family_or_nvt text,
	family text);

CREATE TABLE targets (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	hosts text,
	comment text,
	lsc_credential integer REFERENCES lsc_credentials (id) ON DELETE RESTRICT);

CREATE TABLE configs (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	nvt_selector text REFERENCES nvt_selectors (name) ON DELETE RESTRICT,
	comment text,
	family_count integer,
	nvt_count integer,
	families_growing integer,
	nvts_growing integer);

CREATE TABLE config_preferences (
	config integer PRIMARY KEY REFERENCES configs (id) ON DELETE RESTRICT,
	type text PRIMARY KEY, -- openvasrc section name or NULL for top-level prefs
	name text PRIMARY KEY,
	value text);

CREATE TABLE tasks (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text,
	hidden integer,
	comment text,
	description text, -- RC file
	run_status integer,
	start_time date,
	end_time date,
	config integer REFERENCES configs (id) ON DELETE RESTRICT,
	target integer REFERENCES targets (id) ON DELETE RESTRICT,
	schedule integer REFERENCES schedules (id) ON DELETE RESTRICT,
	schedule_next_time date,
	slave integer REFERENCES slaves (id) ON DELETE RESTRICT);

CREATE TABLE task_files (
	id integer PRIMARY KEY,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	name text,
	content text);

CREATE TABLE task_escalators (
	id integer PRIMARY KEY,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	escalator integer REFERENCES escalators (id) ON DELETE RESTRICT);

CREATE TABLE results (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
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
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	hidden integer,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	date date,
	start_time date,
	end_time date,
	nbefile text,
	comment text,
	scan_run_status integer,
	slave_progress text,
	slave_task_uuid text);

CREATE TABLE report_format_params (
	id integer PRIMARY KEY,
	report_format integer REFERENCES report_formats (id) ON DELETE RESTRICT,
	name text,
	type integer,
	value text,
	type_min integer,
	type_max integer,
	type_regex text,
	fallback text);

CREATE TABLE report_format_param_options (
	id integer PRIMARY KEY,
	report_format_param integer REFERENCES report_format_params (id) ON DELETE RESTRICT,
	value text);

CREATE TABLE report_formats (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	extension text,
	content_type text,
	summary text,
	description text,
	signature text,
	trust integer,
	trust_time date,
	flags integer);

CREATE TABLE report_hosts (
	id integer PRIMARY KEY,
	report integer REFERENCES reports (id) ON DELETE RESTRICT,
	host text,
	start_time date,
	end_time date,
	attack_state INTEGER,
	current_port text,
	max_port text);

CREATE TABLE report_results (
	report integer PRIMARY KEY REFERENCES reports (id) ON DELETE RESTRICT,
	result integer PRIMARY KEY REFERENCES results (id) ON DELETE RESTRICT);

CREATE TABLE nvt_preferences (
    id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
	value text);

CREATE TABLE nvts (
    id integer PRIMARY KEY,
	oid text UNIQUE NOT NULL,
	version text,
    name text,
    summary text,
    description text,
    copyright text,
    cve text,
    bid text,
    xref text,
    tag text,
    sign_key_ids text,
    category text,
    family text,
    cvss_base text,
    risk_factor text);

CREATE TABLE lsc_credentials (
	id integer PRIMARY KEY,
    uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	login text,
	password text,
	comment text,
	public_key text,
	private_key text,
	rpm bytea,
	deb bytea,
	exe bytea);

CREATE TABLE notes (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	nvt text NOT NULL,  -- OID of NVT
	creation_time date,
	modification_time date,
	text text,
	hosts text,
	port text,
	threat text,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	result integer REFERENCES results (id) ON DELETE RESTRICT);

CREATE TABLE overrides (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	nvt text NOT NULL,  -- OID of NVT
	creation_time date,
	modification_time date,
	text text,
	hosts text,
	new_threat text,
	port text,
	threat text,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	result integer REFERENCES results (id) ON DELETE RESTRICT);

CREATE TABLE schedules (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	comment text,
	first_time date,
	period integer,
	period_months integer,
	duration integer);

CREATE TABLE slaves (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	name text NOT NULL,
	comment text,
	host text,
	port text,
	login text,
	password text);
