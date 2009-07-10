CREATE TABLE users (
	id integer PRIMARY KEY,
    name text UNIQUE NOT NULL,
	password text);

CREATE TABLE tasks (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	name text,
	owner integer REFERENCES users (id) ON DELETE RESTRICT,
	rcfile text,
	comment text);

CREATE TABLE reports (
	id integer PRIMARY KEY,
	uuid text UNIQUE NOT NULL,
	task integer REFERENCES tasks (id) ON DELETE RESTRICT,
	nbefile text,
	comment text);
