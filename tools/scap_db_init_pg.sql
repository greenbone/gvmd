/*
 * OpenVAS
 * $Id: scap_db_init.sql 20229 2014-09-01 13:13:29Z mwiegand $
 * Description: Postgres SCAP database initialization script
 *
 * Authors:
 * Henri Doreau <henri.doreau@greenbone.net>
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011-2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

CREATE OR REPLACE FUNCTION drop_scap () RETURNS void AS $$
BEGIN
    IF EXISTS (SELECT schema_name FROM information_schema.schemata
               WHERE schema_name = 'scap')
    THEN
      DROP SCHEMA IF EXISTS scap CASCADE;
    END IF;
END;
$$ LANGUAGE plpgsql;

SELECT drop_scap ();
DROP FUNCTION drop_scap ();
CREATE SCHEMA scap;
SET search_path TO scap;

/* Create new tables and indices. */

CREATE TABLE meta (id SERIAL PRIMARY KEY, name text UNIQUE, value text);
INSERT INTO meta (name, value) VALUES ('database_version', '15');
INSERT INTO meta (name, value) VALUES ('last_update', '0');

CREATE TABLE cves (
  id SERIAL PRIMARY KEY,
  uuid text UNIQUE,
  name text,
  comment text,
  description text,
  creation_time integer,
  modification_time integer,
  vector text,
  complexity text,
  authentication text,
  confidentiality_impact text,
  integrity_impact text,
  availability_impact text,
  products text,
  cvss FLOAT DEFAULT 0
);
CREATE UNIQUE INDEX cve_idx ON cves (name);
CREATE INDEX cves_by_creation_time ON cves (creation_time);
CREATE INDEX cves_by_creation_time_idx ON cves (creation_time);
CREATE INDEX cves_by_modification_time_idx ON cves (modification_time);
CREATE INDEX cves_by_cvss ON cves (cvss);

CREATE TABLE cpes (
  id SERIAL PRIMARY KEY,
  uuid text UNIQUE,
  name text,
  comment text,
  creation_time integer,
  modification_time integer,
  title text,
  status text,
  deprecated_by_id INTEGER,
  max_cvss FLOAT DEFAULT 0,
  cve_refs INTEGER DEFAULT 0,
  nvd_id text
);
CREATE UNIQUE INDEX cpe_idx ON cpes (name);
CREATE INDEX cpes_by_creation_time ON cpes (creation_time);
CREATE INDEX cpes_by_creation_time_idx ON cpes (creation_time);
CREATE INDEX cpes_by_modification_time_idx ON cpes (modification_time);
CREATE INDEX cpes_by_cvss ON cpes (max_cvss);

CREATE TABLE affected_products (
  cve INTEGER NOT NULL,
  cpe INTEGER NOT NULL,
  FOREIGN KEY(cve) REFERENCES cves(id),
  FOREIGN KEY(cpe) REFERENCES cpes(id)
);
CREATE INDEX afp_cpe_idx ON affected_products (cpe);
CREATE INDEX afp_cve_idx ON affected_products (cve);

CREATE TABLE ovaldefs (
  id SERIAL PRIMARY KEY,
  uuid text UNIQUE,
  name text, /* OVAL identifier */
  comment text,
  creation_time integer,
  modification_time integer,
  version INTEGER,
  deprecated INTEGER,
  def_class TEXT, /* enum */
  title TEXT,
  description TEXT,
  xml_file TEXT,
  status TEXT,
  max_cvss FLOAT DEFAULT 0,
  cve_refs INTEGER DEFAULT 0
);
CREATE INDEX ovaldefs_idx ON ovaldefs (name);
CREATE INDEX ovaldefs_by_creation_time ON ovaldefs (creation_time);

CREATE TABLE ovalfiles (
  id SERIAL PRIMARY KEY,
  xml_file TEXT UNIQUE
);
CREATE UNIQUE INDEX ovalfiles_idx ON ovalfiles (xml_file);

CREATE TABLE affected_ovaldefs (
  cve INTEGER NOT NULL,
  ovaldef INTEGER NOT NULL,
  FOREIGN KEY(cve) REFERENCES cves(id),
  FOREIGN KEY(ovaldef) REFERENCES ovaldefs(id)
);
CREATE INDEX aff_ovaldefs_def_idx ON affected_ovaldefs (ovaldef);
CREATE INDEX aff_ovaldefs_cve_idx ON affected_ovaldefs (cve);

/* Create deletion triggers. */

CREATE OR REPLACE FUNCTION scap_delete_affected () RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM affected_products where cve = old.id;
  DELETE FROM affected_ovaldefs where cve = old.id;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cves_delete AFTER DELETE ON cves
FOR EACH ROW EXECUTE PROCEDURE scap_delete_affected ();

CREATE OR REPLACE FUNCTION scap_update_cpes () RETURNS TRIGGER AS $$
BEGIN
  UPDATE cpes SET max_cvss = 0.0 WHERE id = old.cpe;
  UPDATE cpes SET cve_refs = cve_refs -1 WHERE id = old.cpe;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER affected_delete AFTER DELETE ON affected_products
FOR EACH ROW EXECUTE PROCEDURE scap_update_cpes ();

CREATE OR REPLACE FUNCTION scap_delete_oval () RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM ovaldefs WHERE ovaldefs.xml_file = old.xml_file;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER ovalfiles_delete AFTER DELETE ON ovalfiles
FOR EACH ROW EXECUTE PROCEDURE scap_delete_oval ();

CREATE OR REPLACE FUNCTION scap_update_oval () RETURNS TRIGGER AS $$
BEGIN
  UPDATE ovaldefs SET max_cvss = 0.0 WHERE id = old.ovaldef;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER affected_ovaldefs_delete AFTER DELETE ON affected_ovaldefs
FOR EACH ROW EXECUTE PROCEDURE scap_update_oval ();
