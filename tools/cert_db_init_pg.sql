 /*
 * OpenVAS
 * $Id: cert_db_init.sql 15096 2013-01-10 10:16:01Z timopollmeier $
 * Description: Postgres CERT database initialization script
 *
 * Authors:
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
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

DROP SCHEMA IF EXISTS cert CASCADE;
CREATE SCHEMA cert;
SET search_path TO cert;

/* Create new tables and indices. */

CREATE TABLE meta (id SERIAL PRIMARY KEY, name text UNIQUE, value text);
INSERT INTO meta (name, value) VALUES ('database_version', '6');
INSERT INTO meta (name, value) VALUES ('last_update', '0');

CREATE TABLE cert_bund_advs (
  id SERIAL PRIMARY KEY,
  uuid text UNIQUE,
  name text UNIQUE,
  comment TEXT,
  creation_time integer,
  modification_time integer,
  title TEXT,
  summary TEXT,
  cve_refs INTEGER,
  max_cvss FLOAT
);
CREATE UNIQUE INDEX cert_bund_advs_idx ON cert_bund_advs (name);
CREATE INDEX cert_bund_advs_by_creation_time ON cert_bund_advs (creation_time);

CREATE TABLE cert_bund_cves (
  adv_id INTEGER,
  cve_name VARCHAR(20)
);
CREATE INDEX cert_bund_cves_adv_idx ON cert_bund_cves (adv_id);
CREATE INDEX cert_bund_cves_cve_idx ON cert_bund_cves (cve_name);

CREATE TABLE dfn_cert_advs (
  id SERIAL PRIMARY KEY,
  uuid text UNIQUE,
  name text UNIQUE,
  comment TEXT,
  creation_time integer,
  modification_time integer,
  title TEXT,
  summary TEXT,
  cve_refs INTEGER,
  max_cvss FLOAT
);
CREATE UNIQUE INDEX dfn_cert_advs_idx ON dfn_cert_advs (name);
CREATE INDEX dfn_cert_advs_by_creation_time ON dfn_cert_advs (creation_time);

CREATE TABLE dfn_cert_cves (
  adv_id INTEGER,
  cve_name text
);
CREATE INDEX dfn_cert_cves_adv_idx ON dfn_cert_cves (adv_id);
CREATE INDEX dfn_cert_cves_cve_idx ON dfn_cert_cves (cve_name);

/* Create deletion triggers. */

CREATE OR REPLACE FUNCTION cert_delete_bund_adv () RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM cert_bund_cves where adv_id = old.id;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER bund_delete AFTER DELETE ON cert_bund_advs
FOR EACH ROW EXECUTE PROCEDURE cert_delete_bund_adv ();

CREATE OR REPLACE FUNCTION cert_delete_cve () RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM dfn_cert_cves where adv_id = old.id;
  RETURN old;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER cve_delete AFTER DELETE ON dfn_cert_advs
FOR EACH ROW EXECUTE PROCEDURE cert_delete_cve ();
