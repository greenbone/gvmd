 /*
 * OpenVAS
 * $Id: cert_db_init.sql 15096 2013-01-10 10:16:01Z timopollmeier $
 * Description: CERT database initialization script
 *
 * Authors:
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

/* --- TABLES CREATION --- */
/* delete old tables */
DROP TABLE IF EXISTS meta;
DROP TABLE IF EXISTS cert_bund_advs;
DROP TABLE IF EXISTS cert_bund_cves;
DROP TABLE IF EXISTS dfn_cert_advs;
DROP TABLE IF EXISTS dfn_cert_cves;

/* create new tables and indices */
CREATE TABLE meta (id INTEGER PRIMARY KEY AUTOINCREMENT, name UNIQUE, value);
INSERT INTO meta (name, value) VALUES ("database_version", "4");
INSERT INTO meta (name, value) VALUES ("last_update", "0");

CREATE TABLE dfn_cert_advs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name UNIQUE,
  comment TEXT,
  creation_time DATE,
  modification_time DATE,
  title TEXT,
  summary TEXT,
  cve_refs INTEGER,
  max_cvss FLOAT
);
CREATE UNIQUE INDEX dfn_cert_advs_idx ON dfn_cert_advs (name);

CREATE TABLE dfn_cert_cves (
  adv_id INTEGER,
  cve_name VARCHAR(20)
);
CREATE INDEX dfn_cert_cves_adv_idx ON dfn_cert_cves (adv_id);
CREATE INDEX dfn_cert_cves_cve_idx ON dfn_cert_cves (cve_name);

/* deletion triggers */
CREATE TRIGGER dfn_cert_adv_delete AFTER DELETE ON dfn_cert_advs
BEGIN
  DELETE FROM dfn_cert_cves where adv_id = old.id;
END;