/*
 * OpenVAS
 * $Id$
 * Description: SCAP database initialization script
 *
 * Authors:
 * Henri Doreau <henri.doreau@greenbone.net>
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011-2012 Greenbone Networks GmbH
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

.output /dev/null
PRAGMA journal_mode=WAL;
.output stdout

/* --- TABLES CREATION --- */
/* delete old tables */
DROP TABLE IF EXISTS cves;
DROP TABLE IF EXISTS cpes;
DROP TABLE IF EXISTS affected_products;
DROP TABLE IF EXISTS meta;
DROP TABLE IF EXISTS oval_def;
DROP TABLE IF EXISTS ovaldefs;
DROP TABLE IF EXISTS ovalfiles;
DROP TABLE IF EXISTS affected_ovaldefs;


/* create new tables and indices */
CREATE TABLE meta (id INTEGER PRIMARY KEY AUTOINCREMENT, name UNIQUE, value);
INSERT INTO meta (name, value) VALUES ("database_version", "15");
INSERT INTO meta (name, value) VALUES ("last_update", "0");

CREATE TABLE cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name,
  comment,
  description,
  creation_time DATE,
  modification_time DATE,
  vector,
  complexity,
  authentication,
  confidentiality_impact,
  integrity_impact,
  availability_impact,
  products,
  cvss FLOAT DEFAULT 0
);
CREATE UNIQUE INDEX cve_idx ON cves (name);
CREATE INDEX cves_by_creation_time_idx ON cves (creation_time);
CREATE INDEX cves_by_modification_time_idx ON cves (modification_time);
CREATE INDEX cves_by_cvss ON cves (cvss);


CREATE TABLE cpes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name,
  comment,
  creation_time DATE,
  modification_time DATE,
  title,
  status,
  deprecated_by_id INTEGER,
  max_cvss FLOAT DEFAULT 0,
  cve_refs INTEGER DEFAULT 0,
  nvd_id
);
CREATE UNIQUE INDEX cpe_idx ON cpes (name);
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
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name, /* OVAL identifier */
  comment,
  creation_time DATE,
  modification_time DATE,
  version INTEGER,
  deprecated BOOLEAN,
  def_class TEXT, /* enum */
  title TEXT,
  description TEXT,
  xml_file TEXT,
  status TEXT,
  max_cvss FLOAT,
  cve_refs INTEGER
);
CREATE INDEX ovaldefs_idx ON ovaldefs (name);

CREATE TABLE ovalfiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
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

/* deletion triggers */
CREATE TRIGGER cves_delete AFTER DELETE ON cves
BEGIN
  DELETE FROM affected_products where cve = old.id;
  DELETE FROM affected_ovaldefs where cve = old.id;
END;

CREATE TRIGGER affected_delete AFTER DELETE ON affected_products
BEGIN
  UPDATE cpes set max_cvss = 0.0 WHERE id = old.cpe;
  UPDATE cpes set cve_refs = cve_refs -1 WHERE id = old.cpe;
END;

CREATE TRIGGER ovalfiles_delete AFTER DELETE ON ovalfiles
BEGIN
  DELETE FROM ovaldefs WHERE ovaldefs.xml_file = old.xml_file;
END;

CREATE TRIGGER affected_ovaldefs_delete AFTER DELETE ON affected_ovaldefs
BEGIN
  UPDATE ovaldefs SET max_cvss = 0.0 WHERE id = old.ovaldef;
END;
