/* 
 * OpenVAS
 * $Id$
 * Description: SCAP database initialization script
 *
 * Authors:
 * Henri Doreau <henri.doreau@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011 Greenbone Networks GmbH
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
DROP TABLE IF EXISTS cves;
DROP TABLE IF EXISTS cpes;
DROP TABLE IF EXISTS affected_products;

CREATE TABLE meta (id INTEGER PRIMARY KEY AUTOINCREMENT, name UNIQUE, value);
INSERT INTO meta (name, value) VALUES ("database_version", "1");
INSERT INTO meta (name, value) VALUES ("last_update", "0");

CREATE TABLE cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name,
  comment,
  creation_time DATE,
  modification_time DATE,
  cvss FLOAT DEFAULT 0
);
CREATE UNIQUE INDEX cve_idx ON cves (name);


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
  cve_refs INTEGER DEFAULT 0
);
CREATE UNIQUE INDEX cpe_idx ON cpes (name);


CREATE TABLE affected_products (
  cve INTEGER NOT NULL,
  cpe INTEGER NOT NULL,
  FOREIGN KEY(cve) REFERENCES cves(id),
  FOREIGN KEY(cpe) REFERENCES cpes(id)
);
CREATE INDEX afp_idx ON affected_products (cve,cpe);

CREATE TRIGGER cves_delete AFTER DELETE ON cves
BEGIN
  DELETE FROM affected_products where cve = old.id;
END;

CREATE TRIGGER affected_delete AFTER DELETE ON affected_products
BEGIN
  UPDATE cpes set max_cvss =
  (SELECT max(cvss) FROM cves WHERE id in
    (SELECT cve FROM affected_products WHERE cpe = old.cpe)
  ) WHERE id = old.cpe;
  UPDATE cpes set cve_refs = cve_refs -1 WHERE id = old.cpe;
END;
