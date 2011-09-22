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


CREATE TABLE  cves (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve VARCHAR(10) UNIQUE NOT NULL,
  last_mod DATE,
  cvss FLOAT,
  description TEXT
);
CREATE UNIQUE INDEX cve_idx ON cves (cve);


CREATE TABLE cpes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(80) UNIQUE NOT NULL
);
CREATE UNIQUE INDEX cpe_idx ON cpes (name);


CREATE TABLE affected_products (
  cve INTEGER NOT NULL,
  cpe INTEGER NOT NULL,
  FOREIGN KEY(cve) REFERENCES cves(id),
  FOREIGN KEY(cpe) REFERENCES cpes(id)
);
CREATE INDEX afp_idx ON affected_products (cve,cpe);

