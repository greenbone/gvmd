/* 
 * OpenVAS
 * $Id:$
 * Description: SCAP database migration script (version 5 to 6)
 *
 * Authors:
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2011-2012 Greenbone Networks GmbH
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

BEGIN TRANSACTION;
 
CREATE TABLE ovaldefs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid UNIQUE,
  name UNIQUE, /* OVAL identifier */
  comment,
  creation_time DATE, /* OVAL timestamp */
  modification_time DATE, /* OVAL timestamp */
  version INTEGER,
  deprecated BOOLEAN,
  def_class TEXT, /* enum */ 
  title TEXT,
  description TEXT
);
CREATE UNIQUE INDEX ovaldefs_idx ON ovals (name);

INSERT INTO ovaldefs (
  uuid,
  name,
  creation_time,
  modification_time,
  version,
  deprecated,
  def_class,
  title,
  description
)
SELECT
  oval_id,
  oval_id,
  oval_timestamp,
  oval_timestamp,
  version,
  deprecated,
  def_class, 
  title,
  description
FROM 
  oval_def;

DROP INDEX IF EXISTS oval_def_idx;
DROP TABLE oval_def;

UPDATE meta SET value ='6' WHERE name = 'database_version';

COMMIT;