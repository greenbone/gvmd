/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: SQL backend headers.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2010 Greenbone Networks GmbH
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

#ifndef OPENVAS_MANAGER_MANAGE_SQL_H
#define OPENVAS_MANAGER_MANAGE_SQL_H

#include "manage.h"

void init_task_file_iterator (iterator_t *, task_t, const char *);
const char *task_file_iterator_name (iterator_t *);
const char *task_file_iterator_content (iterator_t *);

void init_otp_pref_iterator (iterator_t *, config_t, const char *);
const char *otp_pref_iterator_name (iterator_t *);
const char *otp_pref_iterator_value (iterator_t *);

void sql (char *, ...);

lsc_credential_t target_lsc_credential (target_t);
const char* lsc_credential_iterator_password (iterator_t *);

int create_report (task_t, char **, task_status_t);

char *escalator_data (escalator_t, const char *, const char *);

#endif /* not OPENVAS_MANAGER_MANAGE_SQL_H */
