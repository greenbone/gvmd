/* Test 1 of report_path_task_uuid.
 * $Id$
 * Description: Test report_path_task_uuid with a trailing slash.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../manage.h"

int
main ()
{
  gchar* name = report_path_task_uuid ("/var/lib/openvas/mgr/users/user/tasks/01-abc-02001020/reports/report-id/");
  int ret = strcmp (name, "01-abc-02001020");
  g_free (name);
  if (ret) return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
