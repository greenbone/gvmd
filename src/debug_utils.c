/* Copyright (C) 2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file debug_utils.c
 * @brief Debug utilties and Sentry integration
 */

#include "debug_utils.h"

#include <gvm/base/logging.h>
#include <stdio.h> /* for snprintf */
#include <stdlib.h>

int
init_sentry (void)
{
  char *sentry_dsn_gvmd = NULL;
  char version[96];

  snprintf (version, sizeof (version), "gvmd@%s", GVMD_VERSION);

  sentry_dsn_gvmd = getenv ("SENTRY_DSN_GVMD");
  if (gvm_has_sentry_support () && sentry_dsn_gvmd && *sentry_dsn_gvmd)
    {
      gvm_sentry_init (sentry_dsn_gvmd, version);
      return 1;
    }
  return 0;
}
