/* Copyright (C) 2021-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Debug utilties and Sentry integration
 */

#include "debug_utils.h"

#include <gvm/base/logging.h>
#include <stdio.h> /* for snprintf */
#include <stdlib.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md  utils"

/**
 * @brief Initialize Sentry using the current gvmd version and DSN.
 *
 * The DSN is set via the environment variable SENTRY_DSN_GVMD.
 *
 * @return 1 if sentry support was enabled, 0 if not.
 */
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
