/* OpenVAS Manager trace printing facility.
 * $Id$
 * Description: A printf like macro for tracing.
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

/**
 * @file tracef.h
 * @brief A printf like macro for tracing.
 */

#ifndef OPENVAS_MANAGER_TRACE_H
#define OPENVAS_MANAGER_TRACE_H

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 *
 * Libraries can override this by setting it after including tracef.h.
 */
#define G_LOG_DOMAIN "md   main"

#include <strings.h>
#include <glib.h>

/**
 * @brief Flag with all Glib log levels.
 */
#define ALL_LOG_LEVELS  (G_LOG_LEVEL_DEBUG      \
                         | G_LOG_LEVEL_INFO     \
                         | G_LOG_LEVEL_MESSAGE  \
                         | G_LOG_LEVEL_WARNING  \
                         | G_LOG_LEVEL_CRITICAL \
                         | G_LOG_LEVEL_ERROR    \
                         | G_LOG_FLAG_FATAL     \
                         | G_LOG_FLAG_RECURSION)

#ifndef TRACE
/**
 * @brief Trace flag.
 *
 * 0 to turn off all tracing messages.
 */
#define TRACE 1
#endif

/**
 * @brief Trace text flag.
 *
 * 0 to turn off echoing of actual data transfered (requires TRACE).
 */
#define TRACE_TEXT 1

/**
 * @brief Verbose output flag.
 */
extern int verbose;

/**
 * @brief Logging parameters, as passed to setup_log_handlers.
 */
extern GSList *log_config;

#if TRACE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * @brief Formatted trace output.
 *
 * Print the printf style \a args to stderr, preceded by the process ID.
 */
#define tracef(args...)                                          \
  do {                                                           \
    if (verbose)                                                 \
      {                                                          \
        /* UTF-8 hack: Convert log message to utf-8, in case it  \
         * contains server input. */                             \
        gsize size_dummy;                                        \
        gchar* iso = g_strdup_printf (args);                     \
        gchar* utf8 = g_convert (iso, -1, "UTF-8", "ISO_8859-1", \
                                 NULL, &size_dummy, NULL);       \
        g_free (iso);                                            \
        g_log (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, "%s", utf8);     \
        g_free (utf8);                                           \
      }                                                          \
  } while (0)
#else
/**
 * @brief Dummy macro, enabled with TRACE.
 */
#define tracef(format, args...)
#endif

#endif
