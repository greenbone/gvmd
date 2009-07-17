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

#include <strings.h>
#include <glib.h>

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
#define tracef(args...)                                         \
  do {                                                          \
    if (verbose) g_log ("openvasmd", G_LOG_LEVEL_DEBUG, args);  \
  } while (0)
#else
/**
 * @brief Dummy macro, enabled with TRACE.
 */
#define tracef(format, args...)
#endif

#endif
