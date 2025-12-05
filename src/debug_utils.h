/* Copyright (C) 2021-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


/**
 * @file
 * @brief Headers for debug utilties and Sentry integration
 */

#ifndef _OPENVAS_DEBUG_UTILS_H
#define _OPENVAS_DEBUG_UTILS_H

#include <gvm/base/gvm_sentry.h> /* for gvm_sentry_init */

int
init_sentry (void);

#endif