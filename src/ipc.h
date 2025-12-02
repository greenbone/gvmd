/* Copyright (C) 2024 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Headers for inter-process communitcation (IPC)
 */

#ifndef _GVMD_IPC_H
#define _GVMD_IPC_H

#include <time.h>

typedef enum {
  SEMAPHORE_SCAN_UPDATE = 0,
  SEMAPHORE_DB_CONNECTIONS = 1,
  SEMAPHORE_REPORTS_PROCESSING = 2,
  SEMAPHORE_SET_SIZE = 3
} semaphore_index_t;

int
init_semaphore_set ();

int
semaphore_op (semaphore_index_t, short int, time_t);

int
reinit_semaphore_set ();

#endif /* not _GVMD_IPC_H */
