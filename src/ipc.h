/* Copyright (C) 2024 Greenbone AG
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
 * @file ipc.h
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
