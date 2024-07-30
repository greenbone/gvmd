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
 * @file ipc.c
 * @brief Inter-process communitcation (IPC)
 */

/**
 * @brief Enable extra GNU functions.
 *
 * semtimedop needs this
 */
#define _GNU_SOURCE

#include <errno.h>
#include <sys/sem.h>

#include "ipc.h"
#include "manage.h"


/**
 * @brief System V semaphore set key for gvmd actions.
 */
static key_t semaphore_set_key = -1;

/**
 * @brief System V semaphore set id for gvmd actions.
 */
static int semaphore_set = -1;

/**
 * @brief Union type for values of semctl actions
 */
union semun {
    int              val;    ///< Value for SETVAL
    struct semid_ds *buf;    ///< Buffer for IPC_STAT, IPC_SET
    unsigned short  *array;  ///< Array for GETALL, SETALL
    struct seminfo  *__buf;  ///< Buffer for IPC_INFO (Linux-specific)
};

/**
 * @brief Initializes the semaphore set for gvmd actions.
 *
 * Needs max_concurrent_scan_updates to be set.
 *
 * @return 0 success, -1 error
 */
int
init_semaphore_set ()
{
  // Ensure semaphore set file exists
  gchar *key_file_name = g_build_filename (GVM_STATE_DIR, "gvmd.sem", NULL);
  FILE *key_file = fopen (key_file_name, "a");
  union semun sem_value;
  if (key_file == NULL)
    {
      g_warning ("%s: error creating semaphore file %s: %s",
                 __func__, key_file_name, strerror (errno));
      g_free (key_file_name);
      return -1;
    }
  fclose (key_file);
  semaphore_set_key = ftok (key_file_name, 0);
  if (semaphore_set_key < 0)
    {
      g_warning ("%s: error creating semaphore key for file %s: %s",
                 __func__, key_file_name, strerror (errno));
      g_free (key_file_name);
      return -1;
    }

  semaphore_set = semget (semaphore_set_key, 1, 0660 | IPC_CREAT);
  if (semaphore_set < 0)
    {
      g_warning ("%s: error getting semaphore set: %s",
                 __func__, strerror (errno));
      g_free (key_file_name);
      return -1;
    }

  g_debug ("%s: Semaphore set created for file '%s', key %x",
             __func__, key_file_name, semaphore_set_key);
  g_free (key_file_name);

  sem_value.val = get_max_concurrent_scan_updates () ?: 1;
  if (semctl (semaphore_set, SEMAPHORE_SCAN_UPDATE, SETVAL, sem_value) == -1)
    {
      g_warning ("%s: error initializing scan update semaphore: %s",
                 __func__, strerror (errno));
      return -1;
    }

  return 0;
}

/**
 * @brief Performs a semaphore operation (signal or wait).
 *
 * A negative op_value will try to decrease the semaphore value
 *  and wait if needed.
 * A positive op_value will increase the semaphore value.
 * Zero as op_value will wait for the semaphore value to become zero.
 *
 * (See semop from sys/sem.h)
 *
 * @param[in]  semaphore_index  The index of the semaphore in the gvmd set.
 * @param[in]  op_value   The operation value
 * @param[in]  timeout    Timeout in seconds, 0 for unlimited
 *
 * @return 0 success, 1 timed out, -1 error
 */
int
semaphore_op (semaphore_index_t semaphore_index,
              short int op_value,
              time_t timeout)
{
  int ret;
  struct sembuf op = {
    sem_num: semaphore_index,
    sem_op: op_value,
    sem_flg: SEM_UNDO
  };

  struct timespec ts = {
    tv_nsec: 0,
    tv_sec: timeout,
  };

  ret = semtimedop (semaphore_set, &op, 1, timeout > 0 ? &ts : NULL);
  if (ret)
    {
      if (errno == EAGAIN)
        return 1;
      else
        {
          g_warning ("%s: semaphore operation failed: %s",
                     __func__, strerror (errno));
          return -1;
        }
    }

  return 0;
}
