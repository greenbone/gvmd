/* OpenVAS Manager
 * $Id$
 * Description: Main module for OpenVAS Manager: the system daemon.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2008 Intevation GmbH
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

/** @file openvasmd.c
 *  \brief The OpenVAS Manager
 *
 *  This file defines the OpenVAS Manager, a daemon that is layered between
 *  the real OpenVAS Server (openvasd) and a client (e.g.
 *  OpenVAS-Client).
 */

/** \mainpage
 *
 *  \section Introduction
 *  \verbinclude README
 *
 *  \section manpages Manual Pages
 *  \subpage manpage
 *
 *  \section Installation
 *  \verbinclude INSTALL
 *
 *  \section Implementation
 *  \ref openvasmd.c
 */

/** \page manpage openvasmd
 *  \htmlinclude openvasmd.html
 */

// FIX for asprintf
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openvas/network.h>
#include <openvas/plugutils.h>

/** The name of this program.
 * \todo Use `program_invocation[_short]_name'? */
#define PROGNAME "openvasmd"

/** The version number of this program. */
#ifndef OPENVASMD_VERSION
#define OPENVASMD_VERSION "FIX"
#endif

/** The name of the underlying Operating System. */
#ifndef OPENVAS_OS_NAME
#define OPENVAS_OS_NAME "FIX"
#endif

/** Manager (openvasmd) address. */
#define OPENVASMD_ADDRESS "127.0.0.1"

/** Server (openvasd) address. */
#define OPENVASD_ADDRESS "127.0.0.1"

/** Location of server certificate. */
#ifndef SERVERCERT
#define SERVERCERT "/var/lib/openvas/CA/servercert.pem"
#endif

/** Location of server certificate private key. */
#ifndef SERVERKEY
#define SERVERKEY  "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/** Location of Certificate Authority certificate. */
#ifndef CACERT
#define CACERT     "/var/lib/openvas/CA/cacert.pem"
#endif

/** Server port.  Used if /etc/services "openvas" and -port missing. */
#define OPENVASD_PORT 1241

/** Manager port.  Used if /etc/services "omp" and -sport are missing. */
#define OPENVASMD_PORT 1241

/** The size of the data buffers.  When the client/server buffer is full
  * `select' stops watching for input from the client/server.
  */
//#define BUFFER_SIZE 8192
#define BUFFER_SIZE 8192000

/** Second argument to `listen'. */
#define MAX_CONNECTIONS 512

/** OMP flag.  Enables handling of OpenVAS Management Protocol.
  * If 0 then OMP is turned off.
  */
#define OMP 1

/** Logging flag.  All data transfered to and from the client is logged to
  * a file.  If 0 then logging is turned off.
  */
#define LOG 1

/** Name of log file. */
#define LOG_FILE "/tmp/openvasmd.log"

/** Trace flag.  0 to turn off all tracing messages. */
#define TRACE 1

/** Trace text flag.  0 to turn off echoing of actual data transfered
  * (requires TRACE). */
#define TRACE_TEXT 1

/** Security flag.  0 to turn off all security (i.e. TLS). */
#define OVAS_SSL 1

#if OVAS_SSL
#include <gnutls/gnutls.h>
#endif

#if BUFFER_SIZE > SSIZE_MAX
#error BUFFER_SIZE too big for `read'
#endif

#if TRACE
/** Formatted trace output.
  * Prints the printf style \a args to stderr, preceded by the process ID. */
#define tracef(args...)                   \
  do {                                    \
    fprintf (stderr, "%7i  ", getpid());  \
    fprintf (stderr, args);               \
    fflush (stderr);                      \
  } while (0)
#else
/** Dummy macro, enabled with TRACE. */
#define tracef(format, args...)
#endif

#if LOG
/** Formatted logging output.
  * Prints the printf style \a args to log_stream, preceded by the process ID. */
#define logf(args...)                         \
  do {                                        \
    fprintf (log_stream, "%7i  ", getpid());  \
    fprintf (log_stream, args);               \
    fflush (log_stream);                      \
  } while (0)
#else
/** Dummy macro, enabled with LOG. */
#define logf(format, args...)
#endif

/** The socket accepting OMP connections from clients. */
int manager_socket = -1;

/** The IP address of this program, "the manager". */
struct sockaddr_in manager_address;

/** The IP address of openvasd, "the server". */
struct sockaddr_in server_address;

#if LOG
/** The log stream. */
FILE* log_stream = NULL;
#endif

#if OVAS_SSL
/* The server context. */
static ovas_server_context_t server_context = NULL;
#endif

/** File descriptor set mask: selecting on client read. */
#define FD_CLIENT_READ  1
/** File descriptor set mask: selecting on client write. */
#define FD_CLIENT_WRITE 2
/** File descriptor set mask: selecting on server read. */
#define FD_SERVER_READ  4
/** File descriptor set mask: selecting on server write. */
#define FD_SERVER_WRITE 8

typedef enum
{
  PROTOCOL_OTP,
  PROTOCOL_OMP,
  PROTOCOL_CLOSE,
  PROTOCOL_FAIL
} protocol_read_t;

char from_client[BUFFER_SIZE];
char from_server[BUFFER_SIZE];
char to_server[BUFFER_SIZE];
char to_client[BUFFER_SIZE];
// FIX just make pntrs?
int from_client_end = 0, from_server_end = 0;
int from_client_start = 0, from_server_start = 0;
int to_server_start = 0, to_server_end = 0;
int to_client_start = 0, to_client_end = 0;

char* login = NULL;
char* credentials = NULL;

int server_initialising = 0;


/* Helper functions. */

/** Return \ref string moved past any spaces, replacing with a terminating
    NULL the first of any contiguos spaces at or before \ref end. */
char*
strip_space (char* string, char* end)
{
  while (string[0] == ' ') string++;
  char *last = end, *new_end = end;
  new_end--;
  while (new_end > string && new_end[0] == ' ') { last--; new_end--; }
  if (last < end) last[0] = '\0';
  return string;
}


/* Server. */

typedef struct
{
  char* plugins_md5;
} server_t;

server_t server;

typedef enum
{
  SERVER_TOP,
  SERVER_SERVER,
  SERVER_DONE,
  SERVER_PLUGINS_MD5
} server_state_t;

server_state_t server_state = SERVER_TOP;


/* Tasks. */

typedef struct
{
  unsigned int id;
  char* name;          /* NULL if free. */
  unsigned int time;
  char* comment;
  char* description;
  int description_length;
  int description_size;
  short running;
} task_t;

#define TASKS_INCREMENT 1024
task_t* current_client_task = NULL;
task_t* current_server_task = NULL;
task_t* tasks = NULL;
unsigned int tasks_size = 0;
unsigned int num_tasks = 0;

#if TRACE
void
print_tasks ()
{
  task_t *index = tasks;
  tracef ("tasks: %p\n", tasks);
  tracef ("tasks end: %p\n", tasks + tasks_size);
  while (index < tasks + tasks_size)
    {
      //tracef ("index: %p\n", index);
      if (index->name)
        {
          tracef ("Task %u: \"%s\" %s\n%s\n\n",
                  index->id,
                  index->name,
                  index->comment ?: "",
                  index->description ?: "");
        }
      index++;
    }
}
#endif

int
grow_tasks ()
{
  tracef ("task_t size: %i\n", sizeof (task_t));
  task_t* new = realloc (tasks,
                         (tasks_size + TASKS_INCREMENT) * sizeof (task_t));
  if (new == NULL) return -1;
  tasks = new;

  /* Clear the new part of the memory. */
  new = tasks + tasks_size;
  memset (new, '\0', TASKS_INCREMENT * sizeof (task_t));

  tasks_size += TASKS_INCREMENT;
  tracef ("tasks grown to %i\n", tasks_size);
#if TRACE
  print_tasks ();
#endif
  return 0;
}

void
free_tasks ()
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name)
        {
          tracef ("Freeing task %u: \"%s\" %s (%i)\n%s\n\n",
                  index->id,
                  index->name,
                  index->comment,
                  index->description_length,
                  index->description);
          free (index->name);
          free (index->comment);
          free (index->description);
        }
      index++;
    }
  tasks_size = 0;
  free (tasks);
  tasks = NULL;
}

task_t*
make_task (char* name, unsigned int time, char* comment)
{
  tracef ("make_task %s %u %s\n", name, time, comment);
  if (tasks == NULL && grow_tasks ()) return NULL;
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
 retry:
  while (index < end)
    {
      if (index->name == NULL)
        {
          index->id = index - tasks;
          index->name = name;
          index->time = time;
          index->comment = comment;
          index->description = NULL;
          index->description_size = 0;
          index->running = 0;
          tracef ("Made task %i at %p\n", index->id, index);
          num_tasks++;
          return index;
        }
      index++;
    }
  index = (task_t*) tasks_size;
  if (grow_tasks ()) return NULL;
  index = index + (int) tasks;
  goto retry;
}

task_t*
find_task (unsigned int id)
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end) {
    if (index->name) tracef ("%u vs %u\n", index->id, id);
    if (index->name && index->id == id) return index; else index++;
  }
  return NULL;
}

void
modify_task (task_t* task, char* name, unsigned int time, char* comment)
{
  assert (task->name);
  tracef ("modify_task %u\n", task->id);
  task->name = name;
  task->time = time;
  task->comment = comment;
  task->description_length = 0;
}

#define TO_SERVER(msg)                                            \
  do                                                              \
    {                                                             \
      if (BUFFER_SIZE - to_server_end < strlen (msg)) goto fail;  \
      memcpy (to_server + to_server_end, msg, strlen (msg));      \
      tracef ("-> server: %s\n", msg);                            \
      to_server_end += strlen (msg);                              \
    }                                                             \
  while (0)

int
start_task (task_t* task)
{
  tracef ("start task %u\n", task->id);

  TO_SERVER ("CLIENT <|> PREFERENCES <|>\n");
  TO_SERVER ("plugin_set <|> ");
#if 0
  TO_SERVER (task_plugins (task));
#endif
  TO_SERVER ("\n");
#if 0
  queue_task_preferences (task);
  queue_task_plugin_preferences (task);
#endif
  TO_SERVER ("<|> CLIENT\n");

  TO_SERVER ("CLIENT <|> RULES <|>\n");
#if 0
  queue_task_rules (task);
#endif
  TO_SERVER ("<|> CLIENT\n");

#if 0
  char* targets = task_preference (task, "targets");
  TO_SERVER ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n<|> CLIENT",
             strlen (targets), targets);
#else
  TO_SERVER ("CLIENT <|> LONG_ATTACK <|>\n6\nchiles\n<|> CLIENT");
#endif

  task->running = 1;

  return 0;

 fail:
  return -1;
}

#define DESCRIPTION_INCREMENT 4096

int
grow_description (task_t* task)
{
  int new_size = task->description_size + DESCRIPTION_INCREMENT;
  char* new = realloc (task->description, new_size);
  if (new == NULL) return -1;
  task->description = new;
  task->description_size = new_size;
  return 0;
}

int
add_task_description_line (task_t* task, char* line, int line_length)
{
  assert (task->name);
  if (task->description_size - task->description_length < line_length
      && grow_description (task))
    return -1;
  char* description = task->description;
  description += task->description_length;
  strncpy (description, line, line_length);
  task->description_length += line_length;
  return 0;
}


/* OpenVAS Transfer Protocol (OTP). */

/** Serve the OpenVAS Transfer Protocol (OTP).
  *
  * @param[in]  client_session  The TLS session with the client.
  * @param[in]  server_session  The TLS session with the server.
  * @param[in]  client_socket   The socket connected to the client.
  * @param[in]  server_socket   The socket connected to the server.
  *
  * \return 0 on success, -1 on error.
  */
int
serve_otp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           int client_socket, int server_socket)
{
  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %i bytes\n", from_client_end - initial_start);
#endif
#endif /* TRACE || LOG */

  /* Loop handling input from the sockets. */
  int nfds = 1 + (client_socket > server_socket
                  ? client_socket : server_socket);
  fd_set readfds, exceptfds, writefds;
  while (1)
    {
      /* Setup for select. */
      unsigned char fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      if (from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
        }
      if (from_server_end < BUFFER_SIZE)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
        }
      if (from_server_start < from_server_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (from_client_start < from_client_end)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }

      /* Select, then handle result. */
      int ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          return -1;
        }
      if (ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on client in child select.\n");
              return -1;
            }

          if (FD_ISSET (server_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on server in child select.\n");
              return -1;
            }

          if (fds & FD_CLIENT_READ && FD_ISSET (client_socket, &readfds))
            {
#if TRACE || LOG
              int initial_start = from_client_end;
#endif
              /* Read as much as possible from the client. */
              while (from_client_end < BUFFER_SIZE)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_recv (*client_session,
                                              from_client + from_client_end,
                                              BUFFER_SIZE
                                              - from_client_end);
#else
                  count = read (client_socket,
                                from_client + from_client_end,
                                BUFFER_SIZE - from_client_end);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from client.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      perror ("Failed to read from client");
#endif
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_client_end += count;
                }
#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
                 error" case. */
              if (from_client_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#if TRACE_TEXT
                  tracef ("<= client  \"%.*s\"\n",
                          from_client_end - initial_start,
                          from_client + initial_start);
#else
                  tracef ("<= client  %i bytes\n",
                          from_client_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */
            }

          if (fds & FD_SERVER_WRITE && FD_ISSET (server_socket, &writefds))
            {
              /* Write as much as possible to the server. */
              while (from_client_start < from_client_end)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_send (*server_session,
                                              from_client + from_client_start,
                                              from_client_end - from_client_start);
#else
                  count = write (server_socket,
                                 from_client + from_client_start,
                                 from_client_end - from_client_start);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_server_fd_write;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to server.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_server_fd_write;
                      if (errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      perror ("Failed to write to server");
#endif
                      return -1;
                    }
                  from_client_start += count;
                  tracef ("=> server  %i bytes\n", count);
                }
              tracef ("=> server  done\n");
              from_client_start = from_client_end = 0;
             end_server_fd_write:
              ;
            }

          if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
            {
#if TRACE
              int initial_start = from_server_end;
#endif
              /* Read as much as possible from the server. */
              while (from_server_end < BUFFER_SIZE)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_recv (*server_session,
                                              from_server + from_server_end,
                                              BUFFER_SIZE
                                              - from_server_end);
#else
                  count = read (server_socket,
                                from_server + from_server_end,
                                BUFFER_SIZE - from_server_end);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from server.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (errno == EINTR)
                        /* Interrupted, try read again. */
                        continue;
                      perror ("Failed to read from server");
#endif
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_server_end += count;
                }
#if TRACE
              /* This check prevents output in the "asynchronous network
                 error" case. */
              if (from_server_end > initial_start)
                {
#if TRACE_TEXT
                  tracef ("<= server  \"%.*s\"\n",
                          from_server_end - initial_start,
                          from_server + initial_start);
#else
                  tracef ("<= server  %i bytes\n",
                          from_server_end - initial_start);
#endif
                }
#endif /* TRACE */
            }

          if (fds & FD_CLIENT_WRITE && FD_ISSET (client_socket, &writefds))
            {
              /* Write as much as possible to the client. */
              while (from_server_start < from_server_end)
                {
                  ssize_t count;
#if OVAS_SSL
                  count = gnutls_record_send (*client_session,
                                              from_server + from_server_start,
                                              from_server_end - from_server_start);
#else
                  count = write (client_socket,
                                 from_server + from_server_start,
                                 from_server_end - from_server_start);
#endif
                  if (count < 0)
                    {
#if OVAS_SSL
                      if (count == GNUTLS_E_AGAIN || errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_client_fd_write;
                      if (count == GNUTLS_E_INTERRUPTED || errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      if (errno == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to client.\n");
                      gnutls_perror (count);
#else
                      if (errno == EAGAIN)
                        /* Wrote as much as possible, return to `select'. */
                        goto end_client_fd_write;
                      if (errno == EINTR)
                        /* Interrupted, try write again. */
                        continue;
                      perror ("Failed to write to client");
#endif
                      return -1;
                    }
                  logf ("=> %.*s\n",
                        from_server_end - from_server_start,
                        from_server + from_server_start);
                  from_server_start += count;
                  tracef ("=> client  %i bytes\n", count);
                }
              tracef ("=> client  done\n");
              from_server_start = from_server_end = 0;
             end_client_fd_write:
              ;
            }
        }
    }
}


/* OpenVAS Management Protocol (OMP). */

#define RESPOND(msg)                                              \
  do                                                              \
    {                                                             \
      if (BUFFER_SIZE - to_client_end < strlen (msg)) goto fail;  \
      memcpy (to_client + to_client_end, msg, strlen (msg));      \
      tracef ("-> client: %s\n", msg);                            \
      to_client_end += strlen (msg);                              \
    }                                                             \
  while (0)

/** Process any lines available in from_client, writing any
  * resulting server commands to to_server and any replies for the client
  * to to_client.
  *
  * \return 0 on success, -1 on error (e.g. too little buffer space for response).
  */
int process_omp_client_input ()
{
  char* messages = from_client + from_client_start;
  //tracef ("consider %.*s\n", from_client_end - from_client_start, messages);
  while (memchr (messages, 10, from_client_end - from_client_start))
    {
      /* Found a full line, process the message. */
      char* command;
      tracef ("messages: %.*s...\n",
              from_client_end - from_client_start < 200
              ? from_client_end - from_client_start
              : 200,
              messages);
      char* message = strsep (&messages, "\n");
      tracef ("message: %s\n", message);
      from_client_start += strlen(message) + 1;

      if (current_client_task)
        {
          /* A NEW_TASK or MODIFY_TASK description is being read. */

          if (strlen (message) == 1 && message[0] == '.')
            {
              /* End of description marker. */
              char response[16];
              sprintf (response, "201 %i\n", current_client_task->id);
              RESPOND (response);
              current_client_task = NULL;
              continue;
            }
          else if (strlen (message) > 1 && message[0] == '.')
            {
              /* Line of description starting with a '.'.  The client is
                 required to add an extra '.' to the front of the line. */
              message += 1;
            }

          if (add_task_description_line (current_client_task,
                                         message,
                                         messages - message))
            goto out_of_memory;

          continue;
        }

      command = strsep (&message, " ");
      tracef ("command: %s\n", command);

      if (strncasecmp ("OMP_VERSION", command, 11) == 0)
        RESPOND ("200 1.0\n");
      else if (strncasecmp ("LOGIN", command, 5) == 0)
        {
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            RESPOND ("403 LOGIN requires a username.\n");
          else
            {
              if (login) free (login);
              login = strdup (next);
              if (login == NULL) goto out_of_memory;
              next = strsep (&message, " ");
              if (next && strlen (next) > 0)
                {
                  if (credentials) free (credentials);
                  credentials = strdup (next);
                  if (credentials == NULL) goto out_of_memory;
                }
              RESPOND ("200\n");
            }
        }
      else if (login == NULL)
        RESPOND ("401 LOGIN first.\n");
      else if (strncasecmp ("NEW_TASK", command, 8) == 0)
        {
          /* Scan name. */
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("404 NEW_TASK requires a name.\n");
              continue;
            }
          tracef ("next %s\n", next);
          // FIX parse name with spaces
          char* name = strdup (next);
          if (name == NULL) goto out_of_memory;
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 NEW_TASK requires a time.\n");
              continue;
            }
          tracef ("next %s\n", next);
          /* Scan time. */
          int time;
          if (sscanf (next, "%u", &time) != 1)
            {
              // FIX flush rest of command
              RESPOND ("406 Failed to parse ID.\n");
              continue;
            }
          /* Scan comment. */
          char* comment = strdup (message);
          if (comment == NULL)
            {
              free (name);
              goto out_of_memory;
            }
          /* Make task. */
          current_client_task = make_task (name, time, comment);
          if (current_client_task == NULL)
            {
              free (name);
              free (comment);
              goto out_of_memory;
            }
        }
      else if (strncasecmp ("MODIFY_TASK", command, 11) == 0)
        {
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          current_client_task = find_task (id);
          if (current_client_task == NULL)
            {
              RESPOND ("407 Failed to find task.\n");
              // FIX flush rest of command
              continue;
            }
          // -- FIX same as above
          /* Scan name. */
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("404 NEW_TASK requires a name.\n");
              continue;
            }
          // FIX parse name with spaces
          char* name = strdup (next);
          if (name == NULL) goto out_of_memory;
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 NEW_TASK requires a time.\n");
              free (name);
              continue;
            }
          /* Scan time. */
          int time;
          if (sscanf (next, "%u", &time) != 1)
            {
              // FIX flush rest of command
              RESPOND ("406 Failed to parse ID.\n");
              free (name);
              continue;
            }
          /* Scan comment. */
          char* comment = strdup (message);
          if (comment == NULL)
            {
              free (name);
              goto out_of_memory;
            }
          // --
          modify_task (current_client_task, name, time, comment);
        }
      else if (strncasecmp ("START_TASK", command, 10) == 0)
        {
          // -- FIX same as above
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          // --
          current_client_task = find_task (id);
          if (current_client_task == NULL)
            RESPOND ("407 Failed to find task.\n");
          else if (start_task (current_client_task))
            RESPOND ("408 Failed to start task.\n");
          else
            RESPOND ("200\n");
        }
      else if (strncasecmp ("STATUS", command, 6) == 0)
        {
#if 0
          // -- FIX same as above
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          // --
#endif
          char response[16];
          sprintf (response, "210 %u\n", num_tasks);
          RESPOND (response);
          task_t* index = tasks;
          task_t* end = tasks + tasks_size;
          while (index < end)
            {
              if (index->name)
                {
                  char* line;
                  if (asprintf (&line, "%u %s %c . . . . .\n",
                                index->id,
                                index->name,
                                index->running ? 'R' : 'N')
                      == -1)
                      goto fail;
                  RESPOND (line);
                  free (line);
                }
              index++;
            }
        }
      else
        RESPOND ("402 Command name error.\n");

      continue;
 out_of_memory:
      RESPOND ("501 Manager out of memory.\n");
    } /* while (memchr (... */

  if (from_client_start > 0 && from_client_start == from_client_end)
    {
      from_client_start = from_client_end = 0;
      tracef ("start caught end\n");
    }
  else if (from_client_start == 0)
    {
      if (from_client_end == BUFFER_SIZE)
        {
          // FIX if the buffer is entirely full here then respond with err and clear buffer
          //     (or will hang waiting for buffer to empty)
          //     this could happen if the client sends a line len >= buffer len
          //         could realloc buffer
          tracef ("buffer full\n");
          goto fail;
        }
    }
  else
    {
      /* Move the remaining partial line to the front of the buffer.  This
         ensures that there is space after the partial line into which
         serve_omp can read the rest of the line. */
      char* start = from_client + from_client_start;
      from_client_end -= from_client_start;
      memmove (from_client, start, from_client_end);
      from_client_start = 0;
#if TRACE
      from_client[from_client_end] = '\0';
      //tracef ("new from_client: %s\n", from_client);
      tracef ("new from_client_start: %i\n", from_client_start);
      tracef ("new from_client_end: %i\n", from_client_end);
#endif
    }

  return 0;

  /* RESPOND jumps here when there is too little space in to_client for the
     response.  The result is that the manager closes the connection, so
     from_client_end and from_client_start can be left as they are. */
 fail:
  return -1;
}

/** Process any lines available in from_server.
  *
  * \return 0 on success, -1 on error (e.g. too little buffer space in to_client).
  */
int process_omp_server_input ()
{
  char* messages = from_server + from_server_start;
  //tracef ("consider %.*s\n", from_server_end - from_server_start, messages);

  if (server_initialising)
    {
      switch (server_initialising)
        {
          case 1:
            if (strncasecmp ("< OTP/1.0 >\n", messages, 12))
              {
                tracef ("server fail: expected \"< OTP/1.0 >\n\"\n");
                goto fail;
              }
            server_initialising = 2;
            from_server_start += 12;
            break;
          case 2:
            if (strncasecmp ("User : ", messages, 7))
              {
                tracef ("server fail: expected \"User : \"\n");
                goto fail;
              }
            from_server_start += 7;
            TO_SERVER ("mattm\n"); // FIX
            server_initialising = 3;
            return 0;
          case 3:
            if (strncasecmp ("Password : ", messages, 11))
              {
                tracef ("server fail: expected \"Password : \"\n");
                goto fail;
              }
            from_server_start += 11;
            TO_SERVER ("mattm\n"); // FIX
            server_initialising = 0;
            return 0;
          default:
            goto fail;
        }
    }
  else if (server_state == SERVER_DONE)
    {
      char *end;
 server_done:
      end = messages + from_server_end - from_server_start;
      while (messages < end && messages[0] == ' ') messages++;
      if ((int) (end - messages) < 6) return 0;
      if (strncasecmp ("SERVER", messages, 6))
        {
          tracef ("server fail: expected final \"SERVER\"\n");
          goto fail;
        }
      server_state = SERVER_TOP;
      from_server_start += 6;

      tracef ("server:: new state %i\n", server_state);
    }

  char* match;
  while ((match = memchr (messages, '<', from_server_end - from_server_start))
         && (((int) (match - messages) - from_server_start + 1) < from_server_end)
         && (match[1] == '|')
         && (match[2] == '>'))
    {
      /* Found a full field, process the field. */
      tracef ("server messages: %.*s...\n",
              from_server_end - from_server_start < 200
              ? from_server_end - from_server_start
              : 200,
              messages);
      char* message = messages;
      *match = '\0';
      from_server_start += match + 3 - messages;
      messages = match + 3;
      tracef ("server message: %s\n", message);

      /* Strip leading and trailing whitespace. */
      char* field = strip_space (message,
                                 message + from_server_end - from_server_start);

      tracef ("server:: old state %i\n", server_state);
      tracef ("server:: field %s\n", field);
      switch (server_state)
        {
          case SERVER_DONE:
            if (strncasecmp ("SERVER", field, 6))
              goto fail;
            server_state = SERVER_TOP;
            break;
          case SERVER_PLUGINS_MD5:
            {
              char* md5 = strdup (field);
              if (md5 == NULL)
                goto out_of_memory;
              tracef ("server:: got plugins_md5: %s\n", md5);
              server.plugins_md5 = md5;
              server_state = SERVER_DONE;
              /* Jump to the done check, as this loop only considers fields
                 ending in <|>. */
              tracef ("server:: new state %i\n", server_state);
              goto server_done;
            }
          case SERVER_SERVER:
            if (strncasecmp ("PLUGINS_MD5", field, 11))
              goto fail;
            server_state = SERVER_PLUGINS_MD5;
            break;
          default:
            tracef ("switch t\n");
            tracef ("cmp %i\n", strncasecmp ("SERVER", field, 6));
            if (strncasecmp ("SERVER", field, 6))
              goto fail;
            server_state = SERVER_SERVER;
        }
      tracef ("server:: new state %i\n", server_state);
    }

  return 0;

 out_of_memory:
  tracef ("out of mem (server)\n");

  /* TO_SERVER FIX jumps here when there is too little space in to_client for the
     response.  The result is that the manager closes the connection, so
     from_client_end and from_client_start can be left as they are. */
 fail:
  return -1;


}

/** Serve the OpenVAS Management Protocol (OMP).
  *
  * @param[in]  client_session  The TLS session with the client.
  * @param[in]  server_session  The TLS session with the server.
  * @param[in]  client_socket   The socket connected to the client.
  * @param[in]  server_socket   The socket connected to the server.
  *
  * \return 0 on success, -1 on error.
  */
int
serve_omp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           int client_socket, int server_socket)
{
  tracef ("Serving OMP.\n");

  /* Initialise with the server. */
  memcpy (to_server + to_server_end, "< OTP/1.0 >\n", 12);
  tracef ("-> server: < OTP/1.0 >\n");
  to_server_end += 12;
  server_initialising = 1;

  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %i bytes\n", from_client_end - initial_start);
#endif
#endif /* TRACE || LOG */
  if (process_omp_client_input ()) return -1;

  /* Loop handling input from the sockets. */
  int nfds = 1 + (client_socket > server_socket
                  ? client_socket : server_socket);
  fd_set readfds, exceptfds, writefds;
  unsigned char lastfds = 0; // FIX
  while (1)
    {
      /* Setup for select. */
      unsigned char fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      // FIX shutdown if any eg read fails
      if (from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
          if ((lastfds & FD_CLIENT_READ) == 0) tracef ("client read on\n");
        }
      else
        {
          if (lastfds & FD_CLIENT_READ) tracef ("client read off\n");
        }
      if (from_server_end < BUFFER_SIZE)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
        }
      if (to_client_start < to_client_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (to_server_start < to_server_end)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }
      lastfds = fds;

      /* Select, then handle result. */
      int ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          return -1;
        }
      if (ret == 0) continue;

      if (FD_ISSET (client_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on client in child select.\n");
          return -1;
        }

      if (FD_ISSET (server_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on server in child select.\n");
          return -1;
        }

      if (fds & FD_CLIENT_READ && FD_ISSET (client_socket, &readfds))
        {
          tracef ("FD_CLIENT_READ\n");
#if TRACE || LOG
          int initial_start = from_client_end;
#endif
          /* Read as much as possible from the client. */
          while (from_client_end < BUFFER_SIZE)
            {
              ssize_t count;
#if OVAS_SSL
              count = gnutls_record_recv (*client_session,
                                          from_client + from_client_end,
                                          BUFFER_SIZE
                                          - from_client_end);
#else
              count = read (client_socket,
                            from_client + from_client_end,
                            BUFFER_SIZE - from_client_end);
#endif
              tracef ("count: %i\n", count);
              if (count < 0)
                {
#if OVAS_SSL
                  if (count == GNUTLS_E_AGAIN) // || errno == EAGAIN) FIX
                    /* Got everything available, return to `select'. */
                    break;
                  if (count == GNUTLS_E_INTERRUPTED) // || errno == EINTR) FIX
                    /* Interrupted, try read again. */
                    continue;
                  if (errno == GNUTLS_E_REHANDSHAKE)
                    {
                      /* Return to select. TODO Rehandshake. */
                      tracef ("FIX should rehandshake\n");
                      break;
                    }
                  fprintf (stderr, "Failed to read from client.\n");
                  gnutls_perror (count);
#else
                  if (errno == EAGAIN)
                    /* Got everything available, return to `select'. */
                    break;
                  if (errno == EINTR)
                    /* Interrupted, try read again. */
                    continue;
                  perror ("Failed to read from client");
#endif
                  return -1;
                }
              if (count == 0)
                /* End of file. */
                return 0;
              from_client_end += count;
            }
#if TRACE || LOG
          /* This check prevents output in the "asynchronous network
             error" case. */
          if (from_client_end > initial_start)
            {
              logf ("<= %.*s\n",
                    from_client_end - initial_start,
                    from_client + initial_start);
#if TRACE_TEXT
              tracef ("<= client  \"%.*s\"\n",
                      from_client_end - initial_start,
                      from_client + initial_start);
#else
              tracef ("<= client  %i bytes\n",
                      from_client_end - initial_start);
#endif
            }
#endif /* TRACE || LOG */
          if (process_omp_client_input ()) return -1;
        }

      if (fds & FD_SERVER_WRITE && FD_ISSET (server_socket, &writefds))
        {
          /* Write as much as possible to the server. */
          while (to_server_start < to_server_end)
            {
              ssize_t count;
#if OVAS_SSL
              count = gnutls_record_send (*server_session,
                                          to_server + to_server_start,
                                          to_server_end - to_server_start);
#else
              count = write (server_socket,
                             to_server + to_server_start,
                             to_server_end - to_server_start);
#endif
              if (count < 0)
                {
#if OVAS_SSL
                  if (count == GNUTLS_E_AGAIN) // || errno == EAGAIN)
                    /* Wrote as much as possible, return to `select'. */
                    goto end_server_fd_write;
                  if (count == GNUTLS_E_INTERRUPTED) // || errno == EINTR)
                    /* Interrupted, try write again. */
                    continue;
                  if (errno == GNUTLS_E_REHANDSHAKE)
                    /* Return to select. TODO Rehandshake. */
                    break;
                  fprintf (stderr, "Failed to write to server.\n");
                  gnutls_perror (count);
#else
                  if (errno == EAGAIN)
                    /* Wrote as much as possible, return to `select'. */
                    goto end_server_fd_write;
                  if (errno == EINTR)
                    /* Interrupted, try write again. */
                    continue;
                  perror ("Failed to write to server");
#endif
                  return -1;
                }
              to_server_start += count;
              tracef ("=> server  %i bytes\n", count);
            }
          tracef ("=> server  done\n");
          to_server_start = to_server_end = 0;
         end_server_fd_write:
          ;
        }

      if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
        {
#if TRACE
          int initial_start = from_server_end;
#endif
          /* Read as much as possible from the server. */
          while (from_server_end < BUFFER_SIZE)
            {
              ssize_t count;
#if OVAS_SSL
              count = gnutls_record_recv (*server_session,
                                          from_server + from_server_end,
                                          BUFFER_SIZE
                                          - from_server_end);
#else
              count = read (server_socket,
                            from_server + from_server_end,
                            BUFFER_SIZE - from_server_end);
#endif
              if (count < 0)
                {
#if OVAS_SSL
                  if (count == GNUTLS_E_AGAIN) // || errno == EAGAIN)
                    /* Got everything available, return to `select'. */
                    break;
                  if (count == GNUTLS_E_INTERRUPTED) // || errno == EINTR)
                    /* Interrupted, try read again. */
                    continue;
                  if (errno == GNUTLS_E_REHANDSHAKE)
                    /* Return to select. TODO Rehandshake. */
                    break;
                  fprintf (stderr, "Failed to read from server.\n");
                  gnutls_perror (count);
#else
                  if (errno == EAGAIN)
                    /* Got everything available, return to `select'. */
                    break;
                  if (errno == EINTR)
                    /* Interrupted, try read again. */
                    continue;
                  perror ("Failed to read from server");
#endif
                  return -1;
                }
              if (count == 0)
                /* End of file. */
                return 0;
              from_server_end += count;
            }
#if TRACE
          /* This check prevents output in the "asynchronous network
             error" case. */
          if (from_server_end > initial_start)
            {
#if TRACE_TEXT
              tracef ("<= server  \"%.*s\"\n",
                      from_server_end - initial_start,
                      from_server + initial_start);
#else
              tracef ("<= server  %i bytes\n",
                      from_server_end - initial_start);
#endif
            }
#endif /* TRACE */
          if (process_omp_server_input ()) return -1;
        }

      if (fds & FD_CLIENT_WRITE && FD_ISSET (client_socket, &writefds))
        {
          /* Write as much as possible to the client. */
          while (to_client_start < to_client_end)
            {
              ssize_t count;
#if OVAS_SSL
              count = gnutls_record_send (*client_session,
                                          to_client + to_client_start,
                                          to_client_end - to_client_start);
#else
              count = write (client_socket,
                             to_client + to_client_start,
                             to_client_end - to_client_start);
#endif
              if (count < 0)
                {
#if OVAS_SSL
                  if (count == GNUTLS_E_AGAIN) // || errno == EAGAIN)
                    /* Wrote as much as possible, return to `select'. */
                    goto end_client_fd_write;
                  if (count == GNUTLS_E_INTERRUPTED) // || errno == EINTR)
                    /* Interrupted, try write again. */
                    continue;
                  if (errno == GNUTLS_E_REHANDSHAKE)
                    /* Return to select. TODO Rehandshake. */
                    break;
                  fprintf (stderr, "Failed to write to client.\n");
                  gnutls_perror (count);
#else
                  if (errno == EAGAIN)
                    /* Wrote as much as possible, return to `select'. */
                    goto end_client_fd_write;
                  if (errno == EINTR)
                    /* Interrupted, try write again. */
                    continue;
                  perror ("Failed to write to client");
#endif
                  return -1;
                }
              logf ("=> %.*s\n",
                    to_client_end - to_client_start,
                    to_client + to_client_start);
              to_client_start += count;
              tracef ("=> client  %i bytes\n", count);
            }
          tracef ("=> client  done\n");
          to_client_start = to_client_end = 0;
         end_client_fd_write:
          ;
        }
    } /* while (1) */

  return 0;
}


/* Other functions. */

/** Read the protocol from \arg client_session, which is on \arg
  * client_socket.
  *
  * @param[in]  client_session  The TLS session with the client.
  * @param[in]  client_socket   The socket connected to the client.
  *
  * \return PROTOCOL_FAIL, PROTOCOL_CLOSE, PROTOCOL_OTP or PROTOCOL_OMP.
  */
protocol_read_t
read_protocol (gnutls_session_t* client_session, int client_socket)
{
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (client_socket, F_SETFL, 0) == -1)
    {
      perror ("Failed to set client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  /* Read from the client, checking the protocol when a newline or return
     is read. */
  protocol_read_t ret = PROTOCOL_FAIL;
  char* from_client_current = from_client + from_client_end;
  while (from_client_end < BUFFER_SIZE)
    {
      ssize_t count;
 retry:
#if OVAS_SSL
      count = gnutls_record_recv (*client_session,
                                  from_client + from_client_end,
                                  BUFFER_SIZE
                                  - from_client_end);
#else
      count = read (client_socket,
                    from_client + from_client_end,
                    BUFFER_SIZE
                    - from_client_end);
#endif
      if (count < 0)
        {
#if OVAS_SSL
          if (count == GNUTLS_E_INTERRUPTED) // || errno == EINTR)
            /* Interrupted, try read again. */
            goto retry;
          if (errno == GNUTLS_E_REHANDSHAKE)
            /* Try again. TODO Rehandshake. */
            goto retry;
          fprintf (stderr, "Failed to read from client (read_protocol).\n");
          gnutls_perror (count);
#else
          if (errno == EINTR)
            /* Interrupted, try read again. */
            goto retry;
          perror ("Failed to read from client (read_protocol)");
#endif
          break;
        }
      if (count == 0)
        {
          /* End of file. */
          ret = PROTOCOL_CLOSE;
          break;
        }
      from_client_end += count;

      /* Check for newline or return. */
      from_client[from_client_end] = '\0';
      if (strchr (from_client_current, 10) || strchr (from_client_current, 13))
        {
          if (strstr (from_client, "< OTP/1.0 >"))
            ret = PROTOCOL_OTP;
          else
            ret = PROTOCOL_OMP;
          break;
        }
      from_client_current += count;
    }

  // FIX use orig value
  /* Turn blocking back off. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to reset client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  return ret;
}

/** Serve the client.
  *
  * Connect to the openvasd server, then call either \ref serve_otp or \ref
  * serve_omp to serve the protocol, depending on the first message that
  * the client sends.
  *
  * @param[in]  client_socket  The socket connected to the client.
  *
  * \return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
  */
int
serve_client (int client_socket)
{
  int ret;
  int server_socket;

  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      perror ("Failed to create server socket");
      return EXIT_FAILURE;
    }

#if OVAS_SSL
  /* Setup server session. */

  gnutls_certificate_credentials_t server_credentials;
  if (gnutls_certificate_allocate_credentials (&server_credentials))
    {
      fprintf (stderr, "Failed to allocate server credentials.\n");
      goto close_fail;
    }

  gnutls_session_t server_session;
  if (gnutls_init (&server_session, GNUTLS_CLIENT))
    {
      fprintf (stderr, "Failed to initialise server session.\n");
      goto server_free_fail;
    }

  if (gnutls_set_default_priority (server_session))
    {
      fprintf (stderr, "Failed to set server session priority.\n");
      goto server_fail;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (server_session, kx_priority))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }

  if (gnutls_credentials_set (server_session,
                              GNUTLS_CRD_CERTIFICATE,
                              server_credentials))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }
#endif

  /* Connect to the server. */
  if (connect (server_socket,
               (struct sockaddr *) &server_address,
               sizeof (server_address))
      == -1)
    {
      perror ("Failed to connect to server");
      goto server_fail;
    }
  tracef ("Connected to server on socket %i.\n", server_socket);

#if OVAS_SSL
  /* Complete setup of server session. */

  gnutls_transport_set_ptr (server_session,
                            (gnutls_transport_ptr_t) server_socket);

 retry:
  ret = gnutls_handshake (server_session);
  if (ret < 0)
    {
      if (ret == GNUTLS_E_AGAIN
          || ret == GNUTLS_E_INTERRUPTED
#if 0
          || errno == EAGAIN
          || errno == EINTR
#endif
          )
        goto retry;
      fprintf (stderr, "Failed to shake hands with server.\n");
      gnutls_perror (ret);
      if (shutdown (server_socket, SHUT_RDWR) == -1)
        perror ("Failed to shutdown server socket");
      goto server_fail;
    }
#endif

  // FIX get flags first
  // FIX after read_protocol
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set server socket flag");
      goto fail;
    }

#if OVAS_SSL
  /* Get client socket and session from libopenvas. */

  int real_socket = nessus_get_socket_from_connection (client_socket);
  if (real_socket == -1 || real_socket == client_socket)
    {
      perror ("Failed to get client socket from libopenvas");
      goto fail;
    }

  gnutls_session_t* client_session = ovas_get_tlssession_from_connection(client_socket);
  if (client_session == NULL)
    {
      perror ("Failed to get connection from client socket");
      goto fail;
    }
  client_socket = real_socket;

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set real client socket flag");
      goto fail;
    }
  gnutls_transport_set_lowat (*client_session, 0);
#endif

  /* Read a message from the client, and call the appropriate protocol
     handler. */

  switch (read_protocol (client_session, client_socket))
    {
      case PROTOCOL_OTP:
        // FIX OVAL_SSL
        if (serve_otp (client_session, &server_session, client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_OMP:
        // FIX OVAL_SSL
        if (serve_omp (client_session, &server_session, client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_CLOSE:
        goto fail;
      default:
        fprintf (stderr, "Failed to determine protocol.\n");
    }

#if OVAS_SSL
  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
  gnutls_deinit (server_session);
  gnutls_certificate_free_credentials (server_credentials);
#else
  if (shutdown (server_socket, SHUT_RDWR) == -1)
    perror ("Failed to shutdown server socket");
#endif
  close (server_socket);
  return EXIT_SUCCESS;

 fail:
#if OVAS_SSL
  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
 server_fail:
  gnutls_deinit (server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (server_credentials);

 close_fail:
#else
  if (shutdown (server_socket, SHUT_RDWR) == -1)
    perror ("Failed to shutdown server socket");
 server_fail:
#endif

  close (server_socket);
  return EXIT_FAILURE;
}

#undef FD_CLIENT_READ
#undef FD_CLIENT_WRITE
#undef FD_SERVER_READ
#undef FD_SERVER_WRITE

/** Accept and fork.
  *
  * Accept the client connection and fork a child process.  The child calls
  * \ref serve_client to do the rest of the work.
  */
void
accept_and_maybe_fork () {
  /* Accept the client connection. */
  struct sockaddr_in client_address;
  client_address.sin_family = AF_INET;
  socklen_t size = sizeof (client_address);
  int client_socket;
  while ((client_socket = accept (manager_socket,
                                  (struct sockaddr *) &client_address,
                                  &size))
         == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        /* The connection is gone, return to select. */
        return;
      perror ("Failed to accept client connection");
      exit (EXIT_FAILURE);
    }

  /* Fork a child to serve the client. */
  pid_t pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        {
          // FIX get flags first
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'.
           */
          if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              perror ("Failed to set client socket flag");
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
#if OVAS_SSL
          int secure_client_socket
            = ovas_server_context_attach (server_context, client_socket);
          if (secure_client_socket == -1)
            {
              fprintf (stderr,
                       "Failed to attach server context to socket %i.\n",
                       client_socket);
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          tracef ("Server context attached.\n");
          int ret = serve_client (secure_client_socket);
          close_stream_connection (secure_client_socket);
#else
          int ret = serve_client (client_socket);
          if (shutdown (client_socket, SHUT_RDWR) == -1)
            {
              fprintf (stderr, "(fail on socket %i)\n", client_socket);
              perror ("Failed to shutdown client socket");
            }
          close (client_socket);
#endif
          exit (ret);
        }
      case -1:
        /* Parent when error, return to select. */
        perror ("Failed to fork child");
        break;
      default:
        /* Parent.  Return to select. */
        break;
    }
}

/** at_exit handler.  Close sockets and streams, free the ovas context. */
void
cleanup ()
{
  tracef ("Cleaning up.\n");
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (fclose (log_stream)) perror ("Failed to close log stream");
#endif
#if OVAS_SSL
  ovas_server_context_free (server_context);
#endif
  if (login) free (login);
  if (credentials) free (credentials);
  if (tasks) free_tasks ();
}

/** Handler for all signals.
  *
  * @param[in]  signal  The signal that caused this function to run.
  */
void
handle_signal (int signal)
{
  switch (signal)
    {
      case SIGTERM:
      case SIGHUP:
      case SIGINT:
        exit (EXIT_SUCCESS);
    }
}


/** Entry point to the manager.
  *
  * Setup the manager and then loop forever passing connections to
  * \ref accept_and_maybe_fork.
  *
  * @param[in]  argc  The number of arguments in argv.
  * @param[in]  argv  The list of arguments to the program.
  *
  * \return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
  */
int
main (int argc, char** argv)
{
  int server_port, manager_port;
  tracef ("OpenVAS Manager\n");
  tracef ("GNUTLS_E_AGAIN %i\n", GNUTLS_E_AGAIN);
  tracef ("GNUTLS_E_INTERRUPTED %i\n", GNUTLS_E_INTERRUPTED);
  tracef ("GNUTLS_E_REHANDSHAKE %i\n", GNUTLS_E_REHANDSHAKE);
  tracef ("-8: %s\n", strerror(8));
  tracef ("-9: %s\n", strerror(9));
  tracef ("-10: %s\n", strerror(10));

  /* Process options. */

  static gboolean print_version = FALSE;
  static gchar *manager_address_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *server_address_string = NULL;
  static gchar *server_port_string = NULL;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry option_entries[]
    = {
        { "listen", 'a', 0, G_OPTION_ARG_STRING, &manager_address_string, "Listen on <address>.", "<address>" },
        { "port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string, "Use port number <number>.", "<number>" },
        { "slisten", 'l', 0, G_OPTION_ARG_STRING, &server_address_string, "Server (openvasd) address.", "<address>" },
        { "sport", 's', 0, G_OPTION_ARG_STRING, &server_port_string, "Server (openvasd) port number.", "<number>" },
        { "version", 'v', 0, G_OPTION_ARG_NONE, &print_version, "Print version.", NULL },
        { NULL }
      };

  option_context = g_option_context_new ("- OpenVAS security scanner manager");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      printf ("%s\n\n", error->message);
      exit (EXIT_FAILURE);
    }

  if (print_version)
    {
      printf ("openvasmd (%s) %s for %s\n",
              PROGNAME, OPENVASMD_VERSION, OPENVAS_OS_NAME);
      printf ("Copyright (C) 2008 Intevation GmbH\n\n");
      exit (EXIT_SUCCESS);
    }

  if (manager_address_string == NULL)
    manager_address_string = OPENVASMD_ADDRESS;

  if (server_address_string == NULL)
    server_address_string = OPENVASD_ADDRESS;

  if (manager_port_string)
    {
      manager_port = atoi (manager_port_string);
      if (manager_port <= 0 || manager_port >= 65536)
        {
          fprintf (stderr, "Manager port must be a number between 0 and 65536.\n");
          exit (EXIT_FAILURE);
        }
      manager_port = htons (manager_port);
    }
  else
    {
      struct servent *servent = getservbyname ("openvas", "tcp");
      if (servent)
        // FIX free servent?
        manager_address.sin_port = servent->s_port;
      else
        manager_address.sin_port = htons (OPENVASMD_PORT);
    }

  if (server_port_string)
    {
      server_port = atoi (server_port_string);
      if (server_port <= 0 || server_port >= 65536)
        {
          fprintf (stderr, "Server port must be a number between 0 and 65536.\n");
          exit (EXIT_FAILURE);
        }
      server_port = htons (server_port);
    }
  else
    {
      struct servent *servent = getservbyname ("omp", "tcp");
      if (servent)
        // FIX free servent?
        server_port = servent->s_port;
      else
        server_port = htons (OPENVASD_PORT);
    }

  /* Register the `cleanup' function. */

  if (atexit (&cleanup))
    {
      fprintf (stderr, "Failed to register `atexit' cleanup function.\n");
      exit (EXIT_FAILURE);
    }

  /* Create the manager socket. */

  manager_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (manager_socket == -1)
    {
      perror ("Failed to create manager socket");
      exit (EXIT_FAILURE);
    }

#if LOG
  /* Open the log file. */

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      perror ("Failed to open log file");
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handler. */

  if (signal (SIGTERM, handle_signal) == SIG_ERR
      || signal (SIGINT, handle_signal) == SIG_ERR
      || signal (SIGHUP, handle_signal) == SIG_ERR
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)
    {
      fprintf (stderr, "Failed to register signal handler.\n");
      exit (EXIT_FAILURE);
    }

  /* Setup the server address. */

  server_address.sin_family = AF_INET;
  server_address.sin_port = server_port;
  if (!inet_aton(server_address_string, &server_address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               server_address_string);
      exit (EXIT_FAILURE);
    }

#if OVAS_SSL
  /* Setup security. */

  if (nessus_SSL_init (NULL) < 0)
    {
      fprintf (stderr, "Failed to initialise security.\n");
      exit (EXIT_FAILURE);
    }
  server_context
    = ovas_server_context_new (NESSUS_ENCAPS_TLSv1,
                               SERVERCERT,
                               SERVERKEY,
                               NULL,
                               CACERT,
                               0);
  if (server_context == NULL)
    {
      fprintf (stderr, "Failed to create server context.\n");
      exit (EXIT_FAILURE);
    }
#endif

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the connection between `select' and `accept'. */
  if (fcntl (manager_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set manager socket flag");
      exit (EXIT_FAILURE);
    }

  /* Bind the manager socket to a port. */

  manager_address.sin_family = AF_INET;
  manager_address.sin_port = manager_port;
  if (!inet_aton(manager_address_string, &manager_address.sin_addr))
    {
      fprintf (stderr, "Failed to create manager address %s.\n",
               manager_address_string);
      exit (EXIT_FAILURE);
    }

  if (bind (manager_socket,
            (struct sockaddr *) &manager_address,
            sizeof (manager_address))
      == -1)
    {
      perror ("Failed to bind manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  tracef ("Manager bound to address %s port %i\n",
          manager_address_string,
          ntohs (manager_address.sin_port));
  tracef ("Set to connect to address %s port %i\n",
          server_address_string,
          ntohs (server_address.sin_port));

  /* Enable connections to the socket. */

  if (listen (manager_socket, MAX_CONNECTIONS) == -1)
    {
      perror ("Failed to listen on manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  /* Loop waiting for connections and passing the work to
   * `accept_and_maybe_fork'.
   *
   * FIX This could just loop accept_and_maybe_fork.  Might the manager
   *     want to communicate with anything else here, like the server? */

  int ret, nfds;
  fd_set readfds, exceptfds;
  while (1)
    {
      FD_ZERO (&readfds);
      FD_SET (manager_socket, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (manager_socket, &exceptfds);
      nfds = manager_socket + 1;

      ret = select (nfds, &readfds, NULL, &exceptfds, NULL);

      if (ret == -1)
        {
          perror ("Select failed");
          exit (EXIT_FAILURE);
        }
      if (ret > 0)
        {
          if (FD_ISSET (manager_socket, &exceptfds))
            {
              fprintf (stderr, "Exception in select.\n");
              exit (EXIT_FAILURE);
            }
          if (FD_ISSET (manager_socket, &readfds))
            accept_and_maybe_fork();
        }
    }

  return EXIT_SUCCESS;
}
