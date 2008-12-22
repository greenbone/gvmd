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
