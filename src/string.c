
/** Trace flag.  0 to turn off all tracing messages. */
#define TRACE 0

#include <assert.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "tracef.h"
#include "string.h"

/** "Strip" space and newline characters from either end of some memory.
  *
  * Return the given pointer moved forward past any spaces, replacing the
  * first of any contiguous spaces at or before the end of the memory with
  * a terminating NULL.
  *
  * This is for use when string points into a static buffers.
  *
  * @param[in,out]  string  The start of the memory.
  * @param[in]      end     Pointer to the byte after the end of the memory.
  *
  * @return A new pointer into the string.
  */
char*
strip_space (char* string, char* end)
{
  assert (string <= end);
  tracef ("   strip %p %p\n", string, end);
  if (string >= end) return string;
  end--;
  while (string[0] == ' ' || string[0] == '\n')
    {
      string++;
      if (string >= end)
        {
          end[0] = '\0';
          return end;
        }
    }

  /* Here string is < end. */
  if (end[0] == ' ' || end[0] == '\n')
    {
      end--;
      while (end >= string && (end[0] == ' ' || end[0] == '\n')) { end--; }
      end[1] = '\0';
    }
  return string;
}

#undef TRACE
