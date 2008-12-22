/* Test strip_space. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../string.h"

int
main ()
{
  char string[5];
  char *expect = "abcd";

  strncpy (string, "abcd", 5);

  char* result = strip_space (string, string + 4);
  if (strlen (result) != 4 || strcmp (result, expect))
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
