/**
 * @brief Default for schedule_timeout in minutes.
 */
#define SCHEDULE_TIMEOUT_DEFAULT 60

/**
 * @brief Number of minutes before overdue tasks timeout.
 */
static int schedule_timeout = SCHEDULE_TIMEOUT_DEFAULT;

/**
 * @brief Get the current schedule timeout.
 *
 * @return The schedule timeout in minutes.
 */
int
get_schedule_timeout ()
{
  return schedule_timeout;
}

/**
 * @brief Set the schedule timeout.
 *
 * @param new_timeout The new schedule timeout in minutes.
 */
void
set_schedule_timeout (int new_timeout)
{
  if (new_timeout < 0)
    schedule_timeout = -1;
  else
    schedule_timeout = new_timeout;
}
