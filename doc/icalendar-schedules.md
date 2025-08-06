# Notes on iCalendar Schedules

## General usage

Schedules in Greenbone Vulnerability Manager 8.0 and newer will support a
subset of the iCalendar format as defined in RFC 5545 to define the
first run time, recurrence and duration of the schedule.
The iCalendar text should consist of an VCALENDAR component containing
a single VEVENT.  If the VEVENT uses a TZID, the corresponding VTIMEZONE
should be included as well.

gvmd will modify the iCalendar text to optimize it for its internal functions.
See the following sections for some of the changes made.

## Timezones

Schedules using iCalendar will use the timezone set in their timezone field by
default.
However, if the optimized iCalendar contains an explicit TZID and it is defined
by a valid VTIMEZONE component in the same VCALENDAR, this timezone will be
used instead.
Note that if the TZID is undefined within the VCALENDAR, it will be removed.

## Other restrictions and caveats

- Only the first VEVENT component will be considered. Any other VEVENT, VTODO
  or VJOURNAL components will be removed.
- Only the first RRULE property of the VEVENT will be used. Any following
  occurrences will be removed.
- If a DTEND property is given in the VEVENT, it will be converted to a
  DURATION property.
- RDATE properties specifying a time period will be reduced to a simple start
  time, discarding the end time or duration of the RDATE period.
- Any property besides DTSTART, DTEND, DURATION and RRULE will be removed.
  This includes the deprecated EXRULE property.
- Some properties like PRODID, UID and DTSTAMP may be modified.

## Compatibility with old GMP syntax

Schedules can still be created and modified using the old GMP syntax
and when fetching the schedules with the get_schedules command, an
approximation of the old fields will be included in the response.
When modifying schedules using the old GMP syntax, only the data available to
the old syntax will be used, so some information may be lost.
It is therefore recommended to use iCalendar when modifying schedules with
more complex recurrence or timezone information.

The elements in the old syntax are mapped to VEVENT properties as follows:

- first_time => DTSTART
- duration   => DURATION
- period     => FREQ and COUNT in RRULE
- byday      => BYDAY in RRULE (with restrictions, see below)

The restrictions of the old syntax include:

- The "byday" GMP element only supports simple weekdays, but no number of the
  week, e.g. only "MO" for "every Monday" but not "2MO" for "every second Monday
  of the month".
- There are no corresponding elements for several other recurrence related
  rules and rule parts like BYMONTH.
- iCalendar timezone information is only included in the iCalendar text, so
  only the default timezone of the schedule will be used.
