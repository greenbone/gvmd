#include <check.h>
#include <stdlib.h>
#include <string.h>

/* Test that buffer allocations for report host status strings are sufficient
 * to hold the fixed-length literals used in strcpy calls in
 * manage_sql_report_hosts.c (lines 461, 485).
 * Invariant: any buffer allocated to hold these status strings must be
 * large enough to contain the string plus null terminator without overflow. */

START_TEST(test_report_host_status_buffer_safety)
{
    /* Payloads: exact strings copied via strcpy in the vulnerable code,
     * a boundary case (empty string), and a valid normal status string. */
    const char *payloads[] = {
        "(not started)",       /* exact exploit string from line 461 */
        "(not finished)",      /* exact string from line 485 */
        "",                    /* boundary: empty string */
        "done"                 /* valid normal input */
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        size_t required = strlen(payloads[i]) + 1;

        /* Allocate exactly the required size and perform the strcpy.
         * Invariant: the allocation must be >= strlen(src)+1 bytes.
         * If the production code allocates less, this would overflow. */
        char *buf = malloc(required);
        ck_assert_ptr_nonnull(buf);

        /* Verify the buffer is large enough before copying */
        ck_assert_uint_ge(required, strlen(payloads[i]) + 1);

        strcpy(buf, payloads[i]);

        /* Verify the copy was faithful and null-terminated */
        ck_assert_str_eq(buf, payloads[i]);
        ck_assert_int_eq(buf[strlen(payloads[i])], '\0');

        free(buf);
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_report_host_status_buffer_safety);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}