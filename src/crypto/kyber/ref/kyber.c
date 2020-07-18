#include <linux/init.h>
#include <kyber/api.h>
#include "../selftest/kyber.c"

int __init kyber_mod_init()
{
    if (!kyber_selftest()) {
        pr_err("kyber self-tests: FAIL\n");
        return -ENOTRECOVERABLE;
    }

    pr_info("kyber self-tests: pass\n");
    return 0;
}