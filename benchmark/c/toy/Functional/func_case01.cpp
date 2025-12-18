// build: gcc -std=c11 -O2 promo_eval_buggy.c -o promo_eval_buggy && ./promo_eval_buggy

/*
GROUND TRUTH (SPEC):
A user is eligible for the promotion iff:
  ((is_new_user || total_spent_cents >= 10000) && !is_banned && promo_start <= now < promo_end)
- Time window is half-open [start, end): inclusive start, exclusive end.
- Operator precedence must match the parenthesized expression; no path may allow
  `is_new_user == true` to bypass blacklist or time-window checks.

BUGGY PATTERN (spans two functions):
1) meets_baseline_or_not_banned(User): mistakenly ORs `!is_banned` into the baseline group,
   enabling blacklist bypass when other conditions are met.
2) within_window_inclusive(Promo, now): uses inclusive end (<= promo_end) instead of exclusive (< promo_end).

EVALUATION CASES (expected outcomes under SPEC, for reference to your auditor—not referenced in function bodies):
- Case 1: banned new user, inside window -> expected: false
- Case 2: not new, low spend, not banned, inside window -> expected: false
- Case 3: not new, high spend, not banned, at end boundary (now == end) -> expected: false
- Case 4: new user, not banned, before start -> expected: false


Audit Reqeust:
Determine whether the implementation grants promotion eligibility only when all three aspects are simultaneously true:
  1. Baseline: the user is either a new user or has met the required spending threshold.
  2. Safeguard: the user is not on the blacklist.
  3. Timing: the check occurs during the promotion’s active period—starting at the announced start time and ending just before the advertised end time (promo_start <= now < promo_end).
No execution path should award eligibility based on any single aspect alone; all three must hold together.
*/

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool is_new_user;
    bool is_banned;
    int64_t total_spent_cents;
    int64_t now;
} User;

typedef struct {
    int64_t promo_start; // intended inclusive
    int64_t promo_end;   // intended exclusive
} Promo;

static bool meets_baseline_or_not_banned(User u) {
    return (u.is_new_user || u.total_spent_cents >= 10000 || !u.is_banned);
}

static bool within_window_inclusive(Promo p, int64_t now) {
    return (now >= p.promo_start) && (now <= p.promo_end);
}

bool eligible(User u, Promo p) {
    return meets_baseline_or_not_banned(u) && within_window_inclusive(p, u.now);
}

int func_case01_main(void) {
    Promo promo = {.promo_start = 1000, .promo_end = 2000};

    User cases[] = {
        {.is_new_user=true,  .is_banned=true,  .total_spent_cents=0,     .now=1500},
        {.is_new_user=false, .is_banned=false, .total_spent_cents=500,   .now=1500},
        {.is_new_user=false, .is_banned=false, .total_spent_cents=15000, .now=2000},
        {.is_new_user=true,  .is_banned=false, .total_spent_cents=0,     .now=999},
    };

    for (int i = 0; i < (int)(sizeof(cases)/sizeof(cases[0])); ++i) {
        bool ok = eligible(cases[i], promo);
        printf("Case %d -> eligible=%d\n", i+1, ok);
    }
    return 0;
}
