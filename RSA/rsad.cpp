#include <gmp.h>
#include <gmpxx.h>

#include <iostream>
#pragma G++ optimize(3)

using namespace std;

mpz_class base;

#define LOG2C(n)                                                               \
  (((n) >= 0x1) + ((n) >= 0x2) + ((n) >= 0x4) + ((n) >= 0x8) + ((n) >= 0x10) + \
   ((n) >= 0x20) + ((n) >= 0x40) + ((n) >= 0x80) + ((n) >= 0x100) +            \
   ((n) >= 0x200) + ((n) >= 0x400) + ((n) >= 0x800) + ((n) >= 0x1000) +        \
   ((n) >= 0x2000) + ((n) >= 0x4000) + ((n) >= 0x8000))

#if defined _LONG_LONG_LIMB
#define CNST_LIMB(C) ((mp_limb_t)C##LL)
#else /* not _LONG_LONG_LIMB */
#define CNST_LIMB(C) ((mp_limb_t)C##L)
#endif /* _LONG_LONG_LIMB */
#define MPN_CMP(result, xp, yp, size) __GMPN_CMP(result, xp, yp, size)

#ifndef GMP_BPSW_NOFALSEPOSITIVES_UPTO_64BITS
#define GMP_BPSW_NOFALSEPOSITIVES_UPTO_64BITS 0
#endif

static int millerrabin(mpz_srcptr, mpz_ptr, mpz_ptr, mpz_srcptr,
                       unsigned long int);

int mympz_millerrabin(mpz_srcptr n, int reps) {
  mpz_t nm, x, y, q;
  unsigned long int k;
  gmp_randstate_t rstate;
  int is_prime;

  mpz_init2(nm, (mpz_size(n) + 1));
  mpz_tdiv_q_2exp(nm, n, 1);

  mpz_init2(x, mpz_size(n) + 1);
  mpz_init2(y, 2 * mpz_size(n));
  mpz_init2(q, mpz_size(n));

  k = mpz_scan1(nm, 0L);
  mpz_tdiv_q_2exp(q, nm, k);
  ++k;

  /* BPSW test */
  mpz_set_ui(x, 2);
  is_prime = millerrabin(n, x, y, q, k);

  if (is_prime) {
    if (
#if GMP_BPSW_NOFALSEPOSITIVES_UPTO_64BITS
    /* Consider numbers up to 2^64 that pass the BPSW test as primes. */
#if GMP_NUMB_BITS <= 64
        mpz_size(n) <= 64 / GMP_NUMB_BITS
#else
        0
#endif
#if 64 % GMP_NUMB_BITS != 0
        ||
        mpz_size(n) - 64 / GMP_NUMB_BITS ==
            (mp_ptr(n)[64 / GMP_NUMB_BITS] < CNST_LIMB(1) << 64 % GMP_NUMB_BITS)
#endif
#else
#define GMP_BPSW_LIMB_CONST CNST_LIMB(31)
#define GMP_BPSW_BITS_CONST (LOG2C(31) - 1)
#define GMP_BPSW_BITS_LIMIT (46 + GMP_BPSW_BITS_CONST)

#define GMP_BPSW_LIMBS_LIMIT (GMP_BPSW_BITS_LIMIT / GMP_NUMB_BITS)
#define GMP_BPSW_BITS_MOD (GMP_BPSW_BITS_LIMIT % GMP_NUMB_BITS)

#if GMP_NUMB_BITS <= GMP_BPSW_BITS_LIMIT
        mpz_size(n) <= GMP_BPSW_LIMBS_LIMIT
#else
        0
#endif
#if GMP_BPSW_BITS_MOD >= GMP_BPSW_BITS_CONST
        ||
        mpz_size(n) - GMP_BPSW_LIMBS_LIMIT ==
            (mp_ptr(n)[GMP_BPSW_LIMBS_LIMIT] <
             GMP_BPSW_LIMB_CONST << (GMP_BPSW_BITS_MOD - GMP_BPSW_BITS_CONST))
#else
#if GMP_BPSW_BITS_MOD != 0
        || mpz_size(n) - GMP_BPSW_LIMBS_LIMIT ==
               (mp_ptr(n)[GMP_BPSW_LIMBS_LIMIT] < GMP_BPSW_LIMB_CONST >>
                (GMP_BPSW_BITS_CONST - GMP_BPSW_BITS_MOD))
#else
#if GMP_NUMB_BITS > GMP_BPSW_BITS_CONST
        ||
        mpz_size(nm) - GMP_BPSW_LIMBS_LIMIT + 1 ==
            (mp_ptr(nm)[GMP_BPSW_LIMBS_LIMIT - 1] <
             GMP_BPSW_LIMB_CONST << (GMP_NUMB_BITS - 1 - GMP_BPSW_BITS_CONST))
#endif
#endif
#endif

#undef GMP_BPSW_BITS_LIMIT
#undef GMP_BPSW_LIMB_CONST
#undef GMP_BPSW_BITS_CONST
#undef GMP_BPSW_LIMBS_LIMIT
#undef GMP_BPSW_BITS_MOD

#endif
    )
      is_prime = 2;
    else {
      reps -= 24;
      if (reps > 0) {
        mpz_sub_ui(nm, nm, 2L);

        gmp_randinit_default(rstate);

        do {
          mpz_urandomm(x, rstate, nm);
          mpz_add_ui(x, x, 3L);

          is_prime = millerrabin(n, x, y, q, k);
        } while (--reps > 0 && is_prime);

        gmp_randclear(rstate);
      }
    }
  }
  return is_prime;
}

static int mod_eq_m1(mpz_srcptr x, mpz_srcptr m) {
  mp_size_t ms;
  mp_srcptr mp, xp;

  ms = mpz_size(m);
  if (mpz_size(x) != ms) return 0;

  mp = mp_ptr(m);
  xp = mp_ptr(x);

  if ((*xp ^ CNST_LIMB(1) ^ *mp) != CNST_LIMB(0))
    return 0;
  else {
    int cmp;

    --ms;
    ++xp;
    ++mp;

    MPN_CMP(cmp, xp, mp, ms);

    return cmp == 0;
  }
}

static int millerrabin(mpz_srcptr n, mpz_ptr x, mpz_ptr y, mpz_srcptr q,
                       unsigned long int k) {
  unsigned long int i;

  mpz_powm(y, x, q, n);

  if (mpz_cmp_ui(y, 1L) == 0 || mod_eq_m1(y, n)) return 1;

  for (i = 1; i < k; i++) {
    mpz_powm_ui(y, y, 2L, n);
    if (mod_eq_m1(y, n)) return 1;
    if (mpz_cmp_ui(y, 1L) <= 0) return 0;
  }
  return 0;
}

inline void exgcd(mpz_class& g, mpz_class a, mpz_class b, mpz_class& s,
                  mpz_class& t) {
  if (b == 0) {
    s = 1;
    t = 0;
    g = a;
    return;
  }
  exgcd(g, b, a % b, s, t);
  mpz_class tmp = s;
  s = t;
  t = tmp - (a / b) * t;
}

bool check(const mpz_class& e, const mpz_class& p, const mpz_class& q) {
  if (e < 0xf) return false;
  mpz_class phi = (p - 1) * (q - 1);
  if (gcd(p, q) != 1 || gcd(p-1, q-1) > 0xffff) return false;
  if (!(mympz_millerrabin(p.get_mpz_t(), 10)) & (!mympz_millerrabin(q.get_mpz_t(), 10))) return false;
  mpz_class tmp1 = abs(p - q);
  mpz_class tmp2 = (p + q) / 10;
  if (tmp1 < tmp2) return false;
  if (p < base || q < base) return false;
  return true;
}

int main() {
  // freopen("5/2.in", "r", stdin);
  mpz_ui_pow_ui(base.get_mpz_t(), 2, 256);
  int n;
  cin >> n;
  while (n--) {
    mpz_class e, p, q, phi;
    gmp_scanf("%Zd%Zd%Zd", e.get_mpz_t(), p.get_mpz_t(), q.get_mpz_t());
    phi = (p - 1) * (q - 1);
    if (!check(e, p, q)) {
      cout << "ERROR" << endl;
      continue;
    }
    mpz_class g, d, t;
    exgcd(g, e, phi, d, t);
    if (g != 1 || d < 0) {
      cout << "ERROR" << endl;
      continue;
    }

    gmp_printf("%Zd\n", d);
  }
}
