#include <gmp.h>
#include <stdio.h>

#pragma G++ optimize(3)

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

mpz_t base;

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

void myexgcd(mpz_t g, mpz_t a, mpz_t b, mpz_t s, mpz_t t) {
  if (mpz_cmp_ui(b, 0) == 0) {
    mpz_set_ui(s, 1);
    mpz_set_ui(t, 0);
    mpz_set(g, a);
    return;
  }
  mpz_t tmp1, tmp2;
  mpz_init(tmp1);
  mpz_init(tmp2);
  mpz_set(tmp1, b);
  mpz_mod(tmp2, a, b);
  myexgcd(g, tmp1, tmp2, s, t);
  mpz_set(tmp1, s);
  mpz_set(s, t);
  mpz_div(tmp2, a, b);
  mpz_mul(tmp2, tmp2, t);
  mpz_sub(t, tmp1, tmp2);

  return;
}

void mygcd(mpz_t g, mpz_t a, mpz_t b) {
  if (mpz_cmp_ui(b, 0) == 0) {
    mpz_set(g, a);
    return;
  }
  mpz_t tmp;
  mpz_init(tmp);
  mpz_set(tmp, a);
  mpz_set(a, b);
  mpz_mod(b, tmp, a);
  mygcd(g, a, b);

  return;
}

int check(const mpz_t e, const mpz_t p, const mpz_t q) {
  if (mpz_cmp_ui(e, 0xf) < 0) return 0;
  mpz_t phi, tmp1, tmp2;
  mpz_t g1, g2;
  mpz_init(phi), mpz_init(tmp1), mpz_init(tmp2);
  mpz_init(g1), mpz_init(g2);
  mpz_sub_ui(tmp1, p, 1);
  mpz_sub_ui(tmp2, q, 1);
  mpz_mul(phi, tmp1, tmp2);
  mygcd(g2, tmp1, tmp2);
  mpz_set(tmp1, p);
  mpz_set(tmp2, q);
  mygcd(g1, tmp1, tmp2);
  if (mpz_cmp_ui(g1, 1) != 0 || mpz_cmp_ui(g2, 0xffff) > 0) return 0;
  if (!(mympz_millerrabin(p, 5)) & (!mympz_millerrabin(q, 5))) return 0;
  mpz_sub(tmp1, p, q);
  mpz_abs(tmp1, tmp1);
  mpz_add(tmp2, p, q);
  mpz_div_ui(tmp2, tmp2, 10);
  if (mpz_cmp(tmp1, tmp2) < 0) return 0;
  if (mpz_cmp(p, base) < 0 || mpz_cmp(q, base) < 0) return 0;
  return 1;
}

int main() {
  // freopen("../5/2.in", "r", stdin);
  mpz_init(base);
  mpz_ui_pow_ui(base, 2, 256);
  mpz_t e, p, q, phi;
  mpz_init(e), mpz_init(p), mpz_init(q), mpz_init(phi);
  mpz_t g, d, t;
  mpz_init(g), mpz_init(d), mpz_init(t);
  int n;
  scanf("%d", &n);
  while (n--) {
    gmp_scanf("%Zd%Zd%Zd", e, p, q);
    if (!check(e, p, q)) {
      printf("ERROR\n");
      continue;
    }
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi, p, q);
    myexgcd(g, e, phi, d, t);
    if (mpz_cmp_ui(g, 1) != 0 || mpz_cmp_ui(d, 0) < 0) {
      printf("ERROR\n");
      continue;
    }
    gmp_printf("%Zd\n", d);
  }
}