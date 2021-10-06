#include <gmp.h>
#include <gmpxx.h>

#include <iostream>
#pragma G++ optimize(3, "Ofast", "inline")
#define WINDOW_SIZE 5

using namespace std;

inline mpz_class sliding_window_power_mod(mpz_class x, mpz_class e,
                                          mpz_class n) {
  mpz_class ret = 1, tmp;
  mpz_class pre[1 << WINDOW_SIZE];
  pre[0] = 1;
  pre[1] = x % n;
  tmp = (pre[1] * x) % n;
  for (int i = 3; i < (1 << WINDOW_SIZE); i += 2) {
    pre[i] = (pre[i - 2] * tmp) % n;
  }
  unsigned long l = e.get_mpz_t()->_mp_size * GMP_LIMB_BITS;
  long i = l - 1;
  long s, ni;
  while (i >= 0) {
    if (mpz_tstbit(e.get_mpz_t(), i) == 0) {
      ret *= ret;
      ret %= n;
      i--;
    } else {
      s = (i + 1 - WINDOW_SIZE) >= 0 ? (i + 1 - WINDOW_SIZE) : 0;
      while (mpz_tstbit(e.get_mpz_t(), s) == 0) {
        s++;
      }
      for (int j = 1; j <= i - s + 1; ++j) {
        ret *= ret;
        ret %= n;
      }
      tmp = (e >> s) & ((1 << (i - s + 1)) - 1);
      ni = tmp.get_ui();
      ret *= pre[ni];
      ret %= n;
      i = s - 1;
    }
  }
  return ret;
}

int main() {
  // freopen("5/2.in", "r", stdin);
  int n;
  scanf("%d", &n);
  mpz_class e, p, q, m, g;
  mpz_class N, ans;

  while (n--) {
    gmp_scanf("%Zd%Zd%Zd%Zd", e.get_mpz_t(), m.get_mpz_t(), p.get_mpz_t(), q.get_mpz_t());
    N = p*q;
    ans = sliding_window_power_mod(m, e, N);
    gmp_printf("%Zd\n", ans.get_mpz_t());
  }
}