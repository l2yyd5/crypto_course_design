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

inline void exgcd(mpz_class& g, mpz_class a, mpz_class b, mpz_class& s,
                  mpz_class& t) {
  if (b == 0) {
    s = 1;
    t = 0;
    g = a;
    return;
  }
  exgcd(g, b, a % b, s, t);
  swap(s, t);
  t = t - a / b * s;
}

int main() {
  ios::sync_with_stdio(false);
  cin.tie(nullptr);
  cout.tie(nullptr);
  // freopen("5/2.in", "r", stdin);
  int n;
  cin >> n;
  mpz_class e, p, q, c, m, m1, m2, qInv;
  mpz_class g, d, t, dp, dq;
  mpz_class phi;
  cin >> p >> q >> e;
  phi = (p - 1) * (q - 1);

  exgcd(g, e, phi, d, t);
  dp = d % (p - 1);
  if (dp < 0) dp += (p - 1);
  dq = d % (q - 1);
  if (dq < 0) dq += (q - 1);
  exgcd(g, q, p, qInv, t);
  while (n--) {
    cin >> c;
    m1 = sliding_window_power_mod(c, dp, p);
    m2 = sliding_window_power_mod(c, dq, q);
    m = m2 + (((m1 - m2) * qInv) % p) * q;
    if (m < 0) m += (p * q);
    cout << m << endl;
  }
}