#include <cstdio>
#include <cstring>
#pragma G++ optimize(2)

const int MAXN = 65555;
const unsigned short s_box[16] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8,
                                  0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const unsigned short inv_s_box[16] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf,
                                      0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
unsigned short ss_box[65536];
unsigned short ps_box[65536];

unsigned short count24[0x10][0x10], count13[0x10][0x10];
unsigned int ciphertext[MAXN];
unsigned int highKey, lowKey, ansKey;
unsigned short key1, key2, key3, key4;

inline void pre(unsigned short i, unsigned short& s, unsigned short& sp) {
  unsigned short u = s_box[i & 0xf] | (s_box[(i >> 4) & 0xf] << 4) |
                     (s_box[(i >> 8) & 0xf] << 8) |
                     (s_box[(i >> 12) & 0xf] << 12);
  s = u;
  bool vi[16] = {
      (bool)(u & 0x1),       (bool)(u >> 1 & 0x1),  (bool)(u >> 2 & 0x1),
      (bool)(u >> 3 & 0x1),  (bool)(u >> 4 & 0x1),  (bool)(u >> 5 & 0x1),
      (bool)(u >> 6 & 0x1),  (bool)(u >> 7 & 0x1),  (bool)(u >> 8 & 0x1),
      (bool)(u >> 9 & 0x1),  (bool)(u >> 10 & 0x1), (bool)(u >> 11 & 0x1),
      (bool)(u >> 12 & 0x1), (bool)(u >> 13 & 0x1), (bool)(u >> 14 & 0x1),
      (bool)(u >> 15 & 0x1)};

  bool tmp;
  tmp = vi[1], vi[1] = vi[4], vi[4] = tmp;
  tmp = vi[2], vi[2] = vi[8], vi[8] = tmp;
  tmp = vi[3], vi[3] = vi[12], vi[12] = tmp;
  tmp = vi[6], vi[6] = vi[9], vi[9] = tmp;
  tmp = vi[7], vi[7] = vi[13], vi[13] = tmp;
  tmp = vi[11], vi[11] = vi[14], vi[14] = tmp;

  u = (unsigned short)vi[0] | ((unsigned short)vi[1] << 1) |
      ((unsigned short)vi[2] << 2) | ((unsigned short)vi[3] << 3) |
      ((unsigned short)vi[4] << 4) | ((unsigned short)vi[5] << 5) |
      ((unsigned short)vi[6] << 6) | ((unsigned short)vi[7] << 7) |
      ((unsigned short)vi[8] << 8) | ((unsigned short)vi[9] << 9) |
      ((unsigned short)vi[10] << 10) | ((unsigned short)vi[11] << 11) |
      ((unsigned short)vi[12] << 12) | ((unsigned short)vi[13] << 13) |
      ((unsigned short)vi[14] << 14) | ((unsigned short)vi[15] << 15);
  sp = u;
}

char buf[1 << 20], *p1 = buf, *p2 = buf;
inline int getc() {
  return p1 == p2 && (p2 = (p1 = buf) + fread(buf, 1, 1 << 20, stdin), p1 == p2)
             ? EOF
             : *p1++;
}
inline void read(unsigned int& res) {
  res = 0;
  char ch = getc();
  while (ch != ' ' && ch != '\n') {
    res = (res << 4) + ((ch >= 'a') ? (ch - 'a' + 10) : (ch - '0'));
    ch = getc();
  }
}

char pbuf[1 << 20], *pp = pbuf;
inline void push(const char& c) {
  if (pp - pbuf == 1 << 20) fwrite(pbuf, 1, 1 << 20, stdout), pp = pbuf;
  *pp++ = c;
}
inline void write(int x) {
  static char sta[10];
  int top = 0;
  while (top < 8) {
    char tmp = x & 0xf;
    sta[top++] = (tmp >= 10) ? (tmp - 10 + 'a') : (tmp + '0');
    x >>= 4;
  }
  while (top) push(sta[--top]);
}

inline void input() {
  for (int i = 0; i < 0x10000; i++) {
    read(ciphertext[i]);
  }
}

int main() {
  // freopen("5.in", "r", stdin);
  // freopen("my5.out", "w", stdout);
  // freopen("in.txt", "r", stdin);
  for (unsigned int i = 0; i <= 0xffff; i++) {
    pre(i, ss_box[i], ps_box[i]);
  }
  int n;
  unsigned short u1, u2, u3, u4;
  unsigned short _u1, _u2, _u3, _u4;
  scanf("%d", &n);
  getchar();
  while (n--) {
    input();
    memset(count24, 0, sizeof(count24));
    memset(count13, 0, sizeof(count13));
    for (int i = 0; i < 0x10000; i += 0x1f) {
      if (((ciphertext[i] ^ ciphertext[i ^ 0xb00]) & 0xf0f0) == 0) {
        unsigned short y1[4] = {
            (unsigned short)((ciphertext[i] & 0xf000) >> 12),
            (unsigned short)((ciphertext[i] & 0xf00) >> 8),
            (unsigned short)((ciphertext[i] & 0xf0) >> 4),
            (unsigned short)(ciphertext[i] & 0xf)};
        unsigned short y2[4] = {
            (unsigned short)((ciphertext[i ^ 0xb00] & 0xf000) >> 12),
            (unsigned short)((ciphertext[i ^ 0xb00] & 0xf00) >> 8),
            (unsigned short)((ciphertext[i ^ 0xb00] & 0xf0) >> 4),
            (unsigned short)(ciphertext[i ^ 0xb00] & 0xf)};
        for (int L1 = 0; L1 <= 0xf; L1++) {
          for (int L2 = 0; L2 <= 0xf; L2++) {
            u2 = inv_s_box[L1 ^ y1[1]];
            u4 = inv_s_box[L2 ^ y1[3]];

            _u2 = inv_s_box[L1 ^ y2[1]];
            _u4 = inv_s_box[L2 ^ y2[3]];

            u2 ^= _u2;
            u4 ^= _u4;

            count24[L1][L2] += ((u2 == 6) & (u4 == 6));
          }
        }
      }
      if (((ciphertext[i] ^ ciphertext[i ^ 0x50]) & 0x0f0f) == 0) {
        unsigned short y1[4] = {
            (unsigned short)((ciphertext[i] & 0xf000) >> 12),
            (unsigned short)((ciphertext[i] & 0xf00) >> 8),
            (unsigned short)((ciphertext[i] & 0xf0) >> 4),
            (unsigned short)(ciphertext[i] & 0xf)};
        unsigned short y2[4] = {
            (unsigned short)((ciphertext[i ^ 0x50] & 0xf000) >> 12),
            (unsigned short)((ciphertext[i ^ 0x50] & 0xf00) >> 8),
            (unsigned short)((ciphertext[i ^ 0x50] & 0xf0) >> 4),
            (unsigned short)(ciphertext[i ^ 0x50] & 0xf)};
        for (int L1 = 0; L1 <= 0xf; L1++) {
          for (int L2 = 0; L2 <= 0xf; L2++) {
            u1 = inv_s_box[L1 ^ y1[0]];
            u3 = inv_s_box[L2 ^ y1[2]];

            _u1 = inv_s_box[L1 ^ y2[0]];
            _u3 = inv_s_box[L2 ^ y2[2]];

            u1 ^= _u1;
            u3 ^= _u3;

            count13[L1][L2] += ((u1 == 5) & (u3 == 5));
          }
        }
      }
    }
    bool flag = false;
    for (int round = 0; round < 0xff; round++) {
      unsigned short max24 = 0;
      for (int L1 = 0; L1 <= 0xf; L1++) {
        for (int L2 = 0; L2 <= 0xf; L2++) {
          if (count24[L1][L2] > max24) {
            max24 = count24[L1][L2];
            key2 = L1;
            key4 = L2;
          }
        }
      }
      count24[key2][key4] = 0;

      for (int round2 = 0; round2 < 2; round2++) {
        unsigned short max13 = 0;
        for (int L1 = 0; L1 <= 0xf; L1++) {
          for (int L2 = 0; L2 <= 0xf; L2++) {
            if (count13[L1][L2] > max13) {
              max13 = count13[L1][L2];
              key1 = L1;
              key3 = L2;
            }
          }
        }
        count13[key1][key3] = 0;
        lowKey = key4 | (key3 << 4) | (key2 << 8) | (key1 << 12);
        for (highKey = 0; highKey <= 0xffff; highKey++) {
          unsigned int tmpKey = (highKey << 16) | lowKey;
          int check = 0;
          unsigned short k1, k2, k3, k4, k5 = lowKey;
          k4 = (tmpKey >> 4) & 0xffff;
          k3 = (tmpKey >> 8) & 0xffff;
          k2 = (tmpKey >> 12) & 0xffff;
          k1 = highKey;
          for (check = 0; check < 0xffff; check += 0x1fff) {
            if ((ss_box[ps_box[ps_box[ps_box[check ^ k1] ^ k2] ^ k3] ^ k4] ^
                 k5) != ciphertext[check]) {
              check = 0;
              break;
            }
          }
          if (check) {
            flag = true;
            ansKey = tmpKey;
            break;
          }
        }
        if (flag) break;
      }
      if (flag) break;
    }
    write(ansKey);
    push('\n');
  }
  fwrite(pbuf, 1, pp - pbuf, stdout);
  return 0;
}