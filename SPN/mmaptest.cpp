#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <bitset>
#include <cstdio>
#include <cstring>
#pragma G++ optimize(3)

const int MAXN = 8005;
const int Nr = 4;
const unsigned short s_box[16] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8,
                                  0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const unsigned short inv_s_box[16] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf,
                                      0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
unsigned short ss_box[65536];
unsigned short ps_box[65536];

unsigned short count24[0x10][0x10], count13[0x10][0x10];
unsigned short cnt13[2][0x10][0x10];
unsigned int plaintext[MAXN], ciphertext[MAXN];
unsigned int highKey, lowKey;
unsigned int ansKey;
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

char *pc;

inline void read(unsigned int& res) {
  res = 0;
  char ch = *pc++;
  while (ch != ' ' && ch != '\n' && ch >= '0') {
    res = (res << 4) + ((ch >= 'a') ? (ch - 'a' + 10) : (ch - '0'));
    ch = *pc++;
  }
}

char pbuf[1 << 25], *pp = pbuf;
inline void push(const char& c) {
  if (pp - pbuf == 1 << 25) fwrite(pbuf, 1, 1 << 25, stdout), pp = pbuf;
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

inline unsigned short SPN(unsigned int k, unsigned int p) {
  unsigned short key[5] = {
      (unsigned short)((k >> 16) & 0xffff),
      (unsigned short)((k >> 12) & 0xffff), (unsigned short)((k >> 8) & 0xffff),
      (unsigned short)((k >> 4) & 0xffff), (unsigned short)(k & 0xffff)};
  unsigned short w(p & 0xffff);
  w = ps_box[key[0] ^ w];
  w = ps_box[key[1] ^ w];
  w = ps_box[key[2] ^ w];
  w = ss_box[key[3] ^ w];
  w ^= key[4];

  return w;
}

inline void input() {
  for (int i = 0; i < 8000; i++) {
    read(plaintext[i]);
    read(ciphertext[i]);
  }
}

int main() {
  // freopen("in.txt", "r", stdin);
  pc = (char *) mmap(NULL,  lseek(0, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fileno(stdin), 0);
  for (unsigned int i = 0; i <= 0xffff; i++) {
    pre(i, ss_box[i], ps_box[i]);
  }
  int n;
  unsigned short u1, u2, u3, u4, z;
  n = 0;
  char ch = *pc++;
  while(ch<'0' || ch > '9')
    ch = *pc++;
  while (ch != ' ' && ch != '\n' && ch >= '0') {
    n = (n << 3 | n << 1) + ch - '0';
    ch = *pc++;
  }

  while (n--) {
    input();
    memset(count24, 0, sizeof(count24));
    for (int i = 0; i < 8000; i++) {
      std::bitset<16> x(plaintext[i]);
      unsigned short y[4] = {(unsigned short)((ciphertext[i] & 0xf000) >> 12),
                             (unsigned short)((ciphertext[i] & 0xf00) >> 8),
                             (unsigned short)((ciphertext[i] & 0xf0) >> 4),
                             (unsigned short)(ciphertext[i] & 0xf)};
      for (int L1 = 0; L1 <= 0xf; L1++) {
        for (int L2 = 0; L2 <= 0xf; L2++) {
          u2 = inv_s_box[L1 ^ y[1]];
          u4 = inv_s_box[L2 ^ y[3]];
          z = (x[11] ^ x[9] ^ x[8] ^ (u2 >> 2) ^ u2 ^ (u4 >> 2) ^ u4) & 0x1;
          if (!z) count24[L1][L2]++;
        }
      }
    }
    for (int L1 = 0; L1 <= 0xf; L1++) {
      for (int L2 = 0; L2 <= 0xf; L2++) {
        count24[L1][L2] = count24[L1][L2] >= 4000 ? (count24[L1][L2] - 4000)
                                                  : (4000 - count24[L1][L2]);
      }
    }
    bool flag = false;
    for (int round = 0; round < 0x10; round++) {
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
      memset(cnt13, 0, sizeof(cnt13));
      for (int i = 0; i < 8000; i++) {
        std::bitset<16> x(plaintext[i]);
        unsigned short y[4] = {(unsigned short)((ciphertext[i] & 0xf000) >> 12),
                               (unsigned short)((ciphertext[i] & 0xf00) >> 8),
                               (unsigned short)((ciphertext[i] & 0xf0) >> 4),
                               (unsigned short)(ciphertext[i] & 0xf)};
        for (int L1 = 0; L1 <= 0xf; L1++) {
          for (int L2 = 0; L2 <= 0xf; L2++) {
            u1 = inv_s_box[y[0] ^ L1];
            u2 = inv_s_box[y[1] ^ key2];
            u3 = inv_s_box[y[2] ^ L2];
            u4 = inv_s_box[y[3] ^ key4];
            z = (x[15] ^ x[14] ^ x[12] ^ (u1 >> 3) ^ (u2 >> 3) ^ (u3 >> 3) ^
                 (u4 >> 3)) &
                0x1;
            if (!z) cnt13[0][L1][L2]++;
            z = (x[7] ^ x[6] ^ x[4] ^ (u1 >> 1) ^ (u2 >> 1) ^ (u3 >> 1) ^
                 (u4 >> 1)) &
                0x1;
            if (!z) cnt13[1][L1][L2]++;
          }
        }
      }
      for (int L1 = 0; L1 <= 0xf; L1++) {
        for (int L2 = 0; L2 <= 0xf; L2++) {
          cnt13[0][L1][L2] = cnt13[0][L1][L2] >= 4000
                                 ? (cnt13[0][L1][L2] - 4000)
                                 : (4000 - cnt13[0][L1][L2]);
          cnt13[1][L1][L2] = cnt13[1][L1][L2] >= 4000
                                 ? (cnt13[1][L1][L2] - 4000)
                                 : (4000 - cnt13[1][L1][L2]);
          count13[L1][L2] = cnt13[0][L1][L2] + cnt13[1][L1][L2];
        }
      }

      for (int round2 = 0; round2 < 3; round2++) {
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
          for (check = 0; check < 4; check++) {
            if (SPN(tmpKey, plaintext[check]) != ciphertext[check]) {
              break;
            }
          }
          if (check == 4) {
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