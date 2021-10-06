#include <cstdio>
#include <iostream>
#pragma G++ optimize(3)

using namespace std;

const int Nr = 4;
const unsigned short s_box[16] = {0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8,
                                  0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7};
const unsigned short inv_s_box[16] = {0xe, 0x3, 0x4, 0x8, 0x1, 0xc, 0xa, 0xf,
                                      0x7, 0xd, 0x9, 0x6, 0xb, 0x2, 0x0, 0x5};
unsigned short p_box[65536];
unsigned short ss_box[65536];
unsigned short inv_ss_box[65536];

inline unsigned short pre1(unsigned int i) {
  bool vi[16] = {
      (bool)(i & 0x1),       (bool)(i >> 1 & 0x1),  (bool)(i >> 2 & 0x1),
      (bool)(i >> 3 & 0x1),  (bool)(i >> 4 & 0x1),  (bool)(i >> 5 & 0x1),
      (bool)(i >> 6 & 0x1),  (bool)(i >> 7 & 0x1),  (bool)(i >> 8 & 0x1),
      (bool)(i >> 9 & 0x1),  (bool)(i >> 10 & 0x1), (bool)(i >> 11 & 0x1),
      (bool)(i >> 12 & 0x1), (bool)(i >> 13 & 0x1), (bool)(i >> 14 & 0x1),
      (bool)(i >> 15 & 0x1)};

  bool tmp;
  tmp = vi[1], vi[1] = vi[4], vi[4] = tmp;
  tmp = vi[2], vi[2] = vi[8], vi[8] = tmp;
  tmp = vi[3], vi[3] = vi[12], vi[12] = tmp;
  tmp = vi[6], vi[6] = vi[9], vi[9] = tmp;
  tmp = vi[7], vi[7] = vi[13], vi[13] = tmp;
  tmp = vi[11], vi[11] = vi[14], vi[14] = tmp;

  unsigned short u =
      (unsigned short)vi[0] | ((unsigned short)vi[1] << 1) |
      ((unsigned short)vi[2] << 2) | ((unsigned short)vi[3] << 3) |
      ((unsigned short)vi[4] << 4) | ((unsigned short)vi[5] << 5) |
      ((unsigned short)vi[6] << 6) | ((unsigned short)vi[7] << 7) |
      ((unsigned short)vi[8] << 8) | ((unsigned short)vi[9] << 9) |
      ((unsigned short)vi[10] << 10) | ((unsigned short)vi[11] << 11) |
      ((unsigned short)vi[12] << 12) | ((unsigned short)vi[13] << 13) |
      ((unsigned short)vi[14] << 14) | ((unsigned short)vi[15] << 15);
  return u;
}

inline unsigned short pre2(unsigned int i) {
  unsigned short u = s_box[i & 0xf] | (s_box[(i >> 4) & 0xf] << 4) |
                     (s_box[(i >> 8) & 0xf] << 8) |
                     (s_box[(i >> 12) & 0xf] << 12);
  return u;
}

char buf[1 << 22], *p1 = buf, *p2 = buf;
inline int getc() {
  return p1 == p2 && (p2 = (p1 = buf) + fread(buf, 1, 1 << 22, stdin), p1 == p2)
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

char pbuf[1 << 22], *pp = pbuf;
inline void push(const char& c) {
  if (pp - pbuf == 1 << 22) fwrite(pbuf, 1, 1 << 22, stdout), pp = pbuf;
  *pp++ = c;
}
inline void write(int x) {
  static char sta[8];
  int top = 0;
  while (top < 4) {
    char tmp = x & 0xf;
    sta[top++] = (tmp >= 10) ? (tmp - 10 + 'a') : (tmp + '0');
    x >>= 4;
  }
  while (top) push(sta[--top]);
}

inline void SPN(unsigned int k, unsigned int p, unsigned int& cipher,
                unsigned int& message) {
  unsigned short key[5] = {
      (unsigned short)((k >> 16) & 0xffff),
      (unsigned short)((k >> 12) & 0xffff), (unsigned short)((k >> 8) & 0xffff),
      (unsigned short)((k >> 4) & 0xffff), (unsigned short)(k & 0xffff)};
  unsigned short w(p & 0xffff);
  w = p_box[ss_box[key[0] ^ w]];
  w = p_box[ss_box[key[1] ^ w]];
  w = p_box[ss_box[key[2] ^ w]];
  w = ss_box[key[3] ^ w];
  w ^= key[4];

  cipher = w;

  w ^= 1;
  
  key[1] = p_box[key[1]];
  key[2] = p_box[key[2]];
  key[3] = p_box[key[3]];

  w = p_box[inv_ss_box[key[4] ^ w]];
  w = p_box[inv_ss_box[key[3] ^ w]];
  w = p_box[inv_ss_box[key[2] ^ w]];
  w = inv_ss_box[key[1] ^ w];
  w ^= key[0];

  message = w;
}

int main() {
  for (unsigned int i = 0; i <= 0xffff; i++) {
    p_box[i] = pre1(i);
    unsigned short tmp = pre2(i);
    ss_box[i] = tmp;
    inv_ss_box[tmp] = i;
  }
  int n;
  scanf("%d", &n);
  unsigned int key, plaintext, cipher, message;
  getchar();
  while (n--) {
    read(key);
    read(plaintext);
    SPN(key, plaintext, cipher, message);
    write(cipher);
    push(' ');
    write(message);
    push('\n');
  }
  fwrite(pbuf, 1, pp - pbuf, stdout);
  return 0;
}