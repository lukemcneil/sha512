/* Luke McNeil - CSSE479 HW12 SHA-512 Implementation */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

u_int64_t IV [8] =
{0x6A09E667F3BCC908,
 0xBB67AE8584CAA73B,
 0x3C6EF372FE94F82B,
 0xA54FF53A5F1D36F1,
 0x510E527FADE682D1,
 0x9B05688C2B3E6C1F,
 0x1F83D9ABFB41BD6B,
 0x5BE0CD19137E2179};

u_int64_t K [80] =
{0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
 0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
 0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
 0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
 0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
 0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
 0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817};

u_int64_t getFileSize(FILE *fp) {
  fseek(fp, 0L, SEEK_END);
  u_int64_t size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  return size;
}

void printH(u_int64_t H [8]) {
  for (int i = 0; i < 8; i++) {
    printf("%016lx\n", H[i]);
  }
}

void printInlineH(u_int64_t H [8]) {
  for (int i = 0; i < 8; i++) {
    printf("%016lx", H[i]);
  }
  printf("\n");
}

u_int64_t rotr(u_int64_t x, int amount) {
  return x >> amount | x << (64 - amount);
}

u_int64_t littleSigma0(u_int64_t x) {
  return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

u_int64_t littleSigma1(u_int64_t x) {
  return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

u_int64_t bigSigma0(u_int64_t x) {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

u_int64_t bigSigma1(u_int64_t x) {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

u_int64_t ch(u_int64_t e, u_int64_t f, u_int64_t g) {
  return (e & f) ^ ((~e) & g);
}

u_int64_t maj(u_int64_t a, u_int64_t b, u_int64_t c) {
  return (a & b) ^ (a & c) ^ (b & c);
}

void scheduleMessage(u_int64_t W [80], u_int64_t M [16]) {
  for (int i = 0; i < 16; i++) {
    W[i] = M[i];
  }
  for (int i = 16; i < 80; i++) {
    W[i] = W[i-16] + littleSigma0(W[i-15]) + W[i-7] + littleSigma1(W[i-2]);
  }
  for (int i = 0; i < 80; i++) {
    //printf("W(%2d): %016lx\n", i, W[i]);
  }
}

void roundFunction(u_int64_t H [8], u_int64_t w, u_int64_t k) {
  u_int64_t a = H[0];
  u_int64_t b = H[1];
  u_int64_t c = H[2];
  u_int64_t d = H[3];
  u_int64_t e = H[4];
  u_int64_t f = H[5];
  u_int64_t g = H[6];
  u_int64_t h = H[7];
  u_int64_t temp = ch(e, f, g) + h + bigSigma1(e) + w + k;
  u_int64_t newE = temp + d;
  u_int64_t newA = bigSigma0(a) + maj(a, b, c) + temp;
  u_int64_t newB = a;
  u_int64_t newC = b;
  u_int64_t newD = c;
  u_int64_t newF = e;
  u_int64_t newG = f;
  u_int64_t newH = g;
  H[0] = newA;
  H[1] = newB;
  H[2] = newC;
  H[3] = newD;
  H[4] = newE;
  H[5] = newF;
  H[6] = newG;
  H[7] = newH;
}

void compressionFunction(u_int64_t M [16], u_int64_t H [8]) {
  u_int64_t W[80];
  u_int64_t originalH[8];
  scheduleMessage(W, M);
  for (int i = 0; i < 8; i++) {
    originalH[i] = H[i];
  }
  for (int i = 0; i < 80; i++) {
    roundFunction(H, W[i], K[i]);
    //if (i < 2) {
    //  printf("\n\nafter round %d\n", i);
    //  printf("W[i] = %016lx\n", W[i]);
    //  printf("K[i] = %016lx\n", K[i]);
    //  printH(H);
    //}
  }
  for (int i = 0; i < 8; i++) {
    H[i] += originalH[i];
  }
}

bool readBlock(u_int64_t M[16], FILE *fp, u_int64_t fileSize, u_int64_t offset) {
  for (int i = 0; i < 16; i++) {
    M[i] = 0;
  }
  fread(M, sizeof(u_int64_t), 16, fp);
  int64_t bytesLeftToRead = fileSize - offset;
  int64_t bytesLeftOver = 128 - bytesLeftToRead;
  int64_t byteOffset = (bytesLeftOver-1) % 8;
  int64_t sixtyFourIntsLeftOver = (bytesLeftOver-1) / 8;
  for (int i = 0; i < 16; i++) {
    M[i] = htobe64(M[i]);
  }
  u_int64_t shift = 0x0000000000000080;
  if (bytesLeftOver > 0) {
    M[15-sixtyFourIntsLeftOver] ^= (shift << (byteOffset * 8));
  }
  //printf("%d\n", bytesLeftToRead);
  //printf("%d\n", bytesLeftOver);
  if (bytesLeftOver > 16) {
    M[15] ^= fileSize * 8;
    return false;
  }
  return true;
}

int main(int argc, char *argv[]) {
  // command line args
  if (argc != 2) {
    printf("incorrect number of arguments\n");
    return -1;
  }

  u_int64_t M[16];
  u_int64_t H[8];
  for (int i = 0; i < 8; i++) {
    H[i] = IV[i];
  }
  char *fileName = argv[1];
  FILE *inputFP = fopen(fileName, "rb");
  if (inputFP == NULL) {
    return -1;
  }
  u_int64_t inputSize = getFileSize(inputFP);
  //printf("input size: %ld\n", inputSize);
  u_int64_t offset = 0;
  while (readBlock(M, inputFP, inputSize, offset)) {
    //for (int i = 0; i < 16; i++) {
    //  printf("%016lx\n", M[i]);
    //}
    //printf("round %ld\n", offset/128);
    offset += 128;
    compressionFunction(M, H);
  }
  //for (int i = 0; i < 16; i++) {
  //  printf("%016lx\n", M[i]);
  //}
  compressionFunction(M, H);
  //printf("\n\nfinal hash\n");
  //printH(H);
  printInlineH(H);

  /* u_int64_t test [8] = */
  /*   {0x838df69485d18b84, */
  /*    0x03589a869d0591d4, */
  /*    0xfd868fc15521f1ce, */
  /*    0x65e35d59ba35aca0, */
  /*    0xc00cc8339d6ca0cc, */
  /*    0x44422f10ed7f26e5, */
  /*    0x0c2ba73f999aeae6, */
  /*    0x686f160035a761ce}; */
  /* for (int i = 0; i < 8; i++) { */
  /* H[i] = test[i]; */
  /* } */
  /* printf("\n\n"); */
  /* printH(H); */
  /* u_int64_t w = 0; */
  /* u_int64_t k = K[1]; */
  /* printf("w = %016lx\n", w); */
  /* printf("k = %016lx\n", k); */
  /* roundFunction(H, w, k); */
  /* printf("\n\n"); */
  /* printH(H); */
}
