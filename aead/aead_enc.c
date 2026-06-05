#include "api.h"
#include "ascon.h"
#include "permutations.h"
#include "word.h"
#include "aead.h"

#define MAX_BLOCKS 256

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {

  // --- 1. Barramentos de Memória (DMA/CMA) ---
  #pragma HLS INTERFACE m_axi port=c    offset=slave bundle=MEM_OUT depth=4112
  #pragma HLS INTERFACE m_axi port=m    offset=slave bundle=MEM_IN  depth=4096
  #pragma HLS INTERFACE m_axi port=ad   offset=slave bundle=MEM_AD  depth=4096
  #pragma HLS INTERFACE m_axi port=k    offset=slave bundle=MEM_KEY depth=16
  #pragma HLS INTERFACE m_axi port=npub offset=slave bundle=MEM_KEY depth=16
  #pragma HLS INTERFACE m_axi port=nsec offset=slave bundle=MEM_KEY depth=1

  // --- 2. NOVAS LINHAS: Registos para os Endereços Base (AXI-Lite) ---
  // Sem isto, a CPU não tem onde escrever o endereço físico dos arrays
  #pragma HLS INTERFACE s_axilite port=c    bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=m    bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=ad   bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=k    bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=npub bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=nsec bundle=CTRL

  // --- 3. Registos para Escalares (Tamanhos) e Controlo ---
  #pragma HLS INTERFACE s_axilite port=clen   bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=mlen   bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=adlen  bundle=CTRL
  #pragma HLS INTERFACE s_axilite port=return bundle=CTRL                       
                    
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  ascon_state_t s;
  s.x[0] = ASCON_128A_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128A_RATE) {
      #pragma HLS LOOP_TRIPCOUNT min=0 max=MAX_BLOCKS
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, 8);
      P8(&s);
      ad += ASCON_128A_RATE;
      adlen -= ASCON_128A_RATE;
    }
    /* final associated data block */
    if (adlen >= 8) {
      s.x[0] ^= LOADBYTES(ad, 8);
      s.x[1] ^= LOADBYTES(ad + 8, adlen - 8);
      s.x[1] ^= PAD(adlen - 8);
    } else {
      s.x[0] ^= LOADBYTES(ad, adlen);
      s.x[0] ^= PAD(adlen);
    }
    P8(&s);
  }
  /* domain separation */
  s.x[4] ^= DSEP();

  /* full plaintext blocks */
  while (mlen >= ASCON_128A_RATE) {
    #pragma HLS LOOP_TRIPCOUNT min=0 max=MAX_BLOCKS
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], 8);
    P8(&s);
    m += ASCON_128A_RATE;
    c += ASCON_128A_RATE;
    mlen -= ASCON_128A_RATE;
  }
  /* final plaintext block */
  if (mlen >= 8) {
    s.x[0] ^= LOADBYTES(m, 8);
    s.x[1] ^= LOADBYTES(m + 8, mlen - 8);
    STOREBYTES(c, s.x[0], 8);
    STOREBYTES(c + 8, s.x[1], mlen - 8);
    s.x[1] ^= PAD(mlen - 8);
  } else {
    s.x[0] ^= LOADBYTES(m, mlen);
    STOREBYTES(c, s.x[0], mlen);
    s.x[0] ^= PAD(mlen);
  }
  m += mlen;
  c += mlen;

  /* finalize */
  s.x[2] ^= K0;
  s.x[3] ^= K1;
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;

  /* get tag */
  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  return 0;
}

