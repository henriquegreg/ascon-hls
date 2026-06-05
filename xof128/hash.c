#include "api.h"
#include "ascon.h"
#include "permutations.h"
#include "word.h"

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {

#pragma HLS INTERFACE m_axi     port=out    offset=slave bundle=gmem depth=64
#pragma HLS INTERFACE s_axilite port=out              bundle=control
#pragma HLS INTERFACE m_axi     port=in     offset=slave bundle=gmem depth=MAX_MSG_LEN
#pragma HLS INTERFACE s_axilite port=in               bundle=control
#pragma HLS INTERFACE s_axilite port=len    bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control

  ascon_state_t s;
#pragma HLS ARRAY_PARTITION variable=s.x complete dim=1

  s.x[0] = ASCON_XOF_IV;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  P12(&s);

  int num_full_blocks = (int)(len / ASCON_HASH_RATE);
  int tail_len        = (int)(len % ASCON_HASH_RATE);

  ABSORB_LOOP:
  for (int i = 0; i < num_full_blocks; i++) {
#pragma HLS PIPELINE
#pragma HLS LOOP_TRIPCOUNT min=0 max=MAX_ABSORB_BLOCKS avg=4
    s.x[0] ^= LOADBYTES(in + i * ASCON_HASH_RATE, 8);
    P12(&s);
  }

  /* Absorb final plaintext block (partial, 0..7 bytes) */
  s.x[0] ^= LOADBYTES(in + num_full_blocks * ASCON_HASH_RATE, tail_len);
  s.x[0] ^= PAD(tail_len);
  P12(&s);

  /* Squeeze full output blocks */
  SQUEEZE_LOOP:
  for (int i = 0; i < CRYPTO_BYTES / ASCON_HASH_RATE - 1; i++) {
#pragma HLS PIPELINE
#pragma HLS LOOP_TRIPCOUNT min=7 max=7 avg=7
    STOREBYTES(out + i * ASCON_HASH_RATE, s.x[0], 8);
    P12(&s);
  }

  /* Squeeze final output block */
  STOREBYTES(out + (CRYPTO_BYTES / ASCON_HASH_RATE - 1) * ASCON_HASH_RATE,
             s.x[0], ASCON_HASH_RATE);

  return 0;
}