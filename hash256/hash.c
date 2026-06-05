#include "api.h"
#include "ascon.h"
#include "permutations.h"
#include "word.h"

int crypto_hash(unsigned char* out, const unsigned char* in,
                unsigned long long len) {
  #pragma HLS INTERFACE m_axi     port=out offset=slave bundle=gmem0 depth=32
  #pragma HLS INTERFACE s_axilite port=out              bundle=control
  #pragma HLS INTERFACE m_axi     port=in  offset=slave bundle=gmem1 depth=4096
  #pragma HLS INTERFACE s_axilite port=in               bundle=control
  #pragma HLS INTERFACE s_axilite port=len              bundle=control
  #pragma HLS INTERFACE s_axilite port=return           bundle=control
          
  /* initialize */
  ascon_state_t s;
  #pragma HLS ARRAY_PARTITION variable=s.x complete dim=1

  s.x[0] = ASCON_HASH_IV;
  s.x[1] = 0;
  s.x[2] = 0;
  s.x[3] = 0;
  s.x[4] = 0;
  P12(&s);

  /* absorb full plaintext blocks */
  while (len >= ASCON_HASH_RATE) {
    #pragma HLS LOOP_TRIPCOUNT min=0 max=4096 avg=64
    #pragma HLS PIPELINE
    s.x[0] ^= LOADBYTES(in, 8);
    P12(&s);
    in += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* absorb final plaintext block */
  s.x[0] ^= LOADBYTES(in, len);
  s.x[0] ^= PAD(len);
  P12(&s);

  /* squeeze full output blocks */
  len = CRYPTO_BYTES;
  while (len > ASCON_HASH_RATE) {
    #pragma HLS LOOP_TRIPCOUNT min=3 max=3 avg=3
    #pragma HLS PIPELINE  
    STOREBYTES(out, s.x[0], 8);
    P12(&s);
    out += ASCON_HASH_RATE;
    len -= ASCON_HASH_RATE;
  }
  /* squeeze final output block */
  STOREBYTES(out, s.x[0], len);

  return 0;
}
