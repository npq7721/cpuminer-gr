#include "gr-gate.h"
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../cubehash/sph_cubehash.h"
#include "../echo/sph_echo.h"
#include "../fugue/sph_fugue.h"
#include "../groestl/sph_groestl.h"
#include "../hamsi/sph_hamsi.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../luffa/sph_luffa.h"
#include "../lyra2/lyra2.h"
#include "../sha/sph_sha2.h"
#include "../shabal/sph_shabal.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../skein/sph_skein.h"
#include "../whirlpool/sph_whirlpool.h"
#include "cryptonote/crypto/c_keccak.h"
#include "cryptonote/crypto/hash.h"
#include "cryptonote/cryptonight_dark.h"
#include "cryptonote/cryptonight_dark_lite.h"
#include "cryptonote/cryptonight_fast.h"
#include "cryptonote/cryptonight_lite.h"
#include "cryptonote/cryptonight_turtle.h"
#include "cryptonote/cryptonight_turtle_lite.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int64_t gr_get_max64() { return 0x7ffLL; }

bool register_gr_algo(algo_gate_t *gate) {
  gate->scanhash = (void *)&scanhash_gr;
  gate->hash = (void *)&gr_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->get_max64 = (void *)&gr_get_max64;
  opt_target_factor = 65536.0;
  return true;
};

enum Algo {
  BLAKE = 0,
  BMW,
  GROESTL,
  JH,
  KECCAK,
  SKEIN,
  LUFFA,
  CUBEHASH,
  SHAVITE,
  SIMD,
  ECHO,
  HAMSI,
  FUGUE,
  SHABAL,
  WHIRLPOOL,
  HASH_FUNC_COUNT
};

enum CNAlgo {
  CNDark = 0,
  CNDarklite,
  CNFast,
  CNLite,
  CNTurtle,
  CNTurtlelite,
  CN_HASH_FUNC_COUNT
};

static void selectAlgo(unsigned char nibble, bool *selectedAlgos,
                       uint8_t *selectedIndex, int algoCount,
                       int *currentCount) {
  uint8_t algoDigit = (nibble & 0x0F) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
  algoDigit = (nibble >> 4) % algoCount;
  if (!selectedAlgos[algoDigit]) {
    selectedAlgos[algoDigit] = true;
    selectedIndex[currentCount[0]] = algoDigit;
    currentCount[0] = currentCount[0] + 1;
  }
}

static void getAlgoString(const void *mem, unsigned int size,
                          uint8_t *selectedAlgoOutput, int algoCount) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  unsigned int len = size / 2;
  bool selectedAlgo[algoCount];
  for (int z = 0; z < algoCount; z++) {
    selectedAlgo[z] = false;
  }
  int selectedCount = 0;
  for (i = 0; i < len; i++) {
    selectAlgo(p[i], selectedAlgo, selectedAlgoOutput, algoCount,
               &selectedCount);
    if (selectedCount == algoCount) {
      break;
    }
  }
  if (selectedCount < algoCount) {
    for (uint8_t i = 0; i < algoCount; i++) {
      if (!selectedAlgo[i]) {
        selectedAlgoOutput[selectedCount] = i;
        selectedCount++;
      }
    }
  }
}

static void doCNAlgo(uint8_t algo, const void *in, void *hash, int size) {
  switch (algo) {
  case CNDark:
    cryptonightdark_hash(in, hash, size, 1);
    break;
  case CNDarklite:
    cryptonightdarklite_hash(in, hash, size, 1);
    break;
  case CNFast:
    cryptonightfast_hash(in, hash, size, 1);
    break;
  case CNLite:
    cryptonightlite_hash(in, hash, size, 1);
    break;
  case CNTurtle:
    cryptonightturtle_hash(in, hash, size, 1);
    break;
  case CNTurtlelite:
    cryptonightturtlelite_hash(in, hash, size, 1);
    break;
  }
}

static void doCoreAlgo(uint8_t algo, const void *in, void *hash, int size) {
  switch (algo) {
  case BLAKE:;
    sph_blake512_context ctx_blake;
    sph_blake512_init(&ctx_blake);
    sph_blake512(&ctx_blake, in, size);
    sph_blake512_close(&ctx_blake, hash);
    break;
  case BMW:;
    sph_bmw512_context ctx_bmw;
    sph_bmw512_init(&ctx_bmw);
    sph_bmw512(&ctx_bmw, in, size);
    sph_bmw512_close(&ctx_bmw, hash);
    break;
  case GROESTL:;
    sph_groestl512_context ctx_groestl;
    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, in, size);
    sph_groestl512_close(&ctx_groestl, hash);
    break;
  case SKEIN:;
    sph_skein512_context ctx_skein;
    sph_skein512_init(&ctx_skein);
    sph_skein512(&ctx_skein, in, size);
    sph_skein512_close(&ctx_skein, hash);
    break;
  case JH:;
    sph_jh512_context ctx_jh;
    sph_jh512_init(&ctx_jh);
    sph_jh512(&ctx_jh, in, size);
    sph_jh512_close(&ctx_jh, hash);
    break;
  case KECCAK:;
    sph_keccak512_context ctx_keccak;
    sph_keccak512_init(&ctx_keccak);
    sph_keccak512(&ctx_keccak, in, size);
    sph_keccak512_close(&ctx_keccak, hash);
    break;
  case LUFFA:;
    sph_luffa512_context ctx_luffa;
    sph_luffa512_init(&ctx_luffa);
    sph_luffa512(&ctx_luffa, in, size);
    sph_luffa512_close(&ctx_luffa, hash);
    break;
  case CUBEHASH:;
    sph_cubehash512_context ctx_cubehash;
    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512(&ctx_cubehash, in, size);
    sph_cubehash512_close(&ctx_cubehash, hash);
    break;
  case SHAVITE:;
    sph_shavite512_context ctx_shavite;
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, in, size);
    sph_shavite512_close(&ctx_shavite, hash);
    break;
  case SIMD:;
    sph_simd512_context ctx_simd;
    sph_simd512_init(&ctx_simd);
    sph_simd512(&ctx_simd, in, size);
    sph_simd512_close(&ctx_simd, hash);
    break;
  case ECHO:;
    sph_echo512_context ctx_echo;
    sph_echo512_init(&ctx_echo);
    sph_echo512(&ctx_echo, in, size);
    sph_echo512_close(&ctx_echo, hash);
    break;
  case HAMSI:;
    sph_hamsi512_context ctx_hamsi;
    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512(&ctx_hamsi, in, size);
    sph_hamsi512_close(&ctx_hamsi, hash);
    break;
  case FUGUE:;
    sph_fugue512_context ctx_fugue;
    sph_fugue512_init(&ctx_fugue);
    sph_fugue512(&ctx_fugue, in, size);
    sph_fugue512_close(&ctx_fugue, hash);
    break;
  case SHABAL:;
    sph_shabal512_context ctx_shabal;
    sph_shabal512_init(&ctx_shabal);
    sph_shabal512(&ctx_shabal, in, size);
    sph_shabal512_close(&ctx_shabal, hash);
    break;
  case WHIRLPOOL:;
    sph_whirlpool_context ctx_whirlpool;
    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool(&ctx_whirlpool, in, size);
    sph_whirlpool_close(&ctx_whirlpool, hash);
    break;
  }
}

static const uint8_t cc[20][3] = {
    {0, 1, 2}, {0, 1, 3}, {0, 1, 4}, {0, 1, 5}, {0, 2, 3}, {0, 2, 4}, {0, 2, 5},
    {0, 3, 4}, {0, 3, 5}, {0, 4, 5}, {1, 2, 3}, {1, 2, 4}, {1, 2, 5}, {1, 3, 4},
    {1, 3, 5}, {1, 4, 5}, {2, 3, 4}, {2, 3, 5}, {2, 4, 5}, {3, 4, 5}};

static void gr_bench(int type, int algo, void *input, double time, int cn) {
  struct timeval start, end, diff;
  double elapsed, hashes = 0;
  gettimeofday(&start, NULL);
  static __thread uint32_t nonce = 0;
  do {
    uint32_t hash[64 / 4];
    if (type == 3) {
      static __thread int rot = 0;
      be32enc((uint32_t *)&input[76], nonce);
      gr_hash(hash, input, rot++);
      if (rot == 20) {
        rot = 0;
      }
      ++nonce;
    } else if (type == 2) {
      be32enc((uint32_t *)&input[76], nonce);
      gr_hash(hash, input, cn);
      ++nonce;
    } else if (type == 1) {
      doCoreAlgo(algo, input, hash, 64);
    } else if (type == 0) {
      doCNAlgo(algo, input, hash, 64);
    }

    hashes++;
    gettimeofday(&end, NULL);
    timeval_subtract(&diff, &end, &start);
    elapsed = (double)diff.tv_sec + (double)diff.tv_usec / 1e6;
  } while (elapsed <= time);

  pthread_mutex_lock(&stats_lock);
  gr_bench_hashes += hashes;
  gr_bench_time += elapsed;
  pthread_mutex_unlock(&stats_lock);
}

static void print_stats(const char *prefix, bool reset, bool same_line) {
  double hashrate;
  char hr_units[4] = {0};

  pthread_mutex_lock(&stats_lock);

  hashrate = gr_bench_hashes / gr_bench_time * opt_n_threads;
  scale_hash_for_display(&hashrate, hr_units);
  if (same_line) {
    pthread_mutex_unlock(&applog_lock);
    printf("                      %s\t%.2lf %sH/s (%.2lfs)\t-> %.3lf %sH/s per "
           "thread.\r",
           prefix, hashrate, hr_units, gr_bench_time / opt_n_threads,
           hashrate / opt_n_threads, hr_units);
    fflush(stdout);
    pthread_mutex_unlock(&applog_lock);

  } else {
    applog(LOG_BLUE, "%s\t%.2lf %sH/s (%.2lfs)\t-> %.3lf %sH/s per thread.",
           prefix, hashrate, hr_units, gr_bench_time / opt_n_threads,
           hashrate / opt_n_threads, hr_units);
  }
  if (reset) {
    gr_bench_time = 0;
    gr_bench_hashes = 0;
  }
  pthread_mutex_unlock(&stats_lock);
}

static void sync() {
  static volatile int done = 0;

  pthread_mutex_lock(&stats_lock);
  done++;
  if (done != opt_n_threads) {
    pthread_cond_wait(&sync_cond, &stats_lock);
  } else {
    done = 0;
    pthread_cond_broadcast(&sync_cond);
  }
  pthread_mutex_unlock(&stats_lock);
}

static void gr_extensive_bench(void *input, int thr_id) {
  char prefix[50];
  if (opt_benchmark_extended) {
    int i;
    if (thr_id == 0) {
      applog(LOG_BLUE, "Testing Cryptonight algorithms (10s per algorithm)");
    }
    for (i = 0; i < 6; i++) {
      gr_bench(0, i, input, 10., 0);
      sync();
      if (thr_id == 0) {
        sprintf(prefix, "Type %d:", i + 1);
        print_stats(prefix, true, false);
      }
    }
    if (thr_id == 0) {
      applog(LOG_BLUE, "Testing Core algorithms (2s per algorithm)");
    }
    for (i = 0; i < 15; i++) {
      gr_bench(1, i, input, 2., 0);

      sync();
      if (thr_id == 0) {
        sprintf(prefix, "Type %d:", i + 1);
        print_stats(prefix, true, false);
      }
    }
    if (thr_id == 0) {
      applog(LOG_BLUE, "Testing CN Rotations (10s per rotation)");
    }
    static volatile int rot = 0;
    while (rot < 20) {
      gr_bench(2, -1, input, 10., rot);

      sync();
      if (thr_id == 0) {
        sprintf(prefix, "Rotation %d %d %d:", cc[rot][0], cc[rot][1],
                cc[rot][2]);
        print_stats(prefix, true, false);
        rot++;
      }
      // Make sure rot is updated.
      sync();
    }
  }

  // Default benchmark that goes through all CN scenarios with Random Core.
  double target_time = 30;
  double target_multi = 1;

  if (thr_id == 0) {
    applog(LOG_BLUE, "Testing Average performance");
  }
  while (true) {
    gr_bench(3, -1, input, 2., 0);

    sync();
    if (thr_id == 0) {
      if (target_time * target_multi > gr_bench_time / opt_n_threads) {
        // Update line.
        print_stats("Hashrate (Avg):", false, true);
      } else {
        // Print stats for good.
        print_stats("Hashrate (Avg):", false, false);
        target_multi++;
      }
    }
  }
  exit(0);
}

void gr_hash(void *output, const void *input, uint8_t cn) {
  static __thread uint8_t hash_1[64];
  static __thread uint8_t hash_2[64];

  static __thread uint8_t selectedAlgoOutput[15] = {0};
  static __thread uint8_t selectedCNAlgoOutput[6] = {0};

  getAlgoString(input + 4, 64, selectedAlgoOutput, 15);
  if (cn > 19) {
    getAlgoString(input + 4, 64, selectedCNAlgoOutput, 6);
  } else {
    // Benchmarking.
    selectedCNAlgoOutput[0] = cc[cn][0];
    selectedCNAlgoOutput[1] = cc[cn][1];
    selectedCNAlgoOutput[2] = cc[cn][2];
  }

  // First phasee uses full 80 bytes. Ther rest usees shorter 64 bytes.
  doCoreAlgo(selectedAlgoOutput[0], input, hash_1, 80);
  doCoreAlgo(selectedAlgoOutput[1], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[2], hash_2, hash_1, 64);
  doCoreAlgo(selectedAlgoOutput[3], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[4], hash_2, hash_1, 64);
  doCNAlgo(selectedCNAlgoOutput[0], hash_1, hash_2, 64);
  memset(hash_2 + 32, 0, 32);

  doCoreAlgo(selectedAlgoOutput[5], hash_2, hash_1, 64);
  doCoreAlgo(selectedAlgoOutput[6], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[7], hash_2, hash_1, 64);
  doCoreAlgo(selectedAlgoOutput[8], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[9], hash_2, hash_1, 64);
  doCNAlgo(selectedCNAlgoOutput[1], hash_1, hash_2, 64);
  memset(hash_2 + 32, 0, 32);

  doCoreAlgo(selectedAlgoOutput[10], hash_2, hash_1, 64);
  doCoreAlgo(selectedAlgoOutput[11], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[12], hash_2, hash_1, 64);
  doCoreAlgo(selectedAlgoOutput[13], hash_1, hash_2, 64);
  doCoreAlgo(selectedAlgoOutput[14], hash_2, hash_1, 64);
  doCNAlgo(selectedCNAlgoOutput[2], hash_1, hash_2, 64);
  // memset(hash_2 + 32, 0, 32);

  memcpy(output, hash_2, 32);
}

int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                struct thr_info *mythr) {
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;

  uint32_t _ALIGN(64) endiandata[20];
  const uint32_t first_nonce = pdata[19];
  uint32_t nonce = first_nonce;
  int thr_id = mythr->id;

  if (opt_benchmark) {
    gr_extensive_bench(endiandata, thr_id);
    return 0;
  }

  swab32_array(endiandata, pdata, 20);

  uint32_t hash[8];
  const uint32_t Htarg = ptarget[7];
  do {
    be32enc(&endiandata[19], nonce);

    gr_hash(hash, endiandata, 0xFF);

    if (hash[7] <= Htarg) {
      pdata[19] = nonce;
      *hashes_done = pdata[19] - first_nonce;
      submit_solution(work, hash, mythr);
    }
    ++nonce;

  } while (nonce < max_nonce && !work_restart[thr_id].restart);

  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce + 1;
  return 0;
}
