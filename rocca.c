// rocca_timing.c
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h> // For high-resolution timing on Windows
#else
#include <time.h>    // For high-resolution timing on Unix-like systems
#endif

#include <immintrin.h> // For AES-NI intrinsics

// Constants and Macros
#define S_NUM 8
#define M_NUM 2
#define BLKSIZE 32
#define NUM_LOOP_FOR_INIT 20

#define Z0_3 0x428a2f98
#define Z0_2 0xd728ae22
#define Z0_1 0x71374491
#define Z0_0 0x23ef65cd

#define Z1_3 0xb5c0fbcf
#define Z1_2 0xec4d3b2f
#define Z1_1 0xe9b5dba5
#define Z1_0 0x8189dbbc

#define enc(m, k) _mm_aesenc_si128(m, k)
#define xor(a, b) _mm_xor_si128(a, b)

void print_state(__m128i state) {
    uint8_t bytes[16];
    _mm_storeu_si128((__m128i *)bytes, state);
    for (int i = 0; i < 16; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
}

#define UPDATE_STATE(X)                  \
    tmp7 = S[7];                         \
    tmp6 = S[6];                         \
    S[7] = xor(S[6], S[0]);              \
    S[6] = enc(S[5], S[4]);              \
    S[5] = enc(S[4], S[3]);              \
    S[4] = xor(S[3], X[1]);              \
    S[3] = enc(S[2], S[1]);              \
    S[2] = xor(S[1], tmp6);              \
    S[1] = enc(S[0], tmp7);              \
    S[0] = xor(tmp7, X[0]);

#define LOAD(src, dst)                                    \
    dst[0] = _mm_loadu_si128((const __m128i *)((src)));   \
    dst[1] = _mm_loadu_si128((const __m128i *)((src) + 16));

#define XOR_STRM(src, dst)                                      \
    dst[0] = xor(src[0], enc(S[1], S[5]));                      \
    dst[1] = xor(src[1], enc(xor(S[0], S[4]), S[2]));

#define STORE(src, dst)                            \
    _mm_storeu_si128((__m128i *)((dst)), src[0]);  \
    _mm_storeu_si128((__m128i *)((dst) + 16), src[1]);

#define CAST_U64_TO_M128(v)                                                \
    _mm_set_epi32(0, 0, (((uint64_t)(v)) >> 32) & 0xFFFFFFFF,              \
                  (((uint64_t)(v)) >> 0) & 0xFFFFFFFF)

typedef struct Context {
    __m128i state[8];
    size_t sizeM;
    size_t sizeAD;
} context;

void log_state(__m128i *state) {
    // Function omitted for brevity
}

void stream_init(context *ctx, const uint8_t *key, const uint8_t *nonce) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    S[0] = _mm_loadu_si128((const __m128i *)(key + 16));
    S[1] = _mm_loadu_si128((const __m128i *)(nonce));
    S[2] = _mm_set_epi32(Z0_3, Z0_2, Z0_1, Z0_0);
    S[3] = _mm_set_epi32(Z1_3, Z1_2, Z1_1, Z1_0);
    S[4] = xor(S[1], S[0]);
    S[5] = _mm_setzero_si128();
    S[6] = _mm_loadu_si128((const __m128i *)(key));
    S[7] = _mm_setzero_si128();
    M[0] = S[2];
    M[1] = S[3];

    for (size_t i = 0; i < NUM_LOOP_FOR_INIT; ++i) {
        UPDATE_STATE(M);
    }

    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeM = 0;
    ctx->sizeAD = 0;
}

void stream_proc_ad(context *ctx, const uint8_t *ad, size_t size) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    for (size_t i = 0; i < size / BLKSIZE; ++i) {
        LOAD(ad + i * BLKSIZE, M);
        UPDATE_STATE(M);
    }

    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeAD += size;
}

void stream_enc(context *ctx, uint8_t *dst, const uint8_t *src, size_t size) {
    __m128i S[S_NUM], P[M_NUM], C[M_NUM], tmp7, tmp6;

    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }
    for (size_t i = 0; i < size / BLKSIZE; ++i) {
        LOAD(src + i * BLKSIZE, P);
        XOR_STRM(P, C);
        STORE(C, dst + i * BLKSIZE);
        UPDATE_STATE(P);
    }

    for (size_t i = 0; i < S_NUM; ++i) {
        ctx->state[i] = S[i];
    }
    ctx->sizeM += size;
}

void stream_finalize(context *ctx, uint8_t *tag) {
    __m128i S[S_NUM], M[M_NUM], tmp7, tmp6;

    for (size_t i = 0; i < S_NUM; ++i) {
        S[i] = ctx->state[i];
    }

    M[0] = CAST_U64_TO_M128(ctx->sizeAD << 3);
    M[1] = CAST_U64_TO_M128(ctx->sizeM << 3);

    for (size_t i = 0; i < NUM_LOOP_FOR_INIT; ++i) {
        UPDATE_STATE(M);
    }

    for (size_t i = 1; i < S_NUM; ++i) {
        S[0] = xor(S[0], S[i]);
    }

    _mm_storeu_si128((__m128i *)tag, S[0]);
}

void measure_encryption_time(size_t data_size_bits) {
    size_t data_size_bytes = data_size_bits / 8;
    uint8_t key[32] = {0};
    uint8_t nonce[16] = {0};
    context ctx;
    uint8_t *plaintext = (uint8_t *)malloc(data_size_bytes);
    uint8_t *ciphertext = (uint8_t *)malloc(data_size_bytes);
    uint8_t *associated_data = (uint8_t *)malloc(16); // Adjust size as needed
    uint8_t tag[16];

    if (!plaintext || !ciphertext || !associated_data) {
        printf("Memory allocation failed\n");
        free(plaintext);
        free(ciphertext);
        free(associated_data);
        return;
    }

    // Initialize plaintext and associated data
    memset(plaintext, 0, data_size_bytes);
    memset(associated_data, 0, 16);

    // Variables for timing
    const int num_trials = 1000;
    double times[num_trials];
    double total_time = 0.0;
    double min_time = 1e9;
    double max_time = 0.0;

#ifdef _WIN32
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
#endif

    for (int trial = 0; trial < num_trials; trial++) {
        stream_init(&ctx, key, nonce);
        stream_proc_ad(&ctx, associated_data, 16);

#ifdef _WIN32
        LARGE_INTEGER start_time, end_time;
        QueryPerformanceCounter(&start_time);
#else
        struct timespec start_time, end_time;
        clock_gettime(CLOCK_MONOTONIC, &start_time);
#endif

        stream_enc(&ctx, ciphertext, plaintext, data_size_bytes);
        stream_finalize(&ctx, tag);

#ifdef _WIN32
        QueryPerformanceCounter(&end_time);
        double time_taken = (double)(end_time.QuadPart - start_time.QuadPart) * 1000.0 / frequency.QuadPart;
#else
        clock_gettime(CLOCK_MONOTONIC, &end_time);
        double time_taken = (end_time.tv_sec - start_time.tv_sec) * 1000.0;
        time_taken += (end_time.tv_nsec - start_time.tv_nsec) / 1e6;
#endif

        times[trial] = time_taken;
        total_time += time_taken;
        if (time_taken < min_time)
            min_time = time_taken;
        if (time_taken > max_time)
            max_time = time_taken;
    }

    double average_time = total_time / num_trials;

    // Calculate standard deviation
    double sum_squared_diff = 0.0;
    for (int i = 0; i < num_trials; i++) {
        double diff = times[i] - average_time;
        sum_squared_diff += diff * diff;
    }
    double std_dev = sqrt(sum_squared_diff / num_trials);

    printf("Encryption Time Statistics for %zu-bit data:\n", data_size_bits);
    printf("Average Encryption Time: %.3f us\n", average_time * 1000);
    printf("Minimum Encryption Time: %.3f us\n", min_time *  1000);
    printf("Maximum Encryption Time: %.3f us\n", max_time *  1000);
    printf("Standard Deviation: %.3f us\n\n", std_dev * 1000);

    free(plaintext);
    free(ciphertext);
    free(associated_data);
}

int main() {
    // Measure encryption time for different data sizes
    measure_encryption_time(256);    // 256 bits
    measure_encryption_time(1024);   // 1024 bits
    measure_encryption_time(4096);   // 4096 bits

    return 0;
}
