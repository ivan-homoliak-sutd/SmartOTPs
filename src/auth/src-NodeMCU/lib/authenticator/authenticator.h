/*********************************************************************
* Filename:   authenticator.h
*********************************************************************/

#ifndef AUTHENTICATOR_H
#define AUTHENTICATOR_H

#include "sha256.h"
#include "sha3.h"

#include <stdint.h>
#include <stddef.h>

#define MAX_LEAVES 64
#define TOKEN_SIZE 16
#define MAX 64
#define ENT (TOKEN_SIZE * 8)
#define CS (ENT / 32)
#define MS ((ENT + CS) / 11)

#define MASK 0x80
#define SHIFT_LEFT 7

extern uint16_t chainLen;
extern uint16_t numOfLeaves;
extern uint16_t numOfLeavesInSubtree;
extern uint8_t seed[TOKEN_SIZE];

struct OTP_Index {
    uint16_t within_tree;
    uint16_t within_chain;
};

void compute_root(uint8_t result[TOKEN_SIZE]);
void compute_sha256(const uint8_t data[MAX], const size_t data_len, uint8_t result[32]);
void print_hex(const uint8_t *sha256, size_t size);
void compute_otp_index(const uint16_t index, struct OTP_Index *otp_index);
void generate_seed();
void compute_mnemonic_sentence(uint8_t sequence[TOKEN_SIZE], char const **sentence);
void compute_node_sha256(const uint16_t index, uint8_t result[TOKEN_SIZE]);
void merge_sha256(const uint8_t hash_left[TOKEN_SIZE], const uint8_t hash_right[TOKEN_SIZE], uint8_t result[TOKEN_SIZE]);
void compute_h(const uint8_t data[MAX], const size_t data_len, uint8_t result[SHA256_BLOCK_SIZE]);
void compute_sha256_of_index(const uint16_t index, uint8_t result[TOKEN_SIZE]);
void compute_otp(const uint32_t index, uint8_t result[TOKEN_SIZE]);
void print_sentence(const char *sentence[MS]);

#endif // AUTHENTICATOR_h
