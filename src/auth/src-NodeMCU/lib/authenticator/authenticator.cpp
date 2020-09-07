/*********************************************************************
* Filename:   authenticator.cpp
*********************************************************************/

#include "authenticator.h"
#include "dictionary.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

void compute_otp(const uint32_t index, uint8_t result[TOKEN_SIZE]) {
    uint8_t sha256[SHA256_BLOCK_SIZE];
    struct OTP_Index otp_index;
    // get index within tree and hashchaing
    compute_otp_index(index, &otp_index);

    compute_sha256_of_index(otp_index.within_tree, result);

    // looping through hashchaing
    for (uint16_t i = 0; i < otp_index.within_chain; i++) {
        compute_h(result, TOKEN_SIZE, sha256);
        memcpy(result, sha256, TOKEN_SIZE);
    }
}

void compute_root(uint8_t result[TOKEN_SIZE]) {
    // allocate array for 64 16B values
    uint8_t nodes[TOKEN_SIZE * MAX_LEAVES];

    // set step
    uint16_t step = (TOKEN_SIZE * MAX_LEAVES) / numOfLeaves;

    // to get all the leaves of the tree, we need to compute the first hash of seed and index
    // and then loop through the hashchain
    for (uint16_t tree_index = 0; tree_index < numOfLeaves; tree_index++) {
        uint8_t *node = nodes + (tree_index * step);
        compute_sha256_of_index(tree_index, node);
        for (uint16_t chain_index = 0; chain_index < chainLen - 1; chain_index++) {
            compute_h(node, tree_index, node);
        }

        // the leave of the tree is a hash of the last otp in hashchain
        compute_h(node, TOKEN_SIZE, node);
    }

    // now we loop through the tree leaves up to the root
    while (step < MAX_LEAVES * TOKEN_SIZE) {
        for (uint32_t i = 0; i < (TOKEN_SIZE * MAX_LEAVES); i += step * 2) {
            merge_sha256(nodes + i, nodes + i + step, nodes + i);
        }
        step *= 2;
    }

    // the root is at index 0 of the array
    memcpy(result, nodes, TOKEN_SIZE);
}

void merge_sha256(const uint8_t sha256_left[TOKEN_SIZE], const uint8_t sha256_right[TOKEN_SIZE], uint8_t result[TOKEN_SIZE]) {
    uint8_t sha256[SHA256_BLOCK_SIZE];
    uint8_t data[TOKEN_SIZE * 2];
    memcpy(data, sha256_left, TOKEN_SIZE);
    memcpy(data + TOKEN_SIZE, sha256_right, TOKEN_SIZE);
    compute_h(data, 2 * TOKEN_SIZE, sha256);
    memcpy(result, sha256, TOKEN_SIZE);

    return;
}

void compute_sha256_of_index(const uint16_t index, uint8_t result[TOKEN_SIZE]) {
    uint8_t sha256[SHA256_BLOCK_SIZE];

    // we need to convert the 16bit index to 64bit
    const uint64_t index_long = index;

    uint8_t data[2 * TOKEN_SIZE];

    // this solves endianess problem
    *(data) = *(((uint8_t*) &index_long) + 7);
    *(data + 1) = *(((uint8_t*) &index_long) + 6);
    *(data + 2) = *(((uint8_t*) &index_long) + 5);
    *(data + 3) = *(((uint8_t*) &index_long) + 4);
    *(data + 4) = *(((uint8_t*) &index_long) + 3);
    *(data + 5) = *(((uint8_t*) &index_long) + 2);
    *(data + 6) = *(((uint8_t*) &index_long) + 1);
    *(data + 7) = *(((uint8_t*) &index_long));

    // compute hash of index
    compute_h(data, sizeof(uint64_t), sha256);

    // append the hash of index to the seed
    memcpy(data, seed, TOKEN_SIZE);
    memcpy(data + TOKEN_SIZE, sha256, TOKEN_SIZE);

    compute_h(data, 2 * TOKEN_SIZE, sha256);
    memcpy(result, sha256, TOKEN_SIZE);

    return;
}

void compute_mnemonic_sentence(uint8_t initial_entropy[TOKEN_SIZE], char const **sentence) {

    // the entropy is 16B + 4b of its hash
    uint8_t checksum[SHA256_BLOCK_SIZE];
    compute_sha256(initial_entropy, TOKEN_SIZE, checksum);

    uint8_t entropy[TOKEN_SIZE + 1];

    memcpy(entropy, initial_entropy, TOKEN_SIZE);
    memcpy(entropy + TOKEN_SIZE, checksum, 1);

    uint16_t word_indices[MS];
    memset(word_indices, 0, sizeof(uint16_t) * MS);
    uint16_t word_index = 0;

    uint8_t mask = MASK;
    uint8_t shift_left = SHIFT_LEFT;
    uint8_t *byte = entropy;
    int16_t index = 0;

    // taking out chunks of 11 bits from entropy and storing then in word_indices
    while (index < MS * 11) {
        word_index += ((*byte & mask) >> shift_left) << (10 - index % 11);
        if ((index + 1) % 11 == 0 && index > 0) {
            word_indices[(index + 1) / 11 - 1] = word_index;
            word_index = 0;
        }
        mask >>= 1;
        shift_left--;
        if ((index + 1) % 8 == 0 && index > 0) {
            byte++;
            mask = MASK;
            shift_left = SHIFT_LEFT;
        }
        index++;
    }

    // getting the words of dictionary
    for (uint8_t i = 0; i < MS; i++) {
        sentence[i] = dictionary[word_indices[i]];
    }
    return;
}

void compute_otp_index(const uint16_t index, struct OTP_Index *otp_index) {

    const uint16_t num_of_otps_in_subtree = chainLen * numOfLeavesInSubtree;
    const uint16_t index_of_subtree = index / num_of_otps_in_subtree;
    const uint16_t num_of_otps_in_one_iteration_of_subtree = num_of_otps_in_subtree / chainLen;
    const uint16_t index_within_subtree = index % num_of_otps_in_subtree;
    const uint16_t index_within_iteration = index_within_subtree % num_of_otps_in_one_iteration_of_subtree;

    otp_index->within_chain = chainLen - (index_within_subtree / num_of_otps_in_one_iteration_of_subtree) - 1;
    otp_index->within_tree = index_of_subtree * numOfLeavesInSubtree + index_within_iteration;
    return;
}

void compute_h(const uint8_t data[MAX], const size_t data_len, uint8_t result[SHA256_BLOCK_SIZE]) {
    SHA3_256((struct ethash_h256*) result, data, data_len);
    return;
}

// this sha256 version is used only to compute hash of entropy
void compute_sha256(const uint8_t data[MAX], const size_t data_len, uint8_t result[SHA256_BLOCK_SIZE]) {

    SHA256_CTX ctx;
    sha256_init(&ctx);

    sha256_update(&ctx, data, data_len);
    uint8_t buffer[SHA256_BLOCK_SIZE];

    sha256_final(&ctx, buffer);
    memcpy(result, buffer, SHA256_BLOCK_SIZE);

    return;
}

void generate_seed() {
    for (uint16_t i = 0; i < TOKEN_SIZE; i++) {
         seed[i] = rand() % 255;
    }
}
