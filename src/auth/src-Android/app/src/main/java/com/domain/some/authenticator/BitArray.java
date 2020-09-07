package com.domain.some.authenticator;

// Inspired by phatfingers from StackOverflow
public class BitArray {

    private static final int ALL_ONES = 0xFFFFFFFF;
    private static final int WORD_SIZE = 32;
    private int bits[];
    private int arrSize;

    public BitArray(int size) {
        bits = new int[size / WORD_SIZE + (size % WORD_SIZE == 0 ? 0 : 1)];
        arrSize = size;
    }

    public boolean getBit(int pos) {
        return (bits[pos / WORD_SIZE] & (1 << (pos % WORD_SIZE))) != 0;
    }

    public void setBit(int pos, boolean b) {
        int word = bits[pos / WORD_SIZE];
        int posBit = 1 << (pos % WORD_SIZE);
        if (b) {
            word |= posBit;
        } else {
            word &= (ALL_ONES - posBit);
        }
        bits[pos / WORD_SIZE] = word;
    }

    public int fillBitArray(byte[] data) {
        int mask;

        int j = 0;
        for (byte item : data) {
            for (mask = 128; mask > 0 && j < arrSize; mask >>= 1, j++)
                setBit(j, ((item & mask) > 0));
        }

        return 0;
    }

    public int fillBitArray(int[] data) {
        int mask;

        int j = 0;
        for (int item : data) {
            for (mask = 1024; mask > 0 && j < arrSize; mask >>= 1, j++)
                setBit(j, ((item & mask) > 0));
        }

        return 0;
    }
}
