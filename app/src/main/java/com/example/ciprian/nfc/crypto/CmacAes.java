package com.example.ciprian.nfc.crypto;

import java.util.Arrays;

/**
 * CMAC-AES implementation for NTAG 424 DNA.
 * Based on RFC 4493 and NIST SP 800-38B.
 */
public class CmacAes {

    private static final byte[] ZERO_BLOCK = new byte[16];
    private static final byte RB = (byte) 0x87;

    private final byte[] key;
    private final byte[] k1;
    private final byte[] k2;

    public CmacAes(byte[] key) throws Exception {
        if (key.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes for AES-128");
        }
        this.key = key.clone();

        // Generate subkeys K1 and K2
        byte[] L = AesUtils.encryptECB(key, ZERO_BLOCK);
        this.k1 = generateSubkey(L);
        this.k2 = generateSubkey(k1);
    }

    /**
     * Generates a subkey by left-shifting and conditionally XORing with RB
     */
    private byte[] generateSubkey(byte[] input) {
        byte[] result = new byte[16];
        int carry = 0;

        // Left shift by 1 bit
        for (int i = 15; i >= 0; i--) {
            int b = (input[i] & 0xFF) << 1;
            result[i] = (byte) (b | carry);
            carry = (b >> 8) & 1;
        }

        // XOR with RB if MSB was 1
        if ((input[0] & 0x80) != 0) {
            result[15] ^= RB;
        }

        return result;
    }

    /**
     * Calculates full CMAC (16 bytes)
     */
    public byte[] calculate(byte[] message) throws Exception {
        int blockCount = (message.length + 15) / 16;
        if (blockCount == 0) {
            blockCount = 1;
        }

        boolean completeLastBlock = (message.length > 0) && (message.length % 16 == 0);
        byte[] lastBlock;

        if (completeLastBlock) {
            // Complete block - XOR with K1
            lastBlock = new byte[16];
            System.arraycopy(message, (blockCount - 1) * 16, lastBlock, 0, 16);
            lastBlock = AesUtils.xor(lastBlock, k1);
        } else {
            // Incomplete block - pad and XOR with K2
            lastBlock = new byte[16];
            int remaining = message.length % 16;
            if (message.length > 0) {
                System.arraycopy(message, (blockCount - 1) * 16, lastBlock, 0, remaining);
            }
            lastBlock[remaining] = (byte) 0x80;
            lastBlock = AesUtils.xor(lastBlock, k2);
        }

        // CBC-MAC with last block modified
        byte[] x = ZERO_BLOCK.clone();
        for (int i = 0; i < blockCount - 1; i++) {
            byte[] block = new byte[16];
            System.arraycopy(message, i * 16, block, 0, 16);
            x = AesUtils.encryptECB(key, AesUtils.xor(x, block));
        }
        x = AesUtils.encryptECB(key, AesUtils.xor(x, lastBlock));

        return x;
    }

    /**
     * Calculates truncated CMAC (8 bytes) - used in NTAG 424 DNA responses
     */
    public byte[] calculateMac(byte[] message) throws Exception {
        byte[] fullMac = calculate(message);
        return Arrays.copyOf(fullMac, 8);
    }

    /**
     * Verifies CMAC
     */
    public boolean verify(byte[] message, byte[] mac) throws Exception {
        byte[] calculated = (mac.length == 8) ? calculateMac(message) : calculate(message);
        return Arrays.equals(calculated, mac);
    }

    /**
     * Creates CMAC instance with key
     */
    public static CmacAes getInstance(byte[] key) throws Exception {
        return new CmacAes(key);
    }
}
