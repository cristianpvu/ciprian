package com.example.ciprian.nfc.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AES-128 utilities for NTAG 424 DNA communication.
 * Uses CBC mode with zero IV for key derivation and ECB for some operations.
 */
public class AesUtils {

    private static final String AES = "AES";
    private static final String AES_CBC_NO_PADDING = "AES/CBC/NoPadding";
    private static final String AES_ECB_NO_PADDING = "AES/ECB/NoPadding";

    /**
     * Encrypts data using AES-128-CBC with zero IV
     */
    public static byte[] encryptCBC(byte[] key, byte[] data) throws Exception {
        return encryptCBC(key, new byte[16], data);
    }

    /**
     * Encrypts data using AES-128-CBC with specified IV
     */
    public static byte[] encryptCBC(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_NO_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(padToBlockSize(data));
    }

    /**
     * Decrypts data using AES-128-CBC with zero IV
     */
    public static byte[] decryptCBC(byte[] key, byte[] data) throws Exception {
        return decryptCBC(key, new byte[16], data);
    }

    /**
     * Decrypts data using AES-128-CBC with specified IV
     */
    public static byte[] decryptCBC(byte[] key, byte[] iv, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_CBC_NO_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * Encrypts a single block using AES-128-ECB (for key diversification)
     */
    public static byte[] encryptECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ECB_NO_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(padToBlockSize(data));
    }

    /**
     * Decrypts a single block using AES-128-ECB
     */
    public static byte[] decryptECB(byte[] key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ECB_NO_PADDING);
        SecretKeySpec keySpec = new SecretKeySpec(key, AES);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    /**
     * Generates a random AES-128 key (16 bytes)
     */
    public static byte[] generateRandomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    /**
     * Generates random bytes of specified length
     */
    public static byte[] generateRandom(int length) {
        byte[] data = new byte[length];
        new SecureRandom().nextBytes(data);
        return data;
    }

    /**
     * Pads data to AES block size (16 bytes) using 0x80 padding
     */
    public static byte[] padToBlockSize(byte[] data) {
        int blockSize = 16;
        if (data.length % blockSize == 0) {
            return data;
        }
        int paddedLength = ((data.length / blockSize) + 1) * blockSize;
        byte[] padded = new byte[paddedLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = (byte) 0x80;
        return padded;
    }

    /**
     * Removes 0x80 padding from data
     */
    public static byte[] removePadding(byte[] data) {
        int end = data.length - 1;
        while (end >= 0 && data[end] == 0x00) {
            end--;
        }
        if (end >= 0 && data[end] == (byte) 0x80) {
            return Arrays.copyOf(data, end);
        }
        return data;
    }

    /**
     * XORs two byte arrays
     */
    public static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    /**
     * Rotates byte array left by one byte
     */
    public static byte[] rotateLeft(byte[] data) {
        byte[] result = new byte[data.length];
        System.arraycopy(data, 1, result, 0, data.length - 1);
        result[data.length - 1] = data[0];
        return result;
    }

    /**
     * Converts byte array to hex string
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Converts hex string to byte array
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) return new byte[0];
        hex = hex.replace(" ", "").toUpperCase();
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Calculates CRC32 as used by NXP DESFire/NTAG 424 DNA
     * This is CRC-32/JAMCRC variant:
     * Polynomial: 0xEDB88320 (reflected)
     * Initial value: 0xFFFFFFFF
     * Final XOR: 0x00000000 (no final inversion)
     */
    public static byte[] calculateCrc32(byte[] data) {
        int crc = 0xFFFFFFFF;

        for (byte b : data) {
            crc ^= (b & 0xFF);
            for (int i = 0; i < 8; i++) {
                if ((crc & 1) != 0) {
                    crc = (crc >>> 1) ^ 0xEDB88320;
                } else {
                    crc = crc >>> 1;
                }
            }
        }

        // Return as 4 bytes, little-endian (no final XOR for NXP variant)
        return new byte[]{
                (byte) (crc & 0xFF),
                (byte) ((crc >> 8) & 0xFF),
                (byte) ((crc >> 16) & 0xFF),
                (byte) ((crc >> 24) & 0xFF)
        };
    }

    /**
     * Calculates standard CRC32 (with final XOR)
     * Used for verification/testing
     */
    public static byte[] calculateCrc32Standard(byte[] data) {
        int crc = 0xFFFFFFFF;

        for (byte b : data) {
            crc ^= (b & 0xFF);
            for (int i = 0; i < 8; i++) {
                if ((crc & 1) != 0) {
                    crc = (crc >>> 1) ^ 0xEDB88320;
                } else {
                    crc = crc >>> 1;
                }
            }
        }

        // Final XOR with 0xFFFFFFFF for standard CRC32
        crc ^= 0xFFFFFFFF;

        return new byte[]{
                (byte) (crc & 0xFF),
                (byte) ((crc >> 8) & 0xFF),
                (byte) ((crc >> 16) & 0xFF),
                (byte) ((crc >> 24) & 0xFF)
        };
    }
}
