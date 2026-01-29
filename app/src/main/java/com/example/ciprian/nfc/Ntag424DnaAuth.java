package com.example.ciprian.nfc;

import android.util.Log;

import com.example.ciprian.nfc.crypto.AesUtils;
import com.example.ciprian.nfc.crypto.CmacAes;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * NTAG 424 DNA Authentication (AuthenticateEV2).
 * Implements the secure channel establishment and encrypted communication.
 */
public class Ntag424DnaAuth {

    private static final String TAG = "NTAG424Auth";

    private final Ntag424DnaCommands commands;

    // Session keys derived during authentication
    private byte[] sessionKeyEnc;
    private byte[] sessionKeyMac;
    private byte[] ti; // Transaction Identifier
    private int cmdCounter;
    private boolean authenticated;

    public Ntag424DnaAuth(Ntag424DnaCommands commands) {
        this.commands = commands;
        this.authenticated = false;
        this.cmdCounter = 0;
    }

    /**
     * Performs AuthenticateEV2First with the given key
     */
    public boolean authenticateEV2First(byte keyNo, byte[] key) throws Exception {
        authenticated = false;

        // Step 1: Send AuthenticateEV2First command with key number
        byte[] cmdData = new byte[2];
        cmdData[0] = keyNo;
        cmdData[1] = 0x00; // Key length indicator (0x00 for AES-128)

        byte[] response1 = commands.transceive(Ntag424DnaCommands.CMD_AUTHENTICATE_EV2_FIRST, cmdData);

        if (!commands.hasMoreData(response1)) {
            Log.e(TAG, "AuthenticateEV2First failed at step 1");
            return false;
        }

        // Extract RndB (encrypted with session key based on provided key)
        byte[] encRndB = commands.getData(response1);
        if (encRndB.length != 16) {
            Log.e(TAG, "Invalid RndB length: " + encRndB.length);
            return false;
        }

        // Step 2: Decrypt RndB
        byte[] rndB = AesUtils.decryptCBC(key, encRndB);
        Log.d(TAG, "RndB: " + AesUtils.bytesToHex(rndB));

        // Step 3: Generate RndA
        byte[] rndA = AesUtils.generateRandom(16);
        Log.d(TAG, "RndA: " + AesUtils.bytesToHex(rndA));

        // Step 4: Rotate RndB left by 1 byte
        byte[] rndBRotated = AesUtils.rotateLeft(rndB);

        // Step 5: Concatenate RndA || RndB'
        byte[] rndAB = new byte[32];
        System.arraycopy(rndA, 0, rndAB, 0, 16);
        System.arraycopy(rndBRotated, 0, rndAB, 16, 16);

        // Step 6: Encrypt with IV = 0 (per NXP AN12196)
        Log.d(TAG, "RndB': " + AesUtils.bytesToHex(rndBRotated));
        Log.d(TAG, "RndA||RndB' (plain): " + AesUtils.bytesToHex(rndAB));
        byte[] encRndAB = AesUtils.encryptCBC(key, rndAB); // IV = 0
        Log.d(TAG, "Encrypted RndA||RndB': " + AesUtils.bytesToHex(encRndAB));

        // Step 7: Send second frame
        byte[] response2 = commands.transceive(Ntag424DnaCommands.CMD_ADDITIONAL_FRAME, encRndAB);

        if (!commands.isOk(response2)) {
            Log.e(TAG, "AuthenticateEV2First failed at step 2: " +
                    AesUtils.bytesToHex(commands.getStatus(response2)));
            return false;
        }

        // Step 8: Verify response (encrypted TI || RndA' || PDcap2 || PCDcap2)
        byte[] encResponse = commands.getData(response2);
        if (encResponse.length < 32) {
            Log.e(TAG, "Invalid response length: " + encResponse.length);
            return false;
        }

        // Decrypt response with IV = 0 (per NXP AN12196)
        Log.d(TAG, "Encrypted response: " + AesUtils.bytesToHex(encResponse));
        byte[] decResponse = AesUtils.decryptCBC(key, encResponse); // IV = 0

        // Extract TI (first 4 bytes)
        ti = Arrays.copyOf(decResponse, 4);
        Log.d(TAG, "TI: " + AesUtils.bytesToHex(ti));

        // Extract RndA' and verify
        byte[] rndARotatedReceived = Arrays.copyOfRange(decResponse, 4, 20);
        byte[] rndARotatedExpected = AesUtils.rotateLeft(rndA);

        Log.d(TAG, "Decrypted response: " + AesUtils.bytesToHex(decResponse));
        Log.d(TAG, "RndA sent: " + AesUtils.bytesToHex(rndA));
        Log.d(TAG, "RndA' expected: " + AesUtils.bytesToHex(rndARotatedExpected));
        Log.d(TAG, "RndA' received: " + AesUtils.bytesToHex(rndARotatedReceived));

        if (!Arrays.equals(rndARotatedReceived, rndARotatedExpected)) {
            Log.e(TAG, "RndA verification failed - key might be wrong or crypto issue");
            return false;
        }

        // Step 9: Derive session keys
        deriveSessionKeys(key, rndA, rndB);

        cmdCounter = 0;
        authenticated = true;
        Log.d(TAG, "Authentication successful!");

        return true;
    }

    /**
     * Derives session keys from RndA and RndB
     */
    private void deriveSessionKeys(byte[] key, byte[] rndA, byte[] rndB) throws Exception {
        // SV1 for encryption key: 0xA55A || 0x0001 || 0x0080 || RndA[15..14] ||
        //                         (RndA[13..8] XOR RndB[15..10]) || RndB[9..0] || RndA[7..0]
        byte[] sv1 = new byte[32];
        sv1[0] = (byte) 0xA5;
        sv1[1] = (byte) 0x5A;
        sv1[2] = 0x00;
        sv1[3] = 0x01;
        sv1[4] = 0x00;
        sv1[5] = (byte) 0x80;

        // RndA[15..14]
        sv1[6] = rndA[0];
        sv1[7] = rndA[1];

        // RndA[13..8] XOR RndB[15..10]
        for (int i = 0; i < 6; i++) {
            sv1[8 + i] = (byte) (rndA[2 + i] ^ rndB[i]);
        }

        // RndB[9..0]
        System.arraycopy(rndB, 6, sv1, 14, 10);

        // RndA[7..0]
        System.arraycopy(rndA, 8, sv1, 24, 8);

        // SV2 for MAC key: same structure but 0x5AA5 prefix
        byte[] sv2 = sv1.clone();
        sv2[0] = (byte) 0x5A;
        sv2[1] = (byte) 0xA5;

        // Derive keys using CMAC
        CmacAes cmac = new CmacAes(key);
        sessionKeyEnc = cmac.calculate(sv1);
        sessionKeyMac = cmac.calculate(sv2);

        Log.d(TAG, "Session Key Enc: " + AesUtils.bytesToHex(sessionKeyEnc));
        Log.d(TAG, "Session Key Mac: " + AesUtils.bytesToHex(sessionKeyMac));
    }

    /**
     * Builds a command with MAC for authenticated communication
     */
    public byte[] buildMacCommand(byte cmd, byte[] data) throws Exception {
        if (!authenticated) {
            throw new IllegalStateException("Not authenticated");
        }

        // Build MAC input: Cmd || CmdCounter || TI || CmdHeader || CmdData
        ByteArrayOutputStream macInput = new ByteArrayOutputStream();
        macInput.write(cmd);

        // CmdCounter (2 bytes, little endian)
        macInput.write(cmdCounter & 0xFF);
        macInput.write((cmdCounter >> 8) & 0xFF);

        // TI
        macInput.write(ti);

        // Data
        if (data != null && data.length > 0) {
            macInput.write(data);
        }

        byte[] macInputBytes = macInput.toByteArray();
        Log.d(TAG, "MAC Input (" + macInputBytes.length + " bytes): " + AesUtils.bytesToHex(macInputBytes));
        Log.d(TAG, "Session MAC Key: " + AesUtils.bytesToHex(sessionKeyMac));

        // Calculate MAC
        CmacAes cmac = new CmacAes(sessionKeyMac);
        byte[] fullMac = cmac.calculate(macInputBytes);
        Log.d(TAG, "Full CMAC (16 bytes): " + AesUtils.bytesToHex(fullMac));

        byte[] truncatedMac = truncateMac(fullMac);
        Log.d(TAG, "Truncated MAC (8 bytes): " + AesUtils.bytesToHex(truncatedMac));

        // Build command data: data || MAC
        ByteArrayOutputStream cmdData = new ByteArrayOutputStream();
        if (data != null) {
            cmdData.write(data);
        }
        cmdData.write(truncatedMac);

        return cmdData.toByteArray();
    }

    /**
     * Truncates MAC to 8 bytes (odd bytes)
     */
    private byte[] truncateMac(byte[] mac) {
        byte[] truncated = new byte[8];
        for (int i = 0; i < 8; i++) {
            truncated[i] = mac[i * 2 + 1];
        }
        return truncated;
    }

    /**
     * Sends an authenticated command with MAC
     */
    public byte[] sendMacCommand(byte cmd, byte[] data) throws Exception {
        byte[] cmdData = buildMacCommand(cmd, data);
        byte[] response = commands.transceive(cmd, cmdData);
        cmdCounter++;

        if (!commands.isOk(response)) {
            throw new Exception("Command failed: " + AesUtils.bytesToHex(commands.getStatus(response)));
        }

        // TODO: Verify response MAC if needed

        return commands.getData(response);
    }

    /**
     * Encrypts data for write commands
     */
    public byte[] encryptData(byte[] data) throws Exception {
        if (!authenticated) {
            throw new IllegalStateException("Not authenticated");
        }

        // Build IV: 0xA55A || TI || CmdCounter || 0x0000...
        byte[] iv = new byte[16];
        iv[0] = (byte) 0xA5;
        iv[1] = (byte) 0x5A;
        System.arraycopy(ti, 0, iv, 2, 4);
        iv[6] = (byte) (cmdCounter & 0xFF);
        iv[7] = (byte) ((cmdCounter >> 8) & 0xFF);

        Log.d(TAG, "Encrypt IV (before ECB): " + AesUtils.bytesToHex(iv));
        Log.d(TAG, "Session ENC Key: " + AesUtils.bytesToHex(sessionKeyEnc));
        Log.d(TAG, "CmdCounter for encryption: " + cmdCounter);

        // Encrypt IV
        byte[] encIv = AesUtils.encryptECB(sessionKeyEnc, iv);
        Log.d(TAG, "Encrypt IV (after ECB): " + AesUtils.bytesToHex(encIv));

        // Encrypt data with CBC using encrypted IV
        byte[] encrypted = AesUtils.encryptCBC(sessionKeyEnc, encIv, AesUtils.padToBlockSize(data));
        Log.d(TAG, "Encrypted result: " + AesUtils.bytesToHex(encrypted));

        return encrypted;
    }

    /**
     * Decrypts response data
     */
    public byte[] decryptData(byte[] data) throws Exception {
        if (!authenticated) {
            throw new IllegalStateException("Not authenticated");
        }

        // Build IV similar to encryption
        byte[] iv = new byte[16];
        iv[0] = (byte) 0x5A;
        iv[1] = (byte) 0xA5;
        System.arraycopy(ti, 0, iv, 2, 4);
        iv[6] = (byte) (cmdCounter & 0xFF);
        iv[7] = (byte) ((cmdCounter >> 8) & 0xFF);

        byte[] encIv = AesUtils.encryptECB(sessionKeyEnc, iv);
        return AesUtils.removePadding(AesUtils.decryptCBC(sessionKeyEnc, encIv, data));
    }

    /**
     * Changes a key on the card
     */
    public void changeKey(byte keyNo, byte[] oldKey, byte[] newKey, byte keyVersion) throws Exception {
        if (!authenticated) {
            throw new IllegalStateException("Not authenticated");
        }

        // Build key change data
        ByteArrayOutputStream keyData = new ByteArrayOutputStream();

        if (keyNo == 0) {
            // Changing the same key we authenticated with
            // Data = NewKey(16) || KeyVer(1)
            keyData.write(newKey);
            keyData.write(keyVersion);
        } else {
            // Changing a different key
            // Data = (NewKey XOR OldKey)(16) || KeyVer(1) || CRC32(NewKey)(4)
            byte[] xoredKey = AesUtils.xor(newKey, oldKey);
            keyData.write(xoredKey);
            keyData.write(keyVersion);
            // Add CRC32 of new key (JAMCRC - no final XOR, per NXP DESFire spec)
            byte[] crc = AesUtils.calculateCrc32(newKey);
            keyData.write(crc);
            Log.d(TAG, "ChangeKey: XORed key = " + AesUtils.bytesToHex(xoredKey));
            Log.d(TAG, "ChangeKey: CRC32 (JAMCRC) = " + AesUtils.bytesToHex(crc));
        }

        // Pad to multiple of 16 using 0x80 padding
        byte[] paddedData = AesUtils.padToBlockSize(keyData.toByteArray());
        Log.d(TAG, "ChangeKey: Padded data (" + paddedData.length + " bytes) = " + AesUtils.bytesToHex(paddedData));

        // Encrypt
        byte[] encryptedData = encryptData(paddedData);
        Log.d(TAG, "ChangeKey: Encrypted data = " + AesUtils.bytesToHex(encryptedData));

        // Build command: KeyNo || EncryptedData
        byte[] cmdData = new byte[1 + encryptedData.length];
        cmdData[0] = keyNo;
        System.arraycopy(encryptedData, 0, cmdData, 1, encryptedData.length);

        // Send with MAC
        sendMacCommand(Ntag424DnaCommands.CMD_CHANGE_KEY, cmdData);

        Log.d(TAG, "Key " + keyNo + " changed successfully");
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public byte[] getSessionKeyEnc() {
        return sessionKeyEnc;
    }

    public byte[] getSessionKeyMac() {
        return sessionKeyMac;
    }

    public int getCmdCounter() {
        return cmdCounter;
    }
}
