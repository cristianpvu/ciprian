package com.example.ciprian.nfc;

import android.nfc.tech.IsoDep;
import android.util.Log;

import com.example.ciprian.nfc.crypto.AesUtils;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Low-level commands for NTAG 424 DNA communication.
 * Implements ISO 7816-4 APDU wrapping for DESFire commands.
 */
public class Ntag424DnaCommands {

    private static final String TAG = "NTAG424Commands";

    // Status codes
    public static final byte[] STATUS_OK = {(byte) 0x91, 0x00};
    public static final byte[] STATUS_MORE_DATA = {(byte) 0x91, (byte) 0xAF};
    public static final byte[] STATUS_AUTH_ERROR = {(byte) 0x91, (byte) 0xAE};
    public static final byte[] STATUS_PERMISSION_DENIED = {(byte) 0x91, (byte) 0x9D};
    public static final byte[] STATUS_INTEGRITY_ERROR = {(byte) 0x91, (byte) 0x1E};

    // DESFire commands (wrapped in ISO 7816)
    public static final byte CMD_GET_VERSION = 0x60;
    public static final byte CMD_SELECT_APPLICATION = 0x5A;
    public static final byte CMD_AUTHENTICATE_EV2_FIRST = 0x71;
    public static final byte CMD_AUTHENTICATE_EV2_NON_FIRST = 0x77;
    public static final byte CMD_ADDITIONAL_FRAME = (byte) 0xAF;
    public static final byte CMD_READ_DATA = (byte) 0xAD;
    public static final byte CMD_WRITE_DATA = (byte) 0x8D;
    public static final byte CMD_GET_FILE_SETTINGS = (byte) 0xF5;
    public static final byte CMD_CHANGE_FILE_SETTINGS = 0x5F;
    public static final byte CMD_CHANGE_KEY = (byte) 0xC4;
    public static final byte CMD_GET_KEY_VERSION = 0x64;

    // NTAG 424 DNA specific
    public static final byte[] AID_NTAG424DNA = {(byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};
    public static final byte[] DEFAULT_KEY = new byte[16]; // All zeros

    // File IDs
    public static final byte FILE_CC = 0x01;        // Capability Container
    public static final byte FILE_NDEF = 0x02;      // NDEF Data
    public static final byte FILE_PROPRIETARY = 0x03; // Proprietary Data

    private final IsoDep isoDep;

    public Ntag424DnaCommands(IsoDep isoDep) {
        this.isoDep = isoDep;
    }

    /**
     * Wraps a DESFire command in ISO 7816-4 APDU format
     */
    public byte[] wrapCommand(byte command, byte[] data) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(0x90);           // CLA
        baos.write(command);        // INS
        baos.write(0x00);           // P1
        baos.write(0x00);           // P2

        if (data != null && data.length > 0) {
            baos.write(data.length); // Lc
            baos.write(data, 0, data.length);
        }
        baos.write(0x00);           // Le

        return baos.toByteArray();
    }

    /**
     * Sends command and returns response (excluding status bytes)
     */
    public byte[] transceive(byte command, byte[] data) throws Exception {
        byte[] apdu = wrapCommand(command, data);
        Log.d(TAG, ">>> " + AesUtils.bytesToHex(apdu));

        byte[] response = isoDep.transceive(apdu);
        Log.d(TAG, "<<< " + AesUtils.bytesToHex(response));

        return response;
    }

    /**
     * Checks if response indicates success
     */
    public boolean isOk(byte[] response) {
        if (response == null || response.length < 2) return false;
        return response[response.length - 2] == (byte) 0x91 &&
               response[response.length - 1] == 0x00;
    }

    /**
     * Checks if response indicates more data available
     */
    public boolean hasMoreData(byte[] response) {
        if (response == null || response.length < 2) return false;
        return response[response.length - 2] == (byte) 0x91 &&
               response[response.length - 1] == (byte) 0xAF;
    }

    /**
     * Gets response data (excluding status bytes)
     */
    public byte[] getData(byte[] response) {
        if (response == null || response.length < 2) return new byte[0];
        return Arrays.copyOf(response, response.length - 2);
    }

    /**
     * Gets status bytes from response
     */
    public byte[] getStatus(byte[] response) {
        if (response == null || response.length < 2) return new byte[0];
        return Arrays.copyOfRange(response, response.length - 2, response.length);
    }

    /**
     * Gets full version information (3 parts)
     */
    public VersionInfo getVersion() throws Exception {
        // First frame
        byte[] response1 = transceive(CMD_GET_VERSION, null);
        if (!hasMoreData(response1)) {
            throw new Exception("GetVersion failed: " + AesUtils.bytesToHex(getStatus(response1)));
        }

        // Second frame
        byte[] response2 = transceive(CMD_ADDITIONAL_FRAME, null);
        if (!hasMoreData(response2)) {
            throw new Exception("GetVersion part 2 failed");
        }

        // Third frame
        byte[] response3 = transceive(CMD_ADDITIONAL_FRAME, null);
        if (!isOk(response3)) {
            throw new Exception("GetVersion part 3 failed");
        }

        return new VersionInfo(
            getData(response1),
            getData(response2),
            getData(response3)
        );
    }

    /**
     * Selects the NTAG 424 DNA application
     * Tries native DESFire command first, falls back to ISO SELECT
     */
    public void selectApplication() throws Exception {
        // Try native DESFire SelectApplication first
        byte[] response = transceive(CMD_SELECT_APPLICATION, AID_NTAG424DNA);
        if (isOk(response)) {
            Log.d(TAG, "SelectApplication (native) succeeded");
            return;
        }

        // If native command fails, try ISO SELECT (for tags in ISO mode)
        Log.d(TAG, "Native SelectApplication failed, trying ISO SELECT...");
        response = isoSelect(AID_NTAG424DNA);
        if (isIsoOk(response)) {
            Log.d(TAG, "ISO SELECT succeeded");
            return;
        }

        // If both fail, the tag might already be in application context
        // Try to proceed anyway
        Log.w(TAG, "Both SelectApplication methods failed, proceeding anyway...");
    }

    /**
     * ISO 7816-4 SELECT command
     */
    public byte[] isoSelect(byte[] aid) throws Exception {
        // ISO SELECT: CLA=00, INS=A4, P1=04 (select by DF name), P2=0C (no FCI)
        byte[] apdu = new byte[5 + aid.length + 1];
        apdu[0] = 0x00;                 // CLA
        apdu[1] = (byte) 0xA4;          // INS (SELECT)
        apdu[2] = 0x04;                 // P1 (select by DF name)
        apdu[3] = 0x0C;                 // P2 (no response data)
        apdu[4] = (byte) aid.length;    // Lc
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        apdu[apdu.length - 1] = 0x00;   // Le

        Log.d(TAG, ">>> " + AesUtils.bytesToHex(apdu));
        byte[] response = isoDep.transceive(apdu);
        Log.d(TAG, "<<< " + AesUtils.bytesToHex(response));

        return response;
    }

    /**
     * Checks if ISO response is OK (SW1=90, SW2=00)
     */
    public boolean isIsoOk(byte[] response) {
        if (response == null || response.length < 2) return false;
        return response[response.length - 2] == (byte) 0x90 &&
               response[response.length - 1] == 0x00;
    }

    /**
     * Gets file settings
     */
    public byte[] getFileSettings(byte fileNo) throws Exception {
        byte[] response = transceive(CMD_GET_FILE_SETTINGS, new byte[]{fileNo});
        if (!isOk(response)) {
            throw new Exception("GetFileSettings failed: " + AesUtils.bytesToHex(getStatus(response)));
        }
        return getData(response);
    }

    /**
     * Reads data from a file (plain communication)
     */
    public byte[] readDataPlain(byte fileNo, int offset, int length) throws Exception {
        byte[] params = new byte[7];
        params[0] = fileNo;
        params[1] = (byte) (offset & 0xFF);
        params[2] = (byte) ((offset >> 8) & 0xFF);
        params[3] = (byte) ((offset >> 16) & 0xFF);
        params[4] = (byte) (length & 0xFF);
        params[5] = (byte) ((length >> 8) & 0xFF);
        params[6] = (byte) ((length >> 16) & 0xFF);

        byte[] response = transceive(CMD_READ_DATA, params);
        if (!isOk(response) && !hasMoreData(response)) {
            throw new Exception("ReadData failed: " + AesUtils.bytesToHex(getStatus(response)));
        }

        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(getData(response));

        while (hasMoreData(response)) {
            response = transceive(CMD_ADDITIONAL_FRAME, null);
            data.write(getData(response));
        }

        return data.toByteArray();
    }

    /**
     * Gets key version
     */
    public byte getKeyVersion(byte keyNo) throws Exception {
        byte[] response = transceive(CMD_GET_KEY_VERSION, new byte[]{keyNo});
        if (!isOk(response)) {
            throw new Exception("GetKeyVersion failed: " + AesUtils.bytesToHex(getStatus(response)));
        }
        byte[] data = getData(response);
        return data.length > 0 ? data[0] : 0;
    }

    /**
     * Version information holder
     */
    public static class VersionInfo {
        public final byte[] hardwareInfo;
        public final byte[] softwareInfo;
        public final byte[] productionInfo;
        public final byte[] uid;

        public VersionInfo(byte[] hw, byte[] sw, byte[] prod) {
            this.hardwareInfo = hw;
            this.softwareInfo = sw;
            this.productionInfo = prod;
            // UID is the first 7 bytes of production info
            this.uid = (prod != null && prod.length >= 7) ?
                    Arrays.copyOf(prod, 7) : new byte[0];
        }

        public String getUidHex() {
            return AesUtils.bytesToHex(uid);
        }

        public String getHardwareVersion() {
            if (hardwareInfo == null || hardwareInfo.length < 7) return "Unknown";
            return String.format("%d.%d", hardwareInfo[3], hardwareInfo[4]);
        }

        public String getSoftwareVersion() {
            if (softwareInfo == null || softwareInfo.length < 7) return "Unknown";
            return String.format("%d.%d", softwareInfo[3], softwareInfo[4]);
        }

        public int getStorageSize() {
            if (hardwareInfo == null || hardwareInfo.length < 6) return 0;
            int sizeCode = hardwareInfo[5] & 0xFF;
            return (int) Math.pow(2, sizeCode >> 1);
        }

        public boolean isNtag424Dna() {
            if (hardwareInfo == null || hardwareInfo.length < 3) return false;
            return hardwareInfo[0] == 0x04 && // NXP
                   hardwareInfo[1] == 0x04 && // Type
                   hardwareInfo[2] == 0x02;   // Subtype
        }
    }
}
