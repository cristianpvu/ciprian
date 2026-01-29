package com.example.ciprian.nfc;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

import com.example.ciprian.nfc.crypto.AesUtils;
import com.example.ciprian.nfc.crypto.CmacAes;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Main class for programming NTAG 424 DNA chips.
 * Handles the complete flow: read info, authenticate, change keys, configure SDM.
 */
public class Ntag424DnaProgrammer {

    private static final String TAG = "NTAG424Programmer";

    // Key numbers
    public static final byte KEY_APP_MASTER = 0x00;
    public static final byte KEY_SDM_META_READ = 0x01;
    public static final byte KEY_SDM_FILE_READ = 0x02;
    public static final byte KEY_CHANGE_KEY = 0x03;
    public static final byte KEY_WRITE = 0x04;

    private IsoDep isoDep;
    private Ntag424DnaCommands commands;
    private Ntag424DnaAuth auth;

    public interface ProgressCallback {
        void onProgress(String message, int progress);
        void onError(String error);
        void onSuccess(ProgrammingResult result);
    }

    /**
     * Connects to the tag and initializes communication
     */
    public void connect(Tag tag) throws Exception {
        isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            throw new Exception("Tag does not support IsoDep");
        }

        isoDep.connect();
        isoDep.setTimeout(5000);

        commands = new Ntag424DnaCommands(isoDep);
        auth = new Ntag424DnaAuth(commands);
    }

    /**
     * Disconnects from the tag
     */
    public void disconnect() {
        try {
            if (isoDep != null && isoDep.isConnected()) {
                isoDep.close();
            }
        } catch (Exception e) {
            Log.e(TAG, "Error disconnecting", e);
        }
    }

    /**
     * Reads basic tag information
     */
    public TagInfo readTagInfo() throws Exception {
        Ntag424DnaCommands.VersionInfo version = commands.getVersion();

        if (!version.isNtag424Dna()) {
            throw new Exception("This is not an NTAG 424 DNA tag");
        }

        commands.selectApplication();

        TagInfo info = new TagInfo();
        info.uid = version.getUidHex();
        info.hardwareVersion = version.getHardwareVersion();
        info.softwareVersion = version.getSoftwareVersion();
        info.storageSize = version.getStorageSize();

        // Check key version to see if tag has default keys
        try {
            byte keyVersion = commands.getKeyVersion(KEY_APP_MASTER);
            info.keyVersion = keyVersion;
            info.hasDefaultKeys = (keyVersion == 0x00);
            Log.d(TAG, "Key version: " + String.format("0x%02X", keyVersion) +
                       ", hasDefaultKeys: " + info.hasDefaultKeys);
        } catch (Exception e) {
            Log.w(TAG, "Could not read key version: " + e.getMessage());
            info.keyVersion = -1;
            info.hasDefaultKeys = false;
        }

        // Try to read current NDEF
        try {
            byte[] ndefData = commands.readDataPlain(Ntag424DnaCommands.FILE_NDEF, 0, 256);
            info.currentNdefUrl = parseNdefUrl(ndefData);
        } catch (Exception e) {
            Log.w(TAG, "Could not read NDEF: " + e.getMessage());
        }

        return info;
    }

    /**
     * Programs the tag with new keys and SDM configuration
     *
     * @param config   Programming configuration
     * @param callback Progress callback
     */
    public void programTag(ProgrammingConfig config, ProgressCallback callback) {
        new Thread(() -> {
            try {
                programTagInternal(config, callback);
            } catch (Exception e) {
                Log.e(TAG, "Programming failed", e);
                callback.onError(e.getMessage());
            }
        }).start();
    }

    private void programTagInternal(ProgrammingConfig config, ProgressCallback callback)
            throws Exception {

        callback.onProgress("Connecting to tag...", 5);

        // Get version and select application
        Ntag424DnaCommands.VersionInfo version = commands.getVersion();
        if (!version.isNtag424Dna()) {
            throw new Exception("Not an NTAG 424 DNA tag");
        }

        commands.selectApplication();
        callback.onProgress("Tag identified: " + version.getUidHex(), 10);

        // Authenticate with current key (default or provided)
        callback.onProgress("Authenticating...", 15);
        byte[] currentKey = config.currentKey != null ? config.currentKey : Ntag424DnaCommands.DEFAULT_KEY;

        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentKey)) {
            throw new Exception("Authentication failed. Wrong key?");
        }
        callback.onProgress("Authenticated successfully", 20);

        // Generate new keys if not provided
        byte[] newAppMasterKey = config.appMasterKey != null ?
                config.appMasterKey : AesUtils.generateRandomKey();
        byte[] newSdmMetaReadKey = config.sdmMetaReadKey != null ?
                config.sdmMetaReadKey : AesUtils.generateRandomKey();
        byte[] newSdmFileReadKey = config.sdmFileReadKey != null ?
                config.sdmFileReadKey : AesUtils.generateRandomKey();

        // Step 1: Configure SDM first (test MAC/encryption)
        callback.onProgress("Configuring SDM...", 30);
        configureSdm(config.baseUrl, newSdmMetaReadKey, newSdmFileReadKey);
        Log.d(TAG, "SDM configuration succeeded - MAC/encryption works!");

        // Step 2: Write NDEF with SDM-enabled URL
        callback.onProgress("Writing NDEF data...", 45);
        writeNdefWithSdm(config.baseUrl);
        Log.d(TAG, "NDEF write succeeded!");

        // Step 3: Re-authenticate before changing keys
        callback.onProgress("Re-authenticating for key changes...", 55);
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentKey)) {
            throw new Exception("Re-authentication failed");
        }

        // Step 4: Change keys (other keys first, master key last)
        callback.onProgress("Changing SDM Meta Read key...", 65);
        auth.changeKey(KEY_SDM_META_READ, Ntag424DnaCommands.DEFAULT_KEY,
                newSdmMetaReadKey, (byte) 0x01);

        callback.onProgress("Changing SDM File Read key...", 75);
        auth.changeKey(KEY_SDM_FILE_READ, Ntag424DnaCommands.DEFAULT_KEY,
                newSdmFileReadKey, (byte) 0x01);

        // Step 5: Re-authenticate and change master key last
        callback.onProgress("Changing master key...", 85);
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentKey)) {
            throw new Exception("Re-authentication for master key change failed");
        }
        auth.changeKey(KEY_APP_MASTER, currentKey, newAppMasterKey, (byte) 0x01);

        callback.onProgress("Programming complete!", 100);

        // Build result
        ProgrammingResult result = new ProgrammingResult();
        result.uid = version.getUidHex();
        result.appMasterKey = AesUtils.bytesToHex(newAppMasterKey);
        result.sdmMetaReadKey = AesUtils.bytesToHex(newSdmMetaReadKey);
        result.sdmFileReadKey = AesUtils.bytesToHex(newSdmFileReadKey);
        result.baseUrl = config.baseUrl;

        callback.onSuccess(result);
    }

    /**
     * Configures SDM (Secure Dynamic Messaging) for the NDEF file.
     * Based on NXP AN12196 and NTAG 424 DNA datasheet.
     *
     * Uses PLAIN mirroring (MetaReadKey=0xF) so UID and counter appear as
     * plain ASCII hex in the URL. CMAC is computed with FileReadKey for authentication.
     */
    private void configureSdm(String baseUrl, byte[] metaReadKey, byte[] fileReadKey)
            throws Exception {

        // Determine URL prefix to calculate correct file offsets
        String urlAfterPrefix;
        if (baseUrl.startsWith("https://www.")) {
            urlAfterPrefix = baseUrl.substring(12);
        } else if (baseUrl.startsWith("http://www.")) {
            urlAfterPrefix = baseUrl.substring(11);
        } else if (baseUrl.startsWith("https://")) {
            urlAfterPrefix = baseUrl.substring(8);
        } else if (baseUrl.startsWith("http://")) {
            urlAfterPrefix = baseUrl.substring(7);
        } else {
            urlAfterPrefix = baseUrl;
        }

        // NDEF file layout:
        // [0-1] NDEF message length (2 bytes)
        // [2]   NDEF record header 0xD1
        // [3]   Type length 0x01
        // [4]   Payload length
        // [5]   Type 'U' 0x55
        // [6]   URI prefix code
        // [7+]  URL data (after prefix removal)
        //
        // URL data: urlAfterPrefix + "?uid=00000000000000&ctr=000000&cmac=0000000000000000"

        int ndefHeaderSize = 7;
        int uidOffset = ndefHeaderSize + urlAfterPrefix.length() + 5; // +5 for "?uid="
        int ctrOffset = uidOffset + 14 + 5; // +14 for UID (7 bytes = 14 hex) + 5 for "&ctr="
        int cmacOffset = ctrOffset + 6 + 6; // +6 for counter (3 bytes = 6 hex) + 6 for "&cmac="

        Log.d(TAG, "SDM Offsets - UID: " + uidOffset + " (0x" + Integer.toHexString(uidOffset) +
                "), CTR: " + ctrOffset + " (0x" + Integer.toHexString(ctrOffset) +
                "), CMAC: " + cmacOffset + " (0x" + Integer.toHexString(cmacOffset) + ")");
        Log.d(TAG, "URL after prefix removal: '" + urlAfterPrefix + "' (len=" + urlAfterPrefix.length() + ")");

        // Build file settings
        ByteArrayOutputStream settings = new ByteArrayOutputStream();

        // 1. FileOption (1 byte): SDM enabled (bit 6), CommMode = Plain (bits 1-0 = 00)
        settings.write(0x40);

        // 2. AccessRights (2 bytes)
        //    Byte 1: RW access (key 0) || Change access (key 0) = 0x00
        //    Byte 2: Read access (E=free) || Write access (key 0) = 0xE0
        settings.write(0x00);
        settings.write(0xE0);

        // 3. SDMOptions (1 byte): bit 0=SDM, bit 6=UID mirror, bit 7=ReadCtr mirror
        settings.write(0xC1);

        // 4. SDMAccessRights (2 bytes):
        //    Byte 1: SDMCtrRetKey[7:4] || SDMMetaReadKey[3:0]
        //    Byte 2: SDMFileReadKey[7:4] || SDMCtrIncKey[3:0]
        //    MetaRead=F(free/plain), FileRead=2(key 2), CtrRet=F(free), CtrInc=F(free)
        settings.write(0xFF); // CtrRet=F, MetaRead=F
        settings.write(0x2F); // FileRead=2, CtrInc=F

        // 5. UIDOffset (3 bytes LE) - present because SDMOptions bit 6 = 1
        writeOffset(settings, uidOffset);

        // 6. SDMReadCtrOffset (3 bytes LE) - present because SDMOptions bit 7 = 1
        writeOffset(settings, ctrOffset);

        // 7. SDMMACInputOffset (3 bytes LE) - always present
        //    Start of data used for CMAC calculation
        writeOffset(settings, uidOffset);

        // 8. SDMMACOffset (3 bytes LE) - always present
        //    Where the CMAC placeholder is in the file
        writeOffset(settings, cmacOffset);

        // NO PICCDataOffset - because SDMMetaReadKey = 0xF (plain mirroring)
        // NO SDMENCOffset/Length - because no encrypted file data
        // NO SDMReadCtrLimit - because SDMOptions bit 1 = 0

        byte[] settingsData = settings.toByteArray();
        Log.d(TAG, "ChangeFileSettings data (" + settingsData.length + " bytes): " +
                AesUtils.bytesToHex(settingsData));

        // Build command: FileNo || SettingsData
        byte[] cmdData = new byte[1 + settingsData.length];
        cmdData[0] = Ntag424DnaCommands.FILE_NDEF;
        System.arraycopy(settingsData, 0, cmdData, 1, settingsData.length);

        auth.sendMacCommand(Ntag424DnaCommands.CMD_CHANGE_FILE_SETTINGS, cmdData);

        Log.d(TAG, "SDM configured successfully");
    }

    private void writeOffset(ByteArrayOutputStream out, int offset) {
        out.write(offset & 0xFF);
        out.write((offset >> 8) & 0xFF);
        out.write((offset >> 16) & 0xFF);
    }

    /**
     * Writes NDEF URL message with SDM placeholders
     */
    private void writeNdefWithSdm(String baseUrl) throws Exception {
        // Build NDEF message
        // URL with placeholders: baseUrl?uid=00000000000000&ctr=000000&cmac=0000000000000000

        String fullUrl = baseUrl +
                "?uid=00000000000000" +  // 14 chars placeholder for UID
                "&ctr=000000" +           // 6 chars placeholder for counter
                "&cmac=0000000000000000"; // 16 chars placeholder for CMAC

        byte[] ndefMessage = buildNdefUrlRecord(fullUrl);

        // Write to NDEF file
        ByteArrayOutputStream cmdData = new ByteArrayOutputStream();
        cmdData.write(Ntag424DnaCommands.FILE_NDEF);

        // Offset (3 bytes LE)
        cmdData.write(0x00);
        cmdData.write(0x00);
        cmdData.write(0x00);

        // Length (3 bytes LE)
        cmdData.write(ndefMessage.length & 0xFF);
        cmdData.write((ndefMessage.length >> 8) & 0xFF);
        cmdData.write((ndefMessage.length >> 16) & 0xFF);

        // Data
        cmdData.write(ndefMessage);

        auth.sendMacCommand(Ntag424DnaCommands.CMD_WRITE_DATA, cmdData.toByteArray());

        Log.d(TAG, "NDEF written: " + fullUrl);
    }

    /**
     * Builds an NDEF URL record
     */
    private byte[] buildNdefUrlRecord(String url) {
        // Determine URL prefix
        byte prefixCode = 0x00;
        String urlData = url;

        if (url.startsWith("https://www.")) {
            prefixCode = 0x02;
            urlData = url.substring(12);
        } else if (url.startsWith("http://www.")) {
            prefixCode = 0x01;
            urlData = url.substring(11);
        } else if (url.startsWith("https://")) {
            prefixCode = 0x04;
            urlData = url.substring(8);
        } else if (url.startsWith("http://")) {
            prefixCode = 0x03;
            urlData = url.substring(7);
        }

        byte[] urlBytes = urlData.getBytes();
        int payloadLength = 1 + urlBytes.length; // prefix + URL

        ByteArrayOutputStream ndef = new ByteArrayOutputStream();

        // NDEF file structure: Length (2 bytes) + NDEF message
        int totalLength = 3 + payloadLength; // header + type + payload

        // Length field (2 bytes)
        ndef.write((totalLength >> 8) & 0xFF);
        ndef.write(totalLength & 0xFF);

        // NDEF Record Header
        // MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001 (Well-known)
        ndef.write(0xD1);

        // Type length
        ndef.write(0x01);

        // Payload length (short record)
        ndef.write(payloadLength);

        // Type: 'U' for URI
        ndef.write(0x55);

        // Payload: prefix code + URL
        ndef.write(prefixCode);
        ndef.write(urlBytes, 0, urlBytes.length);

        return ndef.toByteArray();
    }

    /**
     * Parses NDEF URL from raw data
     */
    private String parseNdefUrl(byte[] data) {
        if (data == null || data.length < 7) return null;

        try {
            // Skip length bytes
            int offset = 2;

            // Check header
            if ((data[offset] & 0xD0) != 0xD0) return null;

            int typeLen = data[offset + 1] & 0xFF;
            int payloadLen = data[offset + 2] & 0xFF;

            if (data[offset + 3] != 0x55) return null; // Not URI type

            byte prefixCode = data[offset + 4];
            String prefix = "";
            switch (prefixCode) {
                case 0x01: prefix = "http://www."; break;
                case 0x02: prefix = "https://www."; break;
                case 0x03: prefix = "http://"; break;
                case 0x04: prefix = "https://"; break;
            }

            byte[] urlBytes = Arrays.copyOfRange(data, offset + 5, offset + 4 + payloadLen);
            return prefix + new String(urlBytes);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Factory reset callback
     */
    public interface ResetCallback {
        void onProgress(String message);
        void onError(String error);
        void onSuccess();
    }

    /**
     * Keys needed for factory reset
     */
    public static class TagKeys {
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
    }

    /**
     * Resets the tag to factory defaults (default keys)
     *
     * @param keys     Current tag keys (hex strings)
     * @param callback Reset callback
     */
    public void factoryReset(TagKeys keys, ResetCallback callback) {
        new Thread(() -> {
            try {
                factoryResetInternal(keys, callback);
            } catch (Exception e) {
                Log.e(TAG, "Factory reset failed", e);
                callback.onError(e.getMessage());
            }
        }).start();
    }

    private void factoryResetInternal(TagKeys keys, ResetCallback callback)
            throws Exception {

        callback.onProgress("Connecting to tag...");

        // Get version and select application
        Ntag424DnaCommands.VersionInfo version = commands.getVersion();
        if (!version.isNtag424Dna()) {
            throw new Exception("Not an NTAG 424 DNA tag");
        }

        commands.selectApplication();
        callback.onProgress("Tag identified: " + version.getUidHex());

        // Authenticate with current master key
        callback.onProgress("Authenticating...");
        byte[] currentMasterKey = AesUtils.hexToBytes(keys.appMasterKey);
        byte[] currentMetaReadKey = AesUtils.hexToBytes(keys.sdmMetaReadKey);
        byte[] currentFileReadKey = AesUtils.hexToBytes(keys.sdmFileReadKey);
        byte[] defaultKey = Ntag424DnaCommands.DEFAULT_KEY;

        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentMasterKey)) {
            throw new Exception("Authentication failed. Tag may have different keys.");
        }
        callback.onProgress("Authenticated");

        // Reset keys to default (order: other keys first, then master)
        callback.onProgress("Resetting SDM Meta Read key...");
        auth.changeKey(KEY_SDM_META_READ, currentMetaReadKey, defaultKey, (byte) 0x00);

        callback.onProgress("Resetting SDM File Read key...");
        auth.changeKey(KEY_SDM_FILE_READ, currentFileReadKey, defaultKey, (byte) 0x00);

        // Re-authenticate before changing file settings
        callback.onProgress("Re-authenticating...");
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentMasterKey)) {
            throw new Exception("Re-authentication failed");
        }

        // Reset NDEF file settings (disable SDM)
        callback.onProgress("Disabling SDM...");
        resetFileSettings();

        // Clear NDEF data
        callback.onProgress("Clearing NDEF...");
        clearNdef();

        // Change master key to default last
        callback.onProgress("Resetting master key...");
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentMasterKey)) {
            throw new Exception("Re-authentication for master key reset failed");
        }
        auth.changeKey(KEY_APP_MASTER, currentMasterKey, defaultKey, (byte) 0x00);

        callback.onProgress("Factory reset complete!");
        callback.onSuccess();
    }

    /**
     * Resets NDEF file settings to default (SDM disabled)
     */
    private void resetFileSettings() throws Exception {
        ByteArrayOutputStream settings = new ByteArrayOutputStream();

        // File option: SDM disabled, communication mode Plain
        settings.write(0x00);

        // Access rights: all free
        settings.write(0xE0); // Read: free
        settings.write(0xEE); // Write: free, R/W: free

        byte[] settingsData = settings.toByteArray();
        byte[] cmdData = new byte[1 + settingsData.length];
        cmdData[0] = Ntag424DnaCommands.FILE_NDEF;
        System.arraycopy(settingsData, 0, cmdData, 1, settingsData.length);

        auth.sendMacCommand(Ntag424DnaCommands.CMD_CHANGE_FILE_SETTINGS, cmdData);
        Log.d(TAG, "File settings reset");
    }

    /**
     * Clears NDEF data
     */
    private void clearNdef() throws Exception {
        // Write empty NDEF (just the length bytes)
        ByteArrayOutputStream cmdData = new ByteArrayOutputStream();
        cmdData.write(Ntag424DnaCommands.FILE_NDEF);

        // Offset (3 bytes LE)
        cmdData.write(0x00);
        cmdData.write(0x00);
        cmdData.write(0x00);

        // Length (3 bytes LE) - write 2 bytes of zero length
        cmdData.write(0x02);
        cmdData.write(0x00);
        cmdData.write(0x00);

        // Data: empty NDEF (length = 0)
        cmdData.write(0x00);
        cmdData.write(0x00);

        auth.sendMacCommand(Ntag424DnaCommands.CMD_WRITE_DATA, cmdData.toByteArray());
        Log.d(TAG, "NDEF cleared");
    }

    /**
     * Tag information
     */
    public static class TagInfo {
        public String uid;
        public String hardwareVersion;
        public String softwareVersion;
        public int storageSize;
        public String currentNdefUrl;
        public int keyVersion = -1;
        public boolean hasDefaultKeys = false;
    }

    /**
     * Programming configuration
     */
    public static class ProgrammingConfig {
        public byte[] currentKey;      // Current master key (null = default)
        public byte[] appMasterKey;    // New master key (null = generate random)
        public byte[] sdmMetaReadKey;  // New SDM meta read key
        public byte[] sdmFileReadKey;  // New SDM file read key
        public String baseUrl;         // Base URL for SDM
    }

    /**
     * Programming result
     */
    public static class ProgrammingResult {
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
        public String baseUrl;
    }
}
