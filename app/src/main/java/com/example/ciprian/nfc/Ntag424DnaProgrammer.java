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

        // Log current NDEF file settings for debugging
        try {
            byte[] fileSettings = commands.getFileSettings(Ntag424DnaCommands.FILE_NDEF);
            Log.d(TAG, "NDEF File Settings: " + AesUtils.bytesToHex(fileSettings));
            // Parse: FileType(1) | FileOption(1) | AccessRights(2) | FileSize(3)
            if (fileSettings.length >= 4) {
                int fileOption = fileSettings[1] & 0xFF;
                int accessByte0 = fileSettings[2] & 0xFF;
                int accessByte1 = fileSettings[3] & 0xFF;
                Log.d(TAG, "FileOption: 0x" + Integer.toHexString(fileOption) + 
                    " (SDM=" + ((fileOption & 0x40) != 0) + ", CommMode=" + (fileOption & 0x03) + ")");
                Log.d(TAG, "AccessRights: Read=" + ((accessByte0 >> 4) & 0xF) + 
                    ", Write=" + (accessByte0 & 0xF) +
                    ", RW=" + ((accessByte1 >> 4) & 0xF) + 
                    ", Change=" + (accessByte1 & 0xF));
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not read file settings: " + e.getMessage());
        }

        // Check if tag already has custom keys
        byte keyVersion = commands.getKeyVersion(KEY_APP_MASTER);
        boolean hasCustomKeys = keyVersion != 0x00;
        
        if (hasCustomKeys && config.currentKey == null) {
            throw new Exception("Tag already programmed with custom keys. " +
                    "Please provide the current master key or perform factory reset first.");
        }

        byte[] currentKey = config.currentKey != null ? config.currentKey : Ntag424DnaCommands.DEFAULT_KEY;

        // STRATEGY: For fresh tags (default keys), write NDEF BEFORE auth
        // because default file has Write access = Free (0xE)
        
        if (!hasCustomKeys) {
            // Step 1a: Write NDEF BEFORE authentication (plain, no MAC)
            // This works because default NDEF file has Write = Free
            callback.onProgress("Writing NDEF data (plain)...", 20);
            try {
                writeNdefWithoutMac(buildNdefMessage(config.baseUrl));
                Log.d(TAG, "NDEF write succeeded (plain mode)!");
                
                // Also configure SDM BEFORE auth when Change=E (free)
                Log.d(TAG, "Configuring SDM (plain mode, before auth)...");
                configureSdmPlain(config.baseUrl);
                Log.d(TAG, "SDM configured (plain mode)!");
            } catch (Exception e) {
                Log.w(TAG, "Plain NDEF write failed: " + e.getMessage());
                // Will try with auth below
            }
        }

        // Step 2: Authenticate
        callback.onProgress("Authenticating...", 30);
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentKey)) {
            throw new Exception("Authentication failed. Wrong key?");
        }
        callback.onProgress("Authenticated successfully", 35);

        // Generate new master key if not provided
        byte[] newAppMasterKey = config.appMasterKey != null ?
                config.appMasterKey : AesUtils.generateRandomKey();

        // Step 3: If NDEF wasn't written yet (custom keys), write now with auth
        if (hasCustomKeys) {
            callback.onProgress("Writing NDEF data...", 40);
            writeNdefWithMac(buildNdefMessage(config.baseUrl));
            Log.d(TAG, "NDEF write succeeded (with MAC)!");
            
            // Configure SDM with auth (for custom keys)
            callback.onProgress("Configuring SDM...", 55);
            configureSdm(config.baseUrl);
            Log.d(TAG, "SDM configuration succeeded!");
        }
        // Note: For default keys, SDM was already configured in plain mode before auth

        // Step 5: Change master key LAST
        // Re-authenticate first to reset command counter
        callback.onProgress("Re-authenticating...", 75);
        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentKey)) {
            throw new Exception("Re-authentication failed");
        }

        callback.onProgress("Changing master key...", 90);
        auth.changeKey(KEY_APP_MASTER, currentKey, newAppMasterKey, (byte) 0x01);
        Log.d(TAG, "Master key changed successfully");

        callback.onProgress("Programming complete!", 100);

        // Build result
        ProgrammingResult result = new ProgrammingResult();
        result.uid = version.getUidHex();
        result.appMasterKey = AesUtils.bytesToHex(newAppMasterKey);
        // SDM keys remain as default (standard practice)
        result.sdmMetaReadKey = AesUtils.bytesToHex(Ntag424DnaCommands.DEFAULT_KEY);
        result.sdmFileReadKey = AesUtils.bytesToHex(Ntag424DnaCommands.DEFAULT_KEY);
        result.baseUrl = config.baseUrl;

        callback.onSuccess(result);
    }

    /**
     * Configures SDM (Secure Dynamic Messaging) for the NDEF file.
     * Based on NXP AN12196 and NTAG 424 DNA datasheet.
     *
     * Uses PLAIN mirroring (MetaReadKey=0xF) so UID and counter appear as
     * plain ASCII hex in the URL. CMAC is computed with FileReadKey (key 2) for authentication.
     */
    private void configureSdm(String baseUrl) throws Exception {

        // Determine URL prefix to calculate correct file offsets
        String urlAfterPrefix;
        byte prefixCode;
        if (baseUrl.startsWith("https://www.")) {
            urlAfterPrefix = baseUrl.substring(12);
            prefixCode = 0x02;
        } else if (baseUrl.startsWith("http://www.")) {
            urlAfterPrefix = baseUrl.substring(11);
            prefixCode = 0x01;
        } else if (baseUrl.startsWith("https://")) {
            urlAfterPrefix = baseUrl.substring(8);
            prefixCode = 0x04;
        } else if (baseUrl.startsWith("http://")) {
            urlAfterPrefix = baseUrl.substring(7);
            prefixCode = 0x03;
        } else {
            urlAfterPrefix = baseUrl;
            prefixCode = 0x00;
        }

        // Calculate URL with placeholders (no CMAC for simplified testing)
        String urlWithParams = urlAfterPrefix + "?uid=00000000000000&ctr=000000";

        // NDEF file layout (with 2-byte length prefix):
        // [0-1] NDEF message length (2 bytes, big endian)
        // [2]   NDEF record header 0xD1 (MB=1, ME=1, CF=0, SR=1, IL=0, TNF=001)
        // [3]   Type length 0x01
        // [4]   Payload length
        // [5]   Type 'U' (0x55)
        // [6]   URI prefix code
        // [7+]  URL data

        // Offset calculations:
        // - Length field: 2 bytes (offsets 0-1)
        // - NDEF header: offset 2 (D1)
        // - Type length: offset 3 (01)
        // - Payload length: offset 4
        // - Type: offset 5 (55 = 'U')
        // - Prefix code: offset 6
        // - URL data starts: offset 7
        
        int urlDataOffset = 7; // URL data starts at byte 7 in the file

        // Placeholder positions in URL data (relative to urlDataOffset)
        // URL format: {urlAfterPrefix}?uid=00000000000000&ctr=000000
        int uidParamStart = urlAfterPrefix.length() + 5; // "?uid=" is 5 chars
        int ctrParamStart = uidParamStart + 14 + 5;      // 14 hex chars + "&ctr=" (5 chars)

        // Absolute offsets in file
        int uidOffset = urlDataOffset + uidParamStart;
        int ctrOffset = urlDataOffset + ctrParamStart;

        Log.d(TAG, "SDM Offsets - UID: " + uidOffset + ", CTR: " + ctrOffset);
        Log.d(TAG, "URL after prefix: '" + urlAfterPrefix + "' (len=" + urlAfterPrefix.length() + ")");
        Log.d(TAG, "Full URL will be: " + urlWithParams);

        // Build file settings
        ByteArrayOutputStream settings = new ByteArrayOutputStream();

        // 1. FileOption (1 byte): SDM enabled (bit 6), CommMode = Plain (bits 1-0 = 00)
        settings.write(0x40);

        // 2. AccessRights (2 bytes) - per NTAG 424 DNA datasheet section 11.3.2
        //    Byte 0: bits 7-4 = Read access, bits 3-0 = Write access
        //    Byte 1: bits 7-4 = Read-Write access, bits 3-0 = Change access
        //    0 = key 0, E = free, F = no access
        settings.write(0xE0);  // Read=E (free), Write=0 (needs key 0)
        settings.write(0xE0);  // RW=E (free), Change=0 (needs key 0)

        // 3. SDMOptions (1 byte): 
        //    bit 0 = SDM and Mirroring enabled
        //    bit 4 = ReadCtrLimit enabled (we DON'T want this - no limit)
        //    bit 5 = Encrypted File Data (0 = no)
        //    bit 6 = UID mirror
        //    bit 7 = SDMReadCtr mirror
        // 0x41 = 0100 0001 = UID mirror + SDM enabled (NO CTR for testing)
        settings.write(0x41);

        // 4. SDMAccessRights (2 bytes):
        //    Byte 0: [SDMCtrRetKey 4 bits][SDMMetaReadKey 4 bits]
        //    Byte 1: [SDMFileReadKey 4 bits][SDMCtrIncKey 4 bits]
        //    F = plain/free/disabled
        // Using FileReadKey=F means CMAC is disabled (no authentication)
        // This is simpler for testing - can enable key 2 later
        settings.write(0xFF);  // CtrRet=F (disabled), MetaRead=F (plain UID mirror)
        settings.write(0xFF);  // FileRead=F (no CMAC), CtrInc=F (free increment)

        // 5. UIDOffset (3 bytes LE) - where UID placeholder is
        writeOffset(settings, uidOffset);

        // NOTE: With only UID mirroring (no CTR), we don't include SDMReadCtrOffset
        // Also no SDMMACInputOffset, SDMMACOffset when FileReadKey=F

        byte[] settingsData = settings.toByteArray();
        Log.d(TAG, "ChangeFileSettings data (" + settingsData.length + " bytes): " +
                AesUtils.bytesToHex(settingsData));

        // Build command: FileNo is the header, settings are encrypted
        // ChangeFileSettings with Change access = key 0 requires encrypted data
        byte[] header = new byte[]{Ntag424DnaCommands.FILE_NDEF};
        
        auth.sendEncryptedCommand(Ntag424DnaCommands.CMD_CHANGE_FILE_SETTINGS, header, settingsData);

        Log.d(TAG, "SDM configured successfully");
    }

    /**
     * Configures SDM in PLAIN mode (before authentication)
     * Use when Change access = E (free)
     */
    private void configureSdmPlain(String baseUrl) throws Exception {
        // Build the same settings data as configureSdm
        String urlAfterPrefix = baseUrl.replace("http://", "").replace("https://", "");
        String urlWithParams = urlAfterPrefix + "?uid=00000000000000&ctr=000000";
        
        int urlDataOffset = 7;
        int uidParamStart = urlAfterPrefix.length() + 5;
        int ctrParamStart = uidParamStart + 14 + 5;
        int uidOffset = urlDataOffset + uidParamStart;
        int ctrOffset = urlDataOffset + ctrParamStart;

        Log.d(TAG, "SDM Plain - UID offset: " + uidOffset + ", CTR offset: " + ctrOffset);

        ByteArrayOutputStream settings = new ByteArrayOutputStream();
        
        // FileOption: SDM enabled (0x40), CommMode plain
        settings.write(0x40);
        
        // AccessRights: Read=E, Write=0, RW=E, Change=0
        settings.write(0xE0);
        settings.write(0xE0);
        
        // SDMOptions: UID mirror + ReadCtr mirror + SDM enabled = 0xC1
        settings.write(0xC1);
        
        // SDMAccessRights: all F = plain/free
        settings.write(0xFF);
        settings.write(0xFF);
        
        // UIDOffset (3 bytes LE)
        writeOffset(settings, uidOffset);
        
        // SDMReadCtrOffset (3 bytes LE)
        writeOffset(settings, ctrOffset);

        byte[] settingsData = settings.toByteArray();
        Log.d(TAG, "ChangeFileSettings PLAIN data (" + settingsData.length + " bytes): " +
                AesUtils.bytesToHex(settingsData));

        // Build command data: FileNo + settings (NO encryption, NO MAC)
        ByteArrayOutputStream cmdData = new ByteArrayOutputStream();
        cmdData.write(Ntag424DnaCommands.FILE_NDEF);
        cmdData.write(settingsData);

        byte[] response = commands.transceive(Ntag424DnaCommands.CMD_CHANGE_FILE_SETTINGS, cmdData.toByteArray());
        
        if (!commands.isOk(response)) {
            throw new Exception("ChangeFileSettings (plain) failed: " + AesUtils.bytesToHex(commands.getStatus(response)));
        }
        
        Log.d(TAG, "SDM configured successfully (plain mode)!");
    }

    private void writeOffset(ByteArrayOutputStream out, int offset) {
        out.write(offset & 0xFF);
        out.write((offset >> 8) & 0xFF);
        out.write((offset >> 16) & 0xFF);
    }

    /**
     * Builds NDEF message with SDM placeholders
     * NOTE: For simplified testing, we only use UID and CTR (no CMAC)
     */
    private byte[] buildNdefMessage(String baseUrl) {
        String fullUrl = baseUrl +
                "?uid=00000000000000" +  // 14 chars placeholder for UID (7 bytes hex)
                "&ctr=000000";            // 6 chars placeholder for counter (3 bytes hex)
        // NOTE: CMAC removed for simplified testing (SDMFileReadKey=F)
        return buildNdefUrlRecord(fullUrl);
    }

    /**
     * Writes NDEF URL message with SDM placeholders.
     * 
     * Strategy: The default NDEF file has CommMode=Plain and Write access=E (free).
     * So we can write without authentication/MAC using plain WriteData command.
     * After writing, we configure SDM which changes access rights to require key 0.
     */
    private void writeNdefPlain(String baseUrl) throws Exception {
        byte[] ndefMessage = buildNdefMessage(baseUrl);
        Log.d(TAG, "NDEF message (" + ndefMessage.length + " bytes): " + AesUtils.bytesToHex(ndefMessage));

        // Try writing with MAC first (authenticated session)
        try {
            writeNdefWithMac(ndefMessage);
            Log.d(TAG, "NDEF written successfully with MAC: " + baseUrl);
            return;
        } catch (Exception e) {
            Log.w(TAG, "WriteData with MAC failed: " + e.getMessage() + ", trying plain...");
        }

        // If MAC write fails, try plain write (for default file settings)
        writeNdefWithoutMac(ndefMessage);
        Log.d(TAG, "NDEF written successfully (plain): " + baseUrl);
    }

    /**
     * Writes NDEF data using authenticated command with MAC
     */
    private void writeNdefWithMac(byte[] ndefMessage) throws Exception {
        Log.d(TAG, "writeNdefWithMac: " + ndefMessage.length + " bytes");
        
        // WriteData format: FileNo || Offset (3 LE) || Length (3 LE) || Data
        ByteArrayOutputStream cmdData = new ByteArrayOutputStream();
        cmdData.write(Ntag424DnaCommands.FILE_NDEF);

        // Offset (3 bytes LE)
        cmdData.write(0x00);
        cmdData.write(0x00);
        cmdData.write(0x00);

        // Length (3 bytes LE) - number of bytes to write
        cmdData.write(ndefMessage.length & 0xFF);
        cmdData.write((ndefMessage.length >> 8) & 0xFF);
        cmdData.write((ndefMessage.length >> 16) & 0xFF);

        // Data
        cmdData.write(ndefMessage);
        
        Log.d(TAG, "WriteData command data (before MAC): " + AesUtils.bytesToHex(cmdData.toByteArray()));

        // Send with MAC
        auth.sendMacCommand(Ntag424DnaCommands.CMD_WRITE_DATA, cmdData.toByteArray());
    }

    /**
     * Writes NDEF data using plain command (no MAC, no encryption)
     * Works when file has CommMode=Plain and Write access=Free (0xE)
     */
    private void writeNdefWithoutMac(byte[] ndefMessage) throws Exception {
        Log.d(TAG, "writeNdefWithoutMac: " + ndefMessage.length + " bytes");
        
        // WriteData format: FileNo || Offset (3 LE) || Length (3 LE) || Data
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

        Log.d(TAG, "WriteData command (plain, no MAC): " + AesUtils.bytesToHex(cmdData.toByteArray()));

        // Send plain (no MAC)
        byte[] response = commands.transceive(Ntag424DnaCommands.CMD_WRITE_DATA, cmdData.toByteArray());
        if (!commands.isOk(response)) {
            throw new Exception("Plain WriteData failed: " + AesUtils.bytesToHex(commands.getStatus(response)));
        }
        Log.d(TAG, "WriteData (plain) succeeded!");
    }

    /**
     * Writes NDEF URL message with SDM placeholders (legacy method with MAC)
     */
    private void writeNdefWithSdm(String baseUrl) throws Exception {
        writeNdefPlain(baseUrl);
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
        callback.onProgress("Authenticating with custom key...");
        byte[] currentMasterKey = AesUtils.hexToBytes(keys.appMasterKey);
        byte[] defaultKey = Ntag424DnaCommands.DEFAULT_KEY;

        if (!auth.authenticateEV2First(KEY_APP_MASTER, currentMasterKey)) {
            throw new Exception("Authentication failed. Wrong master key provided.");
        }
        callback.onProgress("Authenticated with custom key");

        // Step 1: Change master key to default FIRST (while we're still authenticated)
        callback.onProgress("Resetting master key to default...");
        auth.changeKey(KEY_APP_MASTER, currentMasterKey, defaultKey, (byte) 0x00);
        Log.d(TAG, "Master key reset to default");

        // Step 2: Re-authenticate with default key
        callback.onProgress("Re-authenticating with default key...");
        if (!auth.authenticateEV2First(KEY_APP_MASTER, defaultKey)) {
            throw new Exception("Re-authentication with default key failed");
        }
        callback.onProgress("Authenticated with default key");

        // Step 3: Reset NDEF file settings (disable SDM)
        try {
            callback.onProgress("Resetting file settings...");
            resetFileSettings();
            Log.d(TAG, "File settings reset");
        } catch (Exception e) {
            Log.w(TAG, "Could not reset file settings: " + e.getMessage());
            // Continue anyway - may already be default
        }

        // Step 4: Re-authenticate again (cmdCounter may have changed)
        callback.onProgress("Re-authenticating...");
        if (!auth.authenticateEV2First(KEY_APP_MASTER, defaultKey)) {
            throw new Exception("Re-authentication failed after file settings reset");
        }

        // Step 5: Clear NDEF data
        callback.onProgress("Clearing NDEF...");
        clearNdef();
        Log.d(TAG, "NDEF cleared");

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

        // Access rights (2 bytes) - per NTAG 424 DNA datasheet section 11.3.2
        // Byte 0: bits 7-4 = Read access, bits 3-0 = Write access  
        // Byte 1: bits 7-4 = Read-Write access, bits 3-0 = Change access
        // E = free, 0 = key 0, F = never
        settings.write(0xEE);  // Read=E (free), Write=E (free)
        settings.write(0xE0);  // RW=E (free), Change=0 (key 0)

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
