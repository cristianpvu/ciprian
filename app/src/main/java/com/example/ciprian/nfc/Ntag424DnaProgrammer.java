package com.example.ciprian.nfc;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;

import net.bplearning.ntag424.DnaCommunicator;
import net.bplearning.ntag424.command.ChangeFileSettings;
import net.bplearning.ntag424.command.ChangeKey;
import net.bplearning.ntag424.command.FileSettings;
import net.bplearning.ntag424.command.GetCardUid;
import net.bplearning.ntag424.command.GetFileSettings;
import net.bplearning.ntag424.command.GetKeyVersion;
import net.bplearning.ntag424.command.IsoSelectFile;
import net.bplearning.ntag424.command.WriteData;
import net.bplearning.ntag424.constants.Ntag424;
import net.bplearning.ntag424.constants.Permissions;
import net.bplearning.ntag424.encryptionmode.AESEncryptionMode;
import net.bplearning.ntag424.sdm.NdefTemplateMaster;
import net.bplearning.ntag424.sdm.SDMSettings;

import java.security.SecureRandom;

/**
 * NTAG 424 DNA programmer using the johnnyb/ntag424-java library.
 * Handles SDM configuration for dynamic URL generation.
 */
public class Ntag424DnaProgrammer {

    private static final String TAG = "NTAG424Programmer";

    private IsoDep isoDep;
    private DnaCommunicator communicator;

    public interface ProgressCallback {
        void onProgress(String message, int progress);
        void onError(String error);
        void onSuccess(ProgrammingResult result);
    }

    public interface ResetCallback {
        void onProgress(String message);
        void onError(String error);
        void onSuccess();
    }

    /**
     * Connects to the tag
     */
    public void connect(Tag tag) throws Exception {
        isoDep = IsoDep.get(tag);
        if (isoDep == null) {
            throw new Exception("Tag does not support IsoDep");
        }

        isoDep.connect();
        isoDep.setTimeout(5000);

        // Create communicator and set transceiver
        communicator = new DnaCommunicator();
        communicator.setTransceiver((bytesToSend) -> {
            Log.d(TAG, ">>> " + bytesToHex(bytesToSend));
            byte[] response = isoDep.transceive(bytesToSend);
            Log.d(TAG, "<<< " + bytesToHex(response));
            return response;
        });

        // Select the NTAG 424 DNA application by DF name
        IsoSelectFile.run(communicator, IsoSelectFile.SELECT_MODE_NAME, Ntag424.DF_NAME);
        Log.d(TAG, "Application selected");
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
        TagInfo info = new TagInfo();

        // Get key version to check if using default keys
        int keyVersion = GetKeyVersion.run(communicator, 0);
        info.keyVersion = keyVersion;
        info.hasDefaultKeys = (keyVersion == 0);
        Log.d(TAG, "Key version: " + keyVersion + ", hasDefaultKeys: " + info.hasDefaultKeys);

        // Try to get UID (needs auth with factory key for virgin tags)
        try {
            if (AESEncryptionMode.authenticateEV2(communicator, 0, Ntag424.FACTORY_KEY)) {
                byte[] uid = GetCardUid.run(communicator);
                info.uid = bytesToHex(uid);
                Log.d(TAG, "UID: " + info.uid);
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not get UID with default key: " + e.getMessage());
            info.uid = "UNKNOWN";
        }

        // Fill in other info
        info.hardwareVersion = "4.0";
        info.softwareVersion = "4.0";
        info.storageSize = 256;

        return info;
    }

    /**
     * Programs the tag with SDM configuration
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

        callback.onProgress("Reading tag info...", 5);

        // Check key version
        int keyVersion = GetKeyVersion.run(communicator, 0);
        boolean hasDefaultKeys = (keyVersion == 0);
        Log.d(TAG, "Key version: " + keyVersion + ", hasDefaultKeys: " + hasDefaultKeys);

        byte[] currentKey = config.currentKey != null ? config.currentKey : Ntag424.FACTORY_KEY;

        if (!hasDefaultKeys && config.currentKey == null) {
            throw new Exception("Tag has custom keys. Please provide the current key.");
        }

        // Authenticate
        callback.onProgress("Authenticating...", 15);
        if (!AESEncryptionMode.authenticateEV2(communicator, 0, currentKey)) {
            throw new Exception("Authentication failed. Wrong key?");
        }
        Log.d(TAG, "Authentication successful");

        // Get card UID
        byte[] uid = GetCardUid.run(communicator);
        String uidHex = bytesToHex(uid);
        Log.d(TAG, "Card UID: " + uidHex);
        callback.onProgress("UID: " + uidHex, 25);

        // Create SDM settings - EXACTLY like the official example
        callback.onProgress("Configuring SDM...", 35);
        SDMSettings sdmSettings = new SDMSettings();
        
        // EXACTLY like official example:
        // sdmMetaReadPerm = KEY2 for encrypted PICC data
        // sdmFileReadPerm = KEY3 for MAC and file encryption
        sdmSettings.sdmMetaReadPerm = Permissions.ACCESS_KEY2;  // Encrypted PICC data with Key2
        sdmSettings.sdmFileReadPerm = Permissions.ACCESS_KEY3;  // MAC with Key3
        sdmSettings.sdmOptionUid = true;
        sdmSettings.sdmOptionReadCounter = true;

        // Create NDEF template - use the user's configured URL
        NdefTemplateMaster master = new NdefTemplateMaster();
        master.usesLRP = false;  // We're using AES, not LRP

        // Use the configured base URL with SDM placeholders
        // Format: baseUrl?uid={UID}&ctr={COUNTER}&cmac={MAC}
        String urlTemplate = config.baseUrl + "?uid={UID}&ctr={COUNTER}&cmac={MAC}";
        Log.d(TAG, "URL Template: " + urlTemplate);

        // Generate NDEF record - this also updates sdmSettings with correct offsets
        byte[] ndefRecord = master.generateNdefTemplateFromUrlString(urlTemplate, sdmSettings);
        Log.d(TAG, "NDEF Record (" + ndefRecord.length + " bytes): " + bytesToHex(ndefRecord));

        // Write NDEF data
        callback.onProgress("Writing NDEF...", 50);
        WriteData.run(communicator, Ntag424.NDEF_FILE_NUMBER, ndefRecord);
        Log.d(TAG, "NDEF written successfully");

        // Get current file settings
        callback.onProgress("Updating file settings...", 65);
        FileSettings ndefFileSettings = GetFileSettings.run(communicator, Ntag424.NDEF_FILE_NUMBER);
        Log.d(TAG, "Current file settings retrieved");
        Log.d(TAG, "Before SDM - readPerm: " + ndefFileSettings.readPerm + 
                   ", writePerm: " + ndefFileSettings.writePerm +
                   ", readWritePerm: " + ndefFileSettings.readWritePerm +
                   ", changePerm: " + ndefFileSettings.changePerm +
                   ", commMode: " + ndefFileSettings.commMode);

        // DON'T change the access permissions - keep them as they are!
        // Only apply the SDM settings
        ndefFileSettings.sdmSettings = sdmSettings;
        
        Log.d(TAG, "After SDM - readPerm: " + ndefFileSettings.readPerm + 
                   ", writePerm: " + ndefFileSettings.writePerm +
                   ", readWritePerm: " + ndefFileSettings.readWritePerm +
                   ", changePerm: " + ndefFileSettings.changePerm);
        Log.d(TAG, "SDM settings - sdmEnabled: " + sdmSettings.sdmEnabled +
                   ", sdmMetaReadPerm: " + sdmSettings.sdmMetaReadPerm + 
                   ", sdmFileReadPerm: " + sdmSettings.sdmFileReadPerm);
        Log.d(TAG, "SDM options - sdmOptionUid: " + sdmSettings.sdmOptionUid +
                   ", sdmOptionReadCounter: " + sdmSettings.sdmOptionReadCounter +
                   ", sdmOptionUseAscii: " + sdmSettings.sdmOptionUseAscii);
        Log.d(TAG, "SDM offsets - uidOffset: " + sdmSettings.sdmUidOffset + 
                   ", counterOffset: " + sdmSettings.sdmReadCounterOffset +
                   ", piccDataOffset: " + sdmSettings.sdmPiccDataOffset +
                   ", macInputOffset: " + sdmSettings.sdmMacInputOffset +
                   ", macOffset: " + sdmSettings.sdmMacOffset);

        // Apply new file settings
        ChangeFileSettings.run(communicator, Ntag424.NDEF_FILE_NUMBER, ndefFileSettings);
        Log.d(TAG, "File settings updated with SDM");

        // Check if Key3 is already changed (key version != 0)
        int key3Version = GetKeyVersion.run(communicator, 3);
        Log.d(TAG, "Key3 version: " + key3Version);

        byte[] newMacKey;
        if (key3Version == 0) {
            // Key3 is still factory key - we can change it
            if (config.sdmFileReadKey != null) {
                newMacKey = config.sdmFileReadKey;
            } else {
                newMacKey = generateRandomKey();
            }

            callback.onProgress("Changing MAC key (Key3)...", 75);
            ChangeKey.run(communicator, 3, Ntag424.FACTORY_KEY, newMacKey, (byte) 0x01);
            Log.d(TAG, "MAC key (Key3) changed to: " + bytesToHex(newMacKey));
        } else {
            // Key3 already changed - skip and use existing (must be provided in config)
            Log.d(TAG, "Key3 already changed (version=" + key3Version + "), keeping existing");
            if (config.sdmFileReadKey != null) {
                newMacKey = config.sdmFileReadKey;
            } else {
                // Can't generate new - we don't know the old key!
                throw new Exception("Key3 already changed but no sdmFileReadKey provided in config");
            }
        }

        // Check if Key0 is already changed
        int key0Version = GetKeyVersion.run(communicator, 0);
        Log.d(TAG, "Key0 version: " + key0Version);

        byte[] newMasterKey;
        if (key0Version == 0 || hasDefaultKeys) {
            // Key0 is factory or we have the current key
            if (config.appMasterKey != null) {
                newMasterKey = config.appMasterKey;
            } else {
                newMasterKey = generateRandomKey();
            }

            callback.onProgress("Changing master key (Key0)...", 90);
            ChangeKey.run(communicator, 0, currentKey, newMasterKey, (byte) 0x01);
            Log.d(TAG, "Master key (Key0) changed");
        } else {
            Log.d(TAG, "Key0 already changed (version=" + key0Version + "), keeping existing");
            newMasterKey = currentKey;
        }

        callback.onProgress("Programming complete!", 100);;

        // Build result - IMPORTANT: save these keys!
        ProgrammingResult result = new ProgrammingResult();
        result.uid = uidHex;
        result.appMasterKey = bytesToHex(newMasterKey);
        result.sdmMetaReadKey = bytesToHex(Ntag424.FACTORY_KEY);  // Not used in plaintext mode
        result.sdmFileReadKey = bytesToHex(newMacKey);  // THIS IS THE SECRET!
        result.baseUrl = config.baseUrl;

        callback.onSuccess(result);
    }

    /**
     * Factory reset - restores ALL keys to default
     */
    public void factoryReset(TagKeys keys, ResetCallback callback) {
        new Thread(() -> {
            try {
                byte[] masterKey = hexToBytes(keys.appMasterKey);
                byte[] macKey = keys.sdmFileReadKey != null ? 
                    hexToBytes(keys.sdmFileReadKey) : Ntag424.FACTORY_KEY;

                callback.onProgress("Authenticating...");
                if (!AESEncryptionMode.authenticateEV2(communicator, 0, masterKey)) {
                    throw new Exception("Authentication failed. Wrong key?");
                }

                // Reset Key3 (MAC key) first - while we're still authenticated with Key0
                callback.onProgress("Restoring Key3 (MAC key)...");
                int key3Version = GetKeyVersion.run(communicator, 3);
                if (key3Version != 0) {
                    // Key3 was changed, reset it
                    ChangeKey.run(communicator, 3, macKey, Ntag424.FACTORY_KEY, (byte) 0x00);
                    Log.d(TAG, "Key3 reset to factory");
                } else {
                    Log.d(TAG, "Key3 already factory");
                }

                // Reset Key0 (master key) last
                callback.onProgress("Restoring Key0 (master key)...");
                ChangeKey.run(communicator, 0, masterKey, Ntag424.FACTORY_KEY, (byte) 0x00);
                Log.d(TAG, "Key0 reset to factory");

                callback.onProgress("Factory reset complete!");
                callback.onSuccess();

            } catch (Exception e) {
                Log.e(TAG, "Factory reset failed", e);
                callback.onError(e.getMessage());
            }
        }).start();
    }

    // Utility methods

    private byte[] generateRandomKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private String bytesToHex(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // Inner classes for compatibility with existing Activity

    public static class TagInfo {
        public String uid;
        public String hardwareVersion;
        public String softwareVersion;
        public int storageSize;
        public int keyVersion;
        public boolean hasDefaultKeys;
        public String currentNdefUrl;
    }

    public static class ProgrammingConfig {
        public String baseUrl;          // Base URL for SDM
        public byte[] appMasterKey;     // New master key (or null for random)
        public byte[] sdmFileReadKey;   // New MAC key (Key3) - or null for random
        public byte[] currentKey;       // Current key if already programmed
    }

    public static class ProgrammingResult {
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
        public String baseUrl;
    }

    public static class TagKeys {
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
    }
}
