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
 * This is a cleaner implementation that leverages the well-tested library.
 */
public class Ntag424LibProgrammer {

    private static final String TAG = "NTAG424LibProgrammer";

    private IsoDep isoDep;
    private DnaCommunicator communicator;

    public interface ProgressCallback {
        void onProgress(String message, int progress);
        void onError(String error);
        void onSuccess(ProgrammingResult result);
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

        // Try to get UID (needs auth)
        try {
            if (AESEncryptionMode.authenticateEV2(communicator, 0, Ntag424.FACTORY_KEY)) {
                byte[] uid = GetCardUid.run(communicator);
                info.uid = bytesToHex(uid);
                Log.d(TAG, "UID: " + info.uid);
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not get UID: " + e.getMessage());
        }

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

        // Create SDM settings
        callback.onProgress("Configuring SDM...", 35);
        SDMSettings sdmSettings = new SDMSettings();
        
        // UID and Counter in plaintext, MAC for verification
        // sdmMetaReadPerm = ACCESS_EVERYONE means UID/Counter are NOT encrypted
        // sdmFileReadPerm is for MAC calculation
        sdmSettings.sdmMetaReadPerm = Permissions.ACCESS_EVERYONE;  // Plain UID/Counter
        sdmSettings.sdmFileReadPerm = Permissions.ACCESS_EVERYONE;  // Use default key for MAC
        sdmSettings.sdmReadCounterRetrievalPerm = Permissions.ACCESS_NONE;

        // Create NDEF template with UID, Counter, and MAC placeholders
        NdefTemplateMaster master = new NdefTemplateMaster();
        master.usesLRP = false;  // We're using AES, not LRP

        // Build URL with placeholders - library will calculate correct offsets
        // Format: baseUrl?uid=XXXXXX&ctr=XXXXXX&cmac=XXXXXXXX
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

        // Update with SDM settings
        ndefFileSettings.sdmSettings = sdmSettings;

        // Apply new file settings
        ChangeFileSettings.run(communicator, Ntag424.NDEF_FILE_NUMBER, ndefFileSettings);
        Log.d(TAG, "File settings updated with SDM");

        // Change master key (optional, for production use)
        byte[] newMasterKey;
        if (config.appMasterKey != null) {
            newMasterKey = config.appMasterKey;
        } else {
            // Generate random key
            newMasterKey = generateRandomKey();
        }

        callback.onProgress("Changing master key...", 85);
        ChangeKey.run(communicator, 0, currentKey, newMasterKey, (byte) 0x01);
        Log.d(TAG, "Master key changed");

        callback.onProgress("Programming complete!", 100);

        // Build result
        ProgrammingResult result = new ProgrammingResult();
        result.uid = uidHex;
        result.appMasterKey = bytesToHex(newMasterKey);
        result.sdmMetaReadKey = bytesToHex(Ntag424.FACTORY_KEY);
        result.sdmFileReadKey = bytesToHex(Ntag424.FACTORY_KEY);
        result.baseUrl = config.baseUrl;

        callback.onSuccess(result);
    }

    /**
     * Factory reset - restores default keys
     */
    public void factoryReset(byte[] currentMasterKey, ProgressCallback callback) {
        new Thread(() -> {
            try {
                callback.onProgress("Authenticating...", 20);
                if (!AESEncryptionMode.authenticateEV2(communicator, 0, currentMasterKey)) {
                    throw new Exception("Authentication failed");
                }

                callback.onProgress("Restoring default key...", 60);
                ChangeKey.run(communicator, 0, currentMasterKey, Ntag424.FACTORY_KEY, (byte) 0x00);

                callback.onProgress("Factory reset complete!", 100);

                ProgrammingResult result = new ProgrammingResult();
                result.appMasterKey = bytesToHex(Ntag424.FACTORY_KEY);
                callback.onSuccess(result);

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

    // Inner classes for compatibility

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
        public byte[] currentKey;       // Current key if already programmed
    }

    public static class ProgrammingResult {
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
        public String baseUrl;
    }
}
