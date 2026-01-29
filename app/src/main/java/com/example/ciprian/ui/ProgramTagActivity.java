package com.example.ciprian.ui;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
import android.util.Patterns;
import android.view.View;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.ciprian.CiprianApp;
import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ActivityProgramTagBinding;
import com.example.ciprian.nfc.Ntag424DnaProgrammer;

public class ProgramTagActivity extends AppCompatActivity {

    private ActivityProgramTagBinding binding;
    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFilters;
    private String[][] techLists;

    private Ntag424DnaProgrammer programmer;
    private Ntag424DnaProgrammer.TagInfo lastTagInfo;
    private String expectedUid; // UID of the tag we expect to program

    private boolean waitingForProgramScan = false;
    private boolean waitingForResetScan = false;
    private boolean isProgramming = false;
    private boolean isResetting = false;
    private Ntag424DnaProgrammer.ProgrammingConfig pendingConfig;
    private Ntag424DnaProgrammer.TagKeys pendingResetKeys;
    private String pendingTagName;
    private String pendingDescription;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivityProgramTagBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        setupToolbar();
        setupNfc();
        setupViews();
        loadDefaults();
    }

    private void setupToolbar() {
        binding.toolbar.setNavigationOnClickListener(v -> finish());
    }

    private void setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        pendingIntent = PendingIntent.getActivity(
                this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_MUTABLE
        );

        IntentFilter techFilter = new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED);
        intentFilters = new IntentFilter[]{techFilter};

        techLists = new String[][]{
                new String[]{IsoDep.class.getName()}
        };
    }

    private void setupViews() {
        binding.buttonProgram.setOnClickListener(v -> onProgramButtonClick());
        binding.buttonFactoryReset.setOnClickListener(v -> onFactoryResetButtonClick());
    }

    private void loadDefaults() {
        binding.editBaseUrl.setText(com.example.ciprian.Config.VERIFY_URL);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null) {
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, intentFilters, techLists);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null) {
            nfcAdapter.disableForegroundDispatch(this);
        }
        if (programmer != null) {
            programmer.disconnect();
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
            if (tag != null) {
                if (waitingForResetScan) {
                    handleResetScan(tag);
                } else if (waitingForProgramScan) {
                    handleProgramScan(tag);
                } else {
                    handleInfoScan(tag);
                }
            }
        }
    }

    /**
     * First scan - just read tag info
     */
    private void handleInfoScan(Tag tag) {
        if (isProgramming) return;

        binding.textScanStatus.setText(R.string.reading_tag);
        binding.cardTagInfo.setVisibility(View.GONE);
        binding.buttonProgram.setEnabled(false);

        new Thread(() -> {
            try {
                programmer = new Ntag424DnaProgrammer();
                programmer.connect(tag);
                lastTagInfo = programmer.readTagInfo();
                programmer.disconnect();

                runOnUiThread(() -> {
                    showTagInfo(lastTagInfo);
                    expectedUid = lastTagInfo.uid;
                    binding.textScanStatus.setText(R.string.tag_detected);
                    binding.buttonProgram.setEnabled(true);
                    // Enable reset button only if tag has custom keys
                    binding.buttonFactoryReset.setEnabled(!lastTagInfo.hasDefaultKeys);
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    binding.textScanStatus.setText(R.string.error_reading_tag);
                    Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    /**
     * Second scan - program the tag
     */
    private void handleProgramScan(Tag tag) {
        waitingForProgramScan = false;
        isProgramming = true;
        binding.textScanStatus.setText(R.string.programming);

        new Thread(() -> {
            try {
                programmer = new Ntag424DnaProgrammer();
                programmer.connect(tag);

                // Verify it's the same tag
                Ntag424DnaProgrammer.TagInfo info = programmer.readTagInfo();
                if (expectedUid != null && !expectedUid.equalsIgnoreCase(info.uid)) {
                    throw new Exception("Different tag! Expected " + expectedUid + " but got " + info.uid);
                }

                programmer.programTag(pendingConfig, new Ntag424DnaProgrammer.ProgressCallback() {
                    @Override
                    public void onProgress(String message, int progress) {
                        runOnUiThread(() -> {
                            binding.textScanStatus.setText(message);
                            binding.progressBar.setProgress(progress);
                        });
                    }

                    @Override
                    public void onError(String error) {
                        runOnUiThread(() -> {
                            isProgramming = false;
                            binding.buttonProgram.setEnabled(true);
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.programming_failed);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.error)
                                    .setMessage(error)
                                    .setPositiveButton(R.string.ok, null)
                                    .show();
                        });
                    }

                    @Override
                    public void onSuccess(Ntag424DnaProgrammer.ProgrammingResult result) {
                        registerTagWithBackend(result, pendingTagName, pendingDescription);
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> {
                    isProgramming = false;
                    binding.buttonProgram.setEnabled(true);
                    binding.progressBar.setVisibility(View.GONE);
                    binding.textScanStatus.setText(R.string.programming_failed);
                    Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }

    private void showTagInfo(Ntag424DnaProgrammer.TagInfo info) {
        binding.cardTagInfo.setVisibility(View.VISIBLE);
        binding.textTagUid.setText("UID: " + info.uid);
        binding.textTagVersion.setText("HW: " + info.hardwareVersion + " / SW: " + info.softwareVersion);

        String storageText = "Storage: " + info.storageSize + " bytes";
        if (info.keyVersion >= 0) {
            if (info.hasDefaultKeys) {
                storageText += " | Keys: DEFAULT (OK)";
            } else {
                storageText += " | Keys: CUSTOM (v" + info.keyVersion + ") - Cannot program!";
                // Disable program button if keys are not default
                binding.buttonProgram.setEnabled(false);
                Toast.makeText(this, "This tag has custom keys and cannot be programmed. Use a virgin tag.", Toast.LENGTH_LONG).show();
            }
        }
        binding.textTagStorage.setText(storageText);
    }

    private void onProgramButtonClick() {
        // Validate input
        String tagName = binding.editTagName.getText().toString().trim();
        String baseUrl = binding.editBaseUrl.getText().toString().trim();

        if (tagName.isEmpty() || baseUrl.isEmpty()) {
            Toast.makeText(this, R.string.please_fill_fields, Toast.LENGTH_SHORT).show();
            return;
        }

        if (!Patterns.WEB_URL.matcher(baseUrl).matches()) {
            Toast.makeText(this, R.string.invalid_url, Toast.LENGTH_SHORT).show();
            return;
        }

        if (lastTagInfo == null) {
            Toast.makeText(this, R.string.hold_tag_near_phone, Toast.LENGTH_SHORT).show();
            return;
        }

        // Store config for when tag is scanned
        pendingConfig = new Ntag424DnaProgrammer.ProgrammingConfig();
        pendingConfig.baseUrl = baseUrl;
        pendingTagName = tagName;
        pendingDescription = binding.editDescription.getText().toString().trim();

        // Show progress and wait for tag
        binding.buttonProgram.setEnabled(false);
        binding.progressBar.setVisibility(View.VISIBLE);
        binding.progressBar.setProgress(0);
        binding.textScanStatus.setText(R.string.hold_tag_near_phone);

        waitingForProgramScan = true;
    }

    private void registerTagWithBackend(Ntag424DnaProgrammer.ProgrammingResult result,
                                        String tagName, String description) {
        ApiClient.RegisterTagRequest request = new ApiClient.RegisterTagRequest();
        request.uid = result.uid;
        request.appMasterKey = result.appMasterKey;
        request.sdmMetaReadKey = result.sdmMetaReadKey;
        request.sdmFileReadKey = result.sdmFileReadKey;
        request.baseUrl = result.baseUrl;
        request.name = tagName;
        request.description = description;

        CiprianApp.getInstance().getApiClient().registerTag(request,
                new ApiClient.ApiCallback<ApiClient.RegisterTagResponse>() {
                    @Override
                    public void onSuccess(ApiClient.RegisterTagResponse response) {
                        runOnUiThread(() -> {
                            isProgramming = false;
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.programming_complete);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.success)
                                    .setMessage(R.string.programming_complete)
                                    .setPositiveButton(R.string.ok, (dialog, which) -> finish())
                                    .setCancelable(false)
                                    .show();
                        });
                    }

                    @Override
                    public void onError(String error) {
                        runOnUiThread(() -> {
                            isProgramming = false;
                            binding.buttonProgram.setEnabled(true);
                            binding.progressBar.setVisibility(View.GONE);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.success)
                                    .setMessage("Tag programmed but failed to register: " + error)
                                    .setPositiveButton(R.string.ok, (dialog, which) -> finish())
                                    .show();
                        });
                    }
                });
    }

    private void onFactoryResetButtonClick() {
        if (lastTagInfo == null) {
            Toast.makeText(this, "Please scan a tag first", Toast.LENGTH_SHORT).show();
            return;
        }

        if (lastTagInfo.hasDefaultKeys) {
            Toast.makeText(this, "Tag already has default keys", Toast.LENGTH_SHORT).show();
            return;
        }

        // Show dialog asking for master key
        showKeyInputDialog();
    }

    private void showKeyInputDialog() {
        final android.widget.EditText input = new android.widget.EditText(this);
        input.setHint("Enter Master Key (hex)");
        input.setInputType(android.text.InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);

        new AlertDialog.Builder(this)
                .setTitle("Factory Reset")
                .setMessage("Enter the current master key (32 hex characters):")
                .setView(input)
                .setPositiveButton("Reset", (dialog, which) -> {
                    String keyHex = input.getText().toString().trim();
                    if (keyHex.length() != 32) {
                        Toast.makeText(this, "Key must be 32 hex characters", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    startFactoryReset(keyHex);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void startFactoryReset(String masterKeyHex) {
        binding.buttonProgram.setEnabled(false);
        binding.buttonFactoryReset.setEnabled(false);
        binding.progressBar.setVisibility(View.VISIBLE);
        binding.progressBar.setProgress(0);
        binding.textScanStatus.setText(R.string.hold_tag_to_reset);

        // Store the key for when tag is scanned
        pendingResetKeys = new Ntag424DnaProgrammer.TagKeys();
        pendingResetKeys.appMasterKey = masterKeyHex;
        // SDM keys are default (we never change them)
        pendingResetKeys.sdmMetaReadKey = "00000000000000000000000000000000";
        pendingResetKeys.sdmFileReadKey = "00000000000000000000000000000000";

        // Wait for tag scan
        waitingForResetScan = true;
    }

    private void handleResetScan(Tag tag) {
        waitingForResetScan = false;
        isResetting = true;
        binding.textScanStatus.setText(R.string.resetting_tag);

        new Thread(() -> {
            try {
                programmer = new Ntag424DnaProgrammer();
                programmer.connect(tag);

                // Verify it's the same tag
                Ntag424DnaProgrammer.TagInfo info = programmer.readTagInfo();
                if (expectedUid != null && !expectedUid.equalsIgnoreCase(info.uid)) {
                    throw new Exception("Different tag! Expected " + expectedUid + " but got " + info.uid);
                }

                // Perform factory reset
                programmer.factoryReset(pendingResetKeys, new Ntag424DnaProgrammer.ResetCallback() {
                    @Override
                    public void onProgress(String message) {
                        runOnUiThread(() -> {
                            binding.textScanStatus.setText(message);
                        });
                    }

                    @Override
                    public void onError(String error) {
                        programmer.disconnect();
                        runOnUiThread(() -> {
                            isResetting = false;
                            binding.buttonProgram.setEnabled(true);
                            binding.buttonFactoryReset.setEnabled(true);
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.reset_failed);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.error)
                                    .setMessage(error)
                                    .setPositiveButton(R.string.ok, null)
                                    .show();
                        });
                    }

                    @Override
                    public void onSuccess() {
                        programmer.disconnect();
                        runOnUiThread(() -> {
                            isResetting = false;
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.reset_complete);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.success)
                                    .setMessage(R.string.reset_complete)
                                    .setPositiveButton(R.string.ok, (dialog, which) -> {
                                        // Refresh tag info
                                        lastTagInfo = null;
                                        expectedUid = null;
                                        binding.cardTagInfo.setVisibility(View.GONE);
                                        binding.buttonProgram.setEnabled(false);
                                        binding.buttonFactoryReset.setEnabled(false);
                                        binding.textScanStatus.setText(R.string.hold_tag_near_phone);
                                    })
                                    .setCancelable(false)
                                    .show();
                        });
                    }
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    isResetting = false;
                    binding.buttonProgram.setEnabled(true);
                    binding.buttonFactoryReset.setEnabled(true);
                    binding.progressBar.setVisibility(View.GONE);
                    binding.textScanStatus.setText(R.string.reset_failed);
                    Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
                });
            }
        }).start();
    }
}
