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
    private String reservedTagId; // id-ul rezervarii din backend (reserve-first)

    // Masa pentru care se scrie cipul (venita din TablesActivity). Daca e setata,
    // cipul se leaga automat de masa imediat dupa scrierea reusita.
    private int boundTableId = -1;
    private String boundTableLabel;

    // Key2 (SDM meta read) propusa de telefon. Backend-ul o inlocuieste cu Key2
    // comuna a mediului (link criptat); daca nu e configurata ramane factory (plaintext).
    private static final String FACTORY_KEY_HEX = "00000000000000000000000000000000";

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

    /**
     * Leaga cipul proaspat scris de masa aleasa. Cipul e deja programat si salvat
     * in DB (reserve-first), deci daca bind-ul pica nu se pierde nimic: se poate
     * reincerca din detaliile tagului ("Assign to table").
     */
    private void bindToTable() {
        binding.progressBar.setVisibility(View.VISIBLE);
        binding.textScanStatus.setText(R.string.binding);

        CiprianApp.getInstance().getApiClient().bindTagToTable(boundTableId, expectedUid,
                new ApiClient.ApiCallback<ApiClient.BindTagResponse>() {
                    @Override public void onSuccess(ApiClient.BindTagResponse resp) {
                        runOnUiThread(() -> {
                            binding.progressBar.setVisibility(View.GONE);
                            showProgrammingDone(getString(R.string.programmed_and_bound,
                                    boundTableLabel != null ? boundTableLabel : ""));
                        });
                    }
                    @Override public void onError(String error) {
                        runOnUiThread(() -> {
                            binding.progressBar.setVisibility(View.GONE);
                            showProgrammingDone(getString(R.string.programmed_bind_failed, error));
                        });
                    }
                });
    }

    private void showProgrammingDone(String message) {
        new AlertDialog.Builder(ProgramTagActivity.this)
                .setTitle(R.string.success)
                .setMessage(message)
                .setPositiveButton(R.string.ok, (dialog, which) -> finish())
                .setCancelable(false)
                .show();
    }

    private void loadDefaults() {
        binding.editBaseUrl.setText(com.example.ciprian.Config.MENU_BASE_URL);

        // Venit din lista de mese: precompletam numele si retinem masa pentru bind.
        boundTableId = getIntent().getIntExtra("table_id", -1);
        boundTableLabel = getIntent().getStringExtra("table_label");
        if (boundTableId > 0) {
            String restaurantName = getIntent().getStringExtra("restaurant_name");
            if (boundTableLabel != null) binding.editTagName.setText(boundTableLabel);
            if (restaurantName != null) binding.editDescription.setText(restaurantName);
            binding.toolbar.setSubtitle(restaurantName != null
                    ? getString(R.string.programming_for, boundTableLabel, restaurantName)
                    : boundTableLabel);
        }
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

                            // Cheile sunt deja salvate in backend (reserve-first),
                            // deci nimic nu e pierdut. Se poate reincerca pe acelasi cip.
                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.error)
                                    .setMessage(getString(R.string.chip_write_failed_safe, error))
                                    .setPositiveButton(R.string.ok, null)
                                    .show();
                        });
                    }

                    @Override
                    public void onSuccess(Ntag424DnaProgrammer.ProgrammingResult result) {
                        // Cheile au fost deja salvate in DB inainte de programare,
                        // deci nu mai e nevoie de niciun apel la backend aici.
                        runOnUiThread(() -> {
                            isProgramming = false;
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.programming_complete);

                            // Cip scris pentru o masa anume -> il legam automat de ea.
                            if (boundTableId > 0) {
                                bindToTable();
                            } else {
                                showProgrammingDone(getString(R.string.programming_complete));
                            }
                        });
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

        // RESERVE-FIRST: generam cheile si le salvam in backend ÎNAINTE de a
        // atinge cipul. Programam cipul DOAR cu cheile intoarse de backend
        // (pe retry pot fi cele deja salvate). Asa nu se scrie niciodata pe cip
        // o cheie pe care baza de date n-o are deja -> cipul nu poate fi pierdut.
        binding.buttonProgram.setEnabled(false);
        binding.progressBar.setVisibility(View.VISIBLE);
        binding.progressBar.setProgress(0);
        binding.textScanStatus.setText(R.string.checking_backend);

        ApiClient.ReserveTagRequest reserveReq = new ApiClient.ReserveTagRequest();
        reserveReq.uid = expectedUid;                         // UID citit la prima scanare
        reserveReq.name = tagName;
        reserveReq.description = pendingDescription;
        reserveReq.baseUrl = baseUrl;
        reserveReq.appMasterKey = generateRandomKeyHex();     // chei propuse
        reserveReq.sdmMetaReadKey = FACTORY_KEY_HEX;          // backend-ul pune Key2 comuna
        reserveReq.sdmFileReadKey = generateRandomKeyHex();

        CiprianApp.getInstance().getApiClient().reserveTag(reserveReq,
                new ApiClient.ApiCallback<ApiClient.ReserveTagResponse>() {
                    @Override
                    public void onSuccess(ApiClient.ReserveTagResponse resp) {
                        runOnUiThread(() -> {
                            // Cheile sunt salvate. Programam cipul cu EXACT cheile din DB.
                            reservedTagId = resp.tagId;
                            pendingConfig.appMasterKey = hexToBytes(resp.appMasterKey);
                            pendingConfig.sdmFileReadKey = hexToBytes(resp.sdmFileReadKey);
                            if (resp.sdmMetaReadKey != null) {
                                pendingConfig.sdmMetaReadKey = hexToBytes(resp.sdmMetaReadKey);
                            }
                            if (resp.baseUrl != null) {
                                pendingConfig.baseUrl = resp.baseUrl;
                            }
                            binding.textScanStatus.setText(R.string.hold_tag_near_phone);
                            waitingForProgramScan = true;
                        });
                    }

                    @Override
                    public void onError(String error) {
                        runOnUiThread(() -> {
                            waitingForProgramScan = false;
                            binding.buttonProgram.setEnabled(true);
                            binding.progressBar.setVisibility(View.GONE);
                            binding.textScanStatus.setText(R.string.backend_check_failed);

                            new AlertDialog.Builder(ProgramTagActivity.this)
                                    .setTitle(R.string.cannot_program_title)
                                    .setMessage(getString(R.string.cannot_program_message, error))
                                    .setPositiveButton(R.string.ok, null)
                                    .show();
                        });
                    }
                });
    }

    private String generateRandomKeyHex() {
        byte[] key = new byte[16];
        new java.security.SecureRandom().nextBytes(key);
        StringBuilder sb = new StringBuilder();
        for (byte b : key) {
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
