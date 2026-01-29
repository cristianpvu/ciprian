package com.example.ciprian.ui;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Bundle;
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
import com.example.ciprian.databinding.ActivityTagDetailsBinding;
import com.example.ciprian.nfc.Ntag424DnaProgrammer;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public class TagDetailsActivity extends AppCompatActivity {

    private ActivityTagDetailsBinding binding;

    private String tagId;
    private String tagUid;

    // NFC
    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFilters;
    private String[][] techLists;

    // Factory Reset state
    private boolean waitingForTagToReset = false;
    private Ntag424DnaProgrammer.TagKeys keysForReset;
    private Ntag424DnaProgrammer programmer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivityTagDetailsBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        setupToolbar();
        setupNfc();
        loadTagDetails();
        setupButtons();
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

    private void loadTagDetails() {
        tagId = getIntent().getStringExtra("tag_id");
        tagUid = getIntent().getStringExtra("tag_uid");
        String tagName = getIntent().getStringExtra("tag_name");
        String tagDescription = getIntent().getStringExtra("tag_description");
        String tagUrl = getIntent().getStringExtra("tag_url");
        int tagScans = getIntent().getIntExtra("tag_scans", 0);
        String tagLastScan = getIntent().getStringExtra("tag_last_scan");
        String tagCreated = getIntent().getStringExtra("tag_created");

        binding.textTagName.setText(tagName != null ? tagName : "Unnamed Tag");
        binding.textTagUid.setText(formatUid(tagUid));
        binding.textTotalScans.setText(String.valueOf(tagScans));
        binding.textLastScan.setText(formatRelativeTime(tagLastScan));
        binding.textBaseUrl.setText(tagUrl);

        if (tagDescription != null && !tagDescription.isEmpty()) {
            binding.cardDescription.setVisibility(View.VISIBLE);
            binding.textDescription.setText(tagDescription);
        }

        if (tagCreated != null) {
            binding.textCreatedAt.setText("Created: " + formatDate(tagCreated));
        }
    }

    private void setupButtons() {
        binding.btnFactoryReset.setOnClickListener(v -> confirmFactoryReset());
        binding.btnDelete.setOnClickListener(v -> confirmDelete());
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
            if (tag != null && waitingForTagToReset) {
                handleTagForReset(tag);
            }
        }
    }

    // ==================== Factory Reset ====================

    private void confirmFactoryReset() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.factory_reset)
                .setMessage(R.string.factory_reset_confirm)
                .setPositiveButton(R.string.ok, (dialog, which) -> startFactoryReset())
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    private void startFactoryReset() {
        // Get keys from backend
        binding.progressReset.setVisibility(View.VISIBLE);
        binding.textResetStatus.setVisibility(View.VISIBLE);
        binding.textResetStatus.setText("Getting tag keys...");
        binding.btnFactoryReset.setEnabled(false);

        CiprianApp.getInstance().getApiClient().getTagKeys(tagId, new ApiClient.ApiCallback<ApiClient.TagKeysResponse>() {
            @Override
            public void onSuccess(ApiClient.TagKeysResponse response) {
                runOnUiThread(() -> {
                    // Verify UID matches
                    if (!response.uid.equalsIgnoreCase(tagUid)) {
                        showResetError("Tag UID mismatch");
                        return;
                    }

                    // Store keys for reset
                    keysForReset = new Ntag424DnaProgrammer.TagKeys();
                    keysForReset.appMasterKey = response.appMasterKey;
                    keysForReset.sdmMetaReadKey = response.sdmMetaReadKey;
                    keysForReset.sdmFileReadKey = response.sdmFileReadKey;

                    // Wait for tag
                    waitingForTagToReset = true;
                    binding.textResetStatus.setText(R.string.hold_tag_to_reset);
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> showResetError(error));
            }
        });
    }

    private void handleTagForReset(Tag tag) {
        waitingForTagToReset = false;
        binding.textResetStatus.setText(R.string.resetting_tag);

        new Thread(() -> {
            try {
                programmer = new Ntag424DnaProgrammer();
                programmer.connect(tag);

                programmer.factoryReset(keysForReset, new Ntag424DnaProgrammer.ResetCallback() {
                    @Override
                    public void onProgress(String message) {
                        runOnUiThread(() -> binding.textResetStatus.setText(message));
                    }

                    @Override
                    public void onError(String error) {
                        runOnUiThread(() -> showResetError(error));
                    }

                    @Override
                    public void onSuccess() {
                        // Delete tag from backend
                        deleteTagFromBackend();
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> showResetError(e.getMessage()));
            }
        }).start();
    }

    private void deleteTagFromBackend() {
        CiprianApp.getInstance().getApiClient().deleteTag(tagId, new ApiClient.ApiCallback<ApiClient.DeleteTagResponse>() {
            @Override
            public void onSuccess(ApiClient.DeleteTagResponse response) {
                runOnUiThread(() -> {
                    binding.progressReset.setVisibility(View.GONE);
                    binding.textResetStatus.setText(R.string.reset_complete);

                    new AlertDialog.Builder(TagDetailsActivity.this)
                            .setTitle(R.string.success)
                            .setMessage(R.string.reset_complete)
                            .setPositiveButton(R.string.ok, (dialog, which) -> finish())
                            .setCancelable(false)
                            .show();
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    // Tag was reset but backend delete failed - still show success
                    binding.progressReset.setVisibility(View.GONE);
                    binding.textResetStatus.setText(R.string.reset_complete);
                    Toast.makeText(TagDetailsActivity.this,
                            "Tag reset but failed to remove from server: " + error,
                            Toast.LENGTH_LONG).show();
                    finish();
                });
            }
        });
    }

    private void showResetError(String error) {
        binding.progressReset.setVisibility(View.GONE);
        binding.textResetStatus.setText(getString(R.string.reset_failed) + ": " + error);
        binding.btnFactoryReset.setEnabled(true);
        waitingForTagToReset = false;
        keysForReset = null;
    }

    // ==================== Delete ====================

    private void confirmDelete() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.delete_tag)
                .setMessage(R.string.delete_tag_confirm)
                .setPositiveButton(R.string.delete, (dialog, which) -> deleteTag())
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    private void deleteTag() {
        CiprianApp.getInstance().getApiClient().deleteTag(tagId, new ApiClient.ApiCallback<ApiClient.DeleteTagResponse>() {
            @Override
            public void onSuccess(ApiClient.DeleteTagResponse response) {
                runOnUiThread(() -> {
                    Toast.makeText(TagDetailsActivity.this, "Tag deleted", Toast.LENGTH_SHORT).show();
                    finish();
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    Toast.makeText(TagDetailsActivity.this, "Delete failed: " + error, Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    // ==================== Formatting ====================

    private String formatUid(String uid) {
        if (uid == null || uid.length() < 2) return uid != null ? uid : "";
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < uid.length(); i += 2) {
            if (i > 0) formatted.append(":");
            formatted.append(uid.substring(i, Math.min(i + 2, uid.length())));
        }
        return formatted.toString();
    }

    private String formatRelativeTime(String isoDate) {
        if (isoDate == null || isoDate.isEmpty()) {
            return "Never";
        }

        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
            Date date = sdf.parse(isoDate);
            if (date == null) return isoDate;

            long diffMs = System.currentTimeMillis() - date.getTime();
            long diffMins = TimeUnit.MILLISECONDS.toMinutes(diffMs);
            long diffHours = TimeUnit.MILLISECONDS.toHours(diffMs);
            long diffDays = TimeUnit.MILLISECONDS.toDays(diffMs);

            if (diffMins < 1) return "Just now";
            if (diffMins < 60) return diffMins + " min ago";
            if (diffHours < 24) return diffHours + "h ago";
            if (diffDays < 7) return diffDays + "d ago";

            SimpleDateFormat outFormat = new SimpleDateFormat("MMM d", Locale.US);
            return outFormat.format(date);
        } catch (ParseException e) {
            return isoDate;
        }
    }

    private String formatDate(String isoDate) {
        if (isoDate == null) return "";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
            Date date = sdf.parse(isoDate);
            if (date == null) return isoDate;

            SimpleDateFormat outFormat = new SimpleDateFormat("MMM d, yyyy", Locale.US);
            return outFormat.format(date);
        } catch (ParseException e) {
            return isoDate;
        }
    }
}
