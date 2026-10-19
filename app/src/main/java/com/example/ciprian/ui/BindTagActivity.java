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
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.ciprian.CiprianApp;
import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ActivityBindTagBinding;

/**
 * Ataseaza un cip DEJA programat la o masa, fara reprogramare.
 *
 * Fiindca toate cipurile au acelasi URL permanent (Config.MENU_BASE_URL), legatura
 * cu masa traieste doar in DB. Aici doar citim UID-ul (read-only, fara write) si chemam
 * bindTagToTable -> backendul rezolva masa la scanare. Util pentru loturi
 * pre-programate, mutarea unui tag intre mese sau inlocuirea unui cip defect.
 */
public class BindTagActivity extends AppCompatActivity {

    public static final String EXTRA_TABLE_ID = "table_id";
    public static final String EXTRA_TABLE_LABEL = "table_label";

    private ActivityBindTagBinding binding;
    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private IntentFilter[] intentFilters;
    private String[][] techLists;

    private int tableId = -1;
    private String tableLabel = "";
    private boolean isBinding = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivityBindTagBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        tableId = getIntent().getIntExtra(EXTRA_TABLE_ID, -1);
        tableLabel = getIntent().getStringExtra(EXTRA_TABLE_LABEL);
        if (tableLabel == null) tableLabel = "";

        binding.toolbar.setNavigationOnClickListener(v -> finish());
        binding.textInstruction.setText(getString(R.string.bind_instructions, tableLabel));
        binding.textStatus.setText(R.string.bind_waiting);

        setupNfc();
    }

    private void setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            Toast.makeText(this, R.string.nfc_not_available, Toast.LENGTH_LONG).show();
            return;
        }

        pendingIntent = PendingIntent.getActivity(
                this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_MUTABLE
        );
        intentFilters = new IntentFilter[]{new IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)};
        techLists = new String[][]{new String[]{IsoDep.class.getName()}};
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
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(intent.getAction())) {
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag.class);
            if (tag != null) handleScan(tag);
        }
    }

    private void handleScan(Tag tag) {
        if (isBinding || tableId == -1) return;
        isBinding = true;

        binding.progress.setVisibility(View.VISIBLE);
        binding.textStatus.setText(R.string.reading_tag);

        new Thread(() -> {
            // UID-ul din anticoliziune (tag.getId()) e UID-ul real cat timp RandomID
            // e dezactivat. Nu cere autentificare, deci merge si pe cipuri deja
            // programate (Key0 schimbat), unde GetCardUid cu cheia de fabrica pica.
            byte[] id = tag.getId();
            if (id == null || id.length != 7) {
                runOnUiThread(() -> {
                    binding.progress.setVisibility(View.GONE);
                    binding.textStatus.setText(R.string.error_reading_tag);
                    isBinding = false;
                });
                return;
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : id) sb.append(String.format("%02X", b));
            String uid = sb.toString();

            runOnUiThread(() -> binding.textStatus.setText(R.string.binding_tag));

            CiprianApp.getInstance().getApiClient().bindTagToTable(tableId, uid,
                    new ApiClient.ApiCallback<ApiClient.BindTagResponse>() {
                        @Override
                        public void onSuccess(ApiClient.BindTagResponse resp) {
                            runOnUiThread(() -> {
                                binding.progress.setVisibility(View.GONE);
                                binding.textStatus.setText(
                                        getString(R.string.bind_complete, tableLabel));
                                isBinding = false;
                            });
                        }

                        @Override
                        public void onError(String error) {
                            runOnUiThread(() -> {
                                binding.progress.setVisibility(View.GONE);
                                binding.textStatus.setText(R.string.bind_failed);
                                Toast.makeText(BindTagActivity.this, error, Toast.LENGTH_LONG).show();
                                isBinding = false;
                            });
                        }
                    });
        }).start();
    }
}
