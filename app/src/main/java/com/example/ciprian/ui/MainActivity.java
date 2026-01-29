package com.example.ciprian.ui;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.view.View;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;

import com.example.ciprian.CiprianApp;
import com.example.ciprian.R;
import com.example.ciprian.data.ApiClient;
import com.example.ciprian.databinding.ActivityMainBinding;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private ActivityMainBinding binding;
    private NfcAdapter nfcAdapter;
    private TagsAdapter adapter;
    private List<ApiClient.TagItem> tags = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        // Check if logged in, redirect to login if not
        if (!CiprianApp.getInstance().getApiClient().isLoggedIn()) {
            startActivity(new Intent(this, LoginActivity.class));
            finish();
            return;
        }

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, 0);
            binding.fabProgram.setTranslationY(-systemBars.bottom);
            return insets;
        });

        setupNfc();
        setupToolbar();
        setupRecyclerView();
        setupFab();
        setupSwipeRefresh();
    }

    private void setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        if (nfcAdapter == null) {
            Toast.makeText(this, R.string.nfc_not_available, Toast.LENGTH_LONG).show();
        }
    }

    private void setupToolbar() {
        binding.toolbar.setOnMenuItemClickListener(item -> {
            if (item.getItemId() == R.id.action_settings) {
                startActivity(new Intent(this, SettingsActivity.class));
                return true;
            } else if (item.getItemId() == R.id.action_logout) {
                showLogoutConfirmation();
                return true;
            }
            return false;
        });
    }

    private void showLogoutConfirmation() {
        new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                .setTitle(R.string.logout)
                .setMessage(R.string.logout_confirm)
                .setPositiveButton(R.string.logout, (dialog, which) -> {
                    CiprianApp.getInstance().getApiClient().logout();
                    startActivity(new Intent(this, LoginActivity.class));
                    finish();
                })
                .setNegativeButton(R.string.cancel, null)
                .show();
    }

    private void setupRecyclerView() {
        adapter = new TagsAdapter(tags, this::onTagClick);
        binding.recyclerTags.setLayoutManager(new LinearLayoutManager(this));
        binding.recyclerTags.setAdapter(adapter);
    }

    private void setupFab() {
        binding.fabProgram.setOnClickListener(v -> {
            if (nfcAdapter == null) {
                Toast.makeText(this, R.string.nfc_not_available, Toast.LENGTH_SHORT).show();
                return;
            }
            if (!nfcAdapter.isEnabled()) {
                Toast.makeText(this, R.string.nfc_disabled, Toast.LENGTH_SHORT).show();
                return;
            }
            startActivity(new Intent(this, ProgramTagActivity.class));
        });
    }

    private void setupSwipeRefresh() {
        binding.swipeRefresh.setOnRefreshListener(this::loadTags);
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadTags();
    }

    private void loadTags() {
        CiprianApp.getInstance().getApiClient().getTags(new ApiClient.ApiCallback<ApiClient.TagListResponse>() {
            @Override
            public void onSuccess(ApiClient.TagListResponse response) {
                runOnUiThread(() -> {
                    binding.swipeRefresh.setRefreshing(false);
                    tags.clear();
                    if (response.tags != null) {
                        tags.addAll(Arrays.asList(response.tags));
                    }
                    adapter.notifyDataSetChanged();
                    showEmptyState(tags.isEmpty());
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    binding.swipeRefresh.setRefreshing(false);
                    // For now, show empty state on error
                    showEmptyState(true);
                });
            }
        });
    }

    private void showEmptyState(boolean show) {
        binding.emptyState.setVisibility(show ? View.VISIBLE : View.GONE);
        binding.recyclerTags.setVisibility(show ? View.GONE : View.VISIBLE);
    }

    private void onTagClick(ApiClient.TagItem tag) {
        Intent intent = new Intent(this, TagDetailsActivity.class);
        intent.putExtra("tag_id", tag.id);
        intent.putExtra("tag_uid", tag.uid);
        intent.putExtra("tag_name", tag.name);
        intent.putExtra("tag_description", tag.description);
        intent.putExtra("tag_url", tag.baseUrl);
        intent.putExtra("tag_scans", tag.scanCount);
        intent.putExtra("tag_last_scan", tag.lastScan);
        intent.putExtra("tag_created", tag.createdAt);
        startActivity(intent);
    }
}
