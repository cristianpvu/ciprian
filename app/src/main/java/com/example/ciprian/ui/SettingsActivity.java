package com.example.ciprian.ui;

import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.ciprian.BuildConfig;
import com.example.ciprian.CiprianApp;
import com.example.ciprian.Config;
import com.example.ciprian.data.SecureStorage;
import com.example.ciprian.databinding.ActivitySettingsBinding;

public class SettingsActivity extends AppCompatActivity {

    private ActivitySettingsBinding binding;
    private SecureStorage storage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        binding = ActivitySettingsBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        storage = CiprianApp.getInstance().getSecureStorage();

        setupToolbar();
        loadAccountInfo();
    }

    private void setupToolbar() {
        binding.toolbar.setNavigationOnClickListener(v -> finish());
    }

    private void loadAccountInfo() {
        // User info
        String userName = storage.getUserName();
        String userEmail = storage.getUserEmail();

        binding.textUserName.setText(userName != null && !userName.isEmpty() ? userName : "-");
        binding.textUserEmail.setText(userEmail != null ? userEmail : "-");

        // Server info - extract domain from URL
        String serverUrl = Config.API_URL;
        try {
            java.net.URL url = new java.net.URL(serverUrl);
            binding.textServer.setText(url.getHost());
        } catch (Exception e) {
            binding.textServer.setText(serverUrl);
        }

        // Version info
        binding.textVersion.setText("Version " + BuildConfig.VERSION_NAME);
    }
}
