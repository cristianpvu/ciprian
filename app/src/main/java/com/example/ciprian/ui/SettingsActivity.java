package com.example.ciprian.ui;

import android.content.Intent;
import android.os.Bundle;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.ciprian.BuildConfig;
import com.example.ciprian.CiprianApp;
import com.example.ciprian.Config;
import com.example.ciprian.R;
import com.example.ciprian.data.SecureStorage;
import com.example.ciprian.databinding.ActivitySettingsBinding;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

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
        setupEnvToggle();
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

        updateServerLabel();

        // Version info
        binding.textVersion.setText("Version " + BuildConfig.VERSION_NAME);
    }

    private void updateServerLabel() {
        String serverUrl = Config.API_URL;
        try {
            binding.textServer.setText(new java.net.URL(serverUrl).getHost());
        } catch (Exception e) {
            binding.textServer.setText(serverUrl);
        }
    }

    private void setupEnvToggle() {
        checkCurrentEnv();
        binding.toggleEnv.addOnButtonCheckedListener((group, checkedId, isChecked) -> {
            if (!isChecked) return;
            Config.Env selected =
                    checkedId == R.id.buttonEnvDev ? Config.Env.DEV : Config.Env.PROD;
            if (selected == Config.current(this)) return; // deja pe mediul ăsta
            confirmSwitch(selected);
        });
    }

    /** Pune bifa pe mediul curent, fără a declanșa un switch. */
    private void checkCurrentEnv() {
        binding.toggleEnv.check(
                Config.current(this) == Config.Env.DEV ? R.id.buttonEnvDev : R.id.buttonEnvProd);
    }

    private void confirmSwitch(Config.Env target) {
        String targetName = target == Config.Env.DEV ? getString(R.string.env_dev)
                                                      : getString(R.string.env_prod);
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.switch_env_title)
                .setMessage(getString(R.string.switch_env_message, targetName))
                .setPositiveButton(R.string.switch_confirm, (d, w) -> applySwitch(target))
                .setNegativeButton(R.string.cancel, (d, w) -> checkCurrentEnv())
                .setOnCancelListener(d -> checkCurrentEnv())
                .show();
    }

    private void applySwitch(Config.Env target) {
        Config.switchEnv(this, target);
        storage.clear(); // token-ul aparține celuilalt backend -> delogare
        Intent i = new Intent(this, LoginActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(i);
        finish();
    }
}
