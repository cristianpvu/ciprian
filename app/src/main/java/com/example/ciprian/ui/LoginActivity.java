package com.example.ciprian.ui;

import android.content.Intent;
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
import com.example.ciprian.databinding.ActivityLoginBinding;

public class LoginActivity extends AppCompatActivity {

    private ActivityLoginBinding binding;
    private boolean isRegisterMode = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);

        // Check if already logged in
        if (CiprianApp.getInstance().getApiClient().isLoggedIn()) {
            goToMain();
            return;
        }

        binding = ActivityLoginBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        setupClickListeners();
    }

    private void setupClickListeners() {
        binding.btnLogin.setOnClickListener(v -> {
            if (isRegisterMode) {
                doRegister();
            } else {
                doLogin();
            }
        });

        binding.btnToggle.setOnClickListener(v -> toggleMode());
    }

    private void toggleMode() {
        isRegisterMode = !isRegisterMode;

        if (isRegisterMode) {
            binding.layoutName.setVisibility(View.VISIBLE);
            binding.btnLogin.setText(R.string.register);
            binding.textToggleHint.setText(R.string.have_account);
            binding.btnToggle.setText(R.string.login);
        } else {
            binding.layoutName.setVisibility(View.GONE);
            binding.btnLogin.setText(R.string.login);
            binding.textToggleHint.setText(R.string.no_account);
            binding.btnToggle.setText(R.string.register);
        }
    }

    private void doLogin() {
        String email = binding.inputEmail.getText().toString().trim();
        String password = binding.inputPassword.getText().toString().trim();

        if (email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, R.string.please_fill_fields, Toast.LENGTH_SHORT).show();
            return;
        }

        setLoading(true);

        CiprianApp.getInstance().getApiClient().login(email, password, new ApiClient.ApiCallback<ApiClient.AuthResponse>() {
            @Override
            public void onSuccess(ApiClient.AuthResponse response) {
                runOnUiThread(() -> {
                    setLoading(false);
                    if (response.success) {
                        goToMain();
                    } else {
                        Toast.makeText(LoginActivity.this, R.string.login_failed, Toast.LENGTH_SHORT).show();
                    }
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    setLoading(false);
                    Toast.makeText(LoginActivity.this, error, Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void doRegister() {
        String name = binding.inputName.getText().toString().trim();
        String email = binding.inputEmail.getText().toString().trim();
        String password = binding.inputPassword.getText().toString().trim();

        if (email.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, R.string.please_fill_fields, Toast.LENGTH_SHORT).show();
            return;
        }

        if (password.length() < 6) {
            Toast.makeText(this, R.string.password_too_short, Toast.LENGTH_SHORT).show();
            return;
        }

        setLoading(true);

        CiprianApp.getInstance().getApiClient().register(email, password, name, new ApiClient.ApiCallback<ApiClient.AuthResponse>() {
            @Override
            public void onSuccess(ApiClient.AuthResponse response) {
                runOnUiThread(() -> {
                    setLoading(false);
                    if (response.success) {
                        Toast.makeText(LoginActivity.this, R.string.register_success, Toast.LENGTH_SHORT).show();
                        goToMain();
                    } else {
                        Toast.makeText(LoginActivity.this, R.string.register_failed, Toast.LENGTH_SHORT).show();
                    }
                });
            }

            @Override
            public void onError(String error) {
                runOnUiThread(() -> {
                    setLoading(false);
                    Toast.makeText(LoginActivity.this, error, Toast.LENGTH_LONG).show();
                });
            }
        });
    }

    private void setLoading(boolean loading) {
        binding.progress.setVisibility(loading ? View.VISIBLE : View.GONE);
        binding.btnLogin.setEnabled(!loading);
        binding.btnToggle.setEnabled(!loading);
        binding.inputEmail.setEnabled(!loading);
        binding.inputPassword.setEnabled(!loading);
        binding.inputName.setEnabled(!loading);
    }

    private void goToMain() {
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }
}
