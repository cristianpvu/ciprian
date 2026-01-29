package com.example.ciprian;

import android.app.Application;

import com.example.ciprian.data.ApiClient;
import com.example.ciprian.data.SecureStorage;

public class CiprianApp extends Application {

    private static CiprianApp instance;
    private SecureStorage secureStorage;
    private ApiClient apiClient;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        secureStorage = new SecureStorage(this);
        apiClient = new ApiClient(this);
    }

    public static CiprianApp getInstance() {
        return instance;
    }

    public SecureStorage getSecureStorage() {
        return secureStorage;
    }

    public ApiClient getApiClient() {
        return apiClient;
    }
}
