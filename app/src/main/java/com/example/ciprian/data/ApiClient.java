package com.example.ciprian.data;

import android.content.Context;
import android.util.Log;

import com.example.ciprian.Config;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.logging.HttpLoggingInterceptor;

/**
 * API client pentru backend-ul Ciprian NFC.
 */
public class ApiClient {

    private static final String TAG = "ApiClient";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final OkHttpClient client;
    private final Gson gson;
    private final SecureStorage storage;

    public ApiClient(Context context) {
        HttpLoggingInterceptor logging = new HttpLoggingInterceptor();
        logging.setLevel(HttpLoggingInterceptor.Level.BODY);

        this.client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .addInterceptor(logging)
                .build();

        this.gson = new GsonBuilder()
                .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                .create();

        this.storage = new SecureStorage(context);
    }

    // ==================== AUTH ====================

    /**
     * Înregistrare user nou
     */
    public void register(String email, String password, String name, ApiCallback<AuthResponse> callback) {
        RegisterRequest body = new RegisterRequest();
        body.email = email;
        body.password = password;
        body.name = name;

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/auth/register")
                .post(RequestBody.create(gson.toJson(body), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Register failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                handleAuthResponse(response, callback);
            }
        });
    }

    /**
     * Login
     */
    public void login(String email, String password, ApiCallback<AuthResponse> callback) {
        LoginRequest body = new LoginRequest();
        body.email = email;
        body.password = password;

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/auth/login")
                .post(RequestBody.create(gson.toJson(body), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Login failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                handleAuthResponse(response, callback);
            }
        });
    }

    private void handleAuthResponse(Response response, ApiCallback<AuthResponse> callback) throws IOException {
        if (response.isSuccessful() && response.body() != null) {
            AuthResponse authResponse = gson.fromJson(response.body().string(), AuthResponse.class);
            if (authResponse.success && authResponse.token != null) {
                storage.setAuthToken(authResponse.token);
                if (authResponse.user != null) {
                    storage.setUserEmail(authResponse.user.email);
                    if (authResponse.user.name != null) {
                        storage.setUserName(authResponse.user.name);
                    }
                }
            }
            callback.onSuccess(authResponse);
        } else {
            String errorBody = response.body() != null ? response.body().string() : "";
            ErrorResponse error = gson.fromJson(errorBody, ErrorResponse.class);
            callback.onError(error != null && error.error != null ? error.error : "Request failed");
        }
    }

    /**
     * Verifică dacă user-ul e logat
     */
    public boolean isLoggedIn() {
        return storage.getAuthToken() != null;
    }

    /**
     * Logout
     */
    public void logout() {
        storage.clear();
    }

    // ==================== TAGS ====================

    /**
     * Obține lista de cipuri
     */
    public void getTags(ApiCallback<TagListResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/tags")
                .addHeader("Authorization", "Bearer " + token)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Get tags failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    TagListResponse resp = gson.fromJson(response.body().string(), TagListResponse.class);
                    callback.onSuccess(resp);
                } else {
                    callback.onError("Failed to get tags: " + response.code());
                }
            }
        });
    }

    /**
     * Înregistrează un cip nou
     */
    public void registerTag(RegisterTagRequest tagRequest, ApiCallback<RegisterTagResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/tags")
                .addHeader("Authorization", "Bearer " + token)
                .post(RequestBody.create(gson.toJson(tagRequest), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Register tag failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    RegisterTagResponse resp = gson.fromJson(response.body().string(), RegisterTagResponse.class);
                    callback.onSuccess(resp);
                } else {
                    String errorBody = response.body() != null ? response.body().string() : "";
                    ErrorResponse error = gson.fromJson(errorBody, ErrorResponse.class);
                    callback.onError(error != null && error.error != null ? error.error : "Failed to register tag");
                }
            }
        });
    }

    /**
     * Obține cheile unui cip (pentru factory reset)
     */
    public void getTagKeys(String tagId, ApiCallback<TagKeysResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/tags/" + tagId + "/keys")
                .addHeader("Authorization", "Bearer " + token)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Get tag keys failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful() && response.body() != null) {
                    TagKeysResponse resp = gson.fromJson(response.body().string(), TagKeysResponse.class);
                    callback.onSuccess(resp);
                } else {
                    callback.onError("Failed to get tag keys: " + response.code());
                }
            }
        });
    }

    /**
     * Șterge un cip
     */
    public void deleteTag(String tagId, ApiCallback<DeleteTagResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/tags/" + tagId)
                .addHeader("Authorization", "Bearer " + token)
                .delete()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Delete tag failed", e);
                callback.onError(e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                if (response.isSuccessful()) {
                    DeleteTagResponse resp = new DeleteTagResponse();
                    resp.success = true;
                    callback.onSuccess(resp);
                } else {
                    callback.onError("Failed to delete tag: " + response.code());
                }
            }
        });
    }

    // ==================== REQUEST/RESPONSE CLASSES ====================

    public static class RegisterRequest {
        public String email;
        public String password;
        public String name;
    }

    public static class LoginRequest {
        public String email;
        public String password;
    }

    public static class AuthResponse {
        public boolean success;
        public User user;
        public String token;
    }

    public static class User {
        public String id;
        public String email;
        public String name;
    }

    public static class ErrorResponse {
        public String error;
    }

    public static class RegisterTagRequest {
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
        public String baseUrl;
        public String name;
        public String description;
    }

    public static class RegisterTagResponse {
        public boolean success;
        public String tagId;
        public String message;
    }

    public static class DeleteTagResponse {
        public boolean success;
    }

    public static class TagKeysResponse {
        public String id;
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
    }

    public static class TagListResponse {
        public TagItem[] tags;
        public int total;
    }

    public static class TagItem {
        public String id;
        public String uid;
        public String name;
        public String description;
        public String baseUrl;
        public int scanCount;
        public String lastScan;
        public String createdAt;
    }

    public interface ApiCallback<T> {
        void onSuccess(T response);
        void onError(String error);
    }
}
