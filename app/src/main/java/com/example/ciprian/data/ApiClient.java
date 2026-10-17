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

    /**
     * Preflight înainte de programare: verifică într-un singur apel că
     * serverul răspunde, token-ul e valid (nu expirat) și user-ul există
     * în baza de date. Foloseste GET /api/auth/me.
     *
     * Daca asta esueaza, NU trebuie sa atingem cipul - altfel ramane
     * programat dar nesalvat in DB (si pierdut).
     */
    public void preflight(ApiCallback<User> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/auth/me")
                .addHeader("Authorization", "Bearer " + token)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Preflight failed", e);
                callback.onError("Cannot reach server: " + e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String bodyStr = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    MeResponse resp = gson.fromJson(bodyStr, MeResponse.class);
                    callback.onSuccess(resp != null ? resp.user : null);
                } else {
                    ErrorResponse error = gson.fromJson(bodyStr, ErrorResponse.class);
                    callback.onError(error != null && error.error != null
                            ? error.error : ("Server error: " + response.code()));
                }
            }
        });
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
     * Reserve-first: salvează cheile în backend ÎNAINTE de a scrie pe cip.
     * Răspunsul conține cheile pe care telefonul TREBUIE să le scrie pe cip
     * (pe retry pot fi cele deja salvate, nu cele propuse acum).
     */
    public void reserveTag(ReserveTagRequest tagRequest, ApiCallback<ReserveTagResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) {
            callback.onError("Not logged in");
            return;
        }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/tags/reserve")
                .addHeader("Authorization", "Bearer " + token)
                .post(RequestBody.create(gson.toJson(tagRequest), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Reserve tag failed", e);
                callback.onError("Cannot reach server: " + e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                String bodyStr = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    ReserveTagResponse resp = gson.fromJson(bodyStr, ReserveTagResponse.class);
                    callback.onSuccess(resp);
                } else {
                    ErrorResponse error = gson.fromJson(bodyStr, ErrorResponse.class);
                    callback.onError(error != null && error.error != null
                            ? error.error : ("Failed to reserve tag: " + response.code()));
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

    public static class MeResponse {
        public User user;
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

    public static class ReserveTagRequest {
        public String uid;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
        public String baseUrl;
        public String name;
        public String description;
    }

    public static class ReserveTagResponse {
        public boolean success;
        public boolean reused;
        public String tagId;
        public String uid;
        public String name;
        public String description;
        public String baseUrl;
        public String appMasterKey;
        public String sdmMetaReadKey;
        public String sdmFileReadKey;
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

    // ==================== DINEDROID (restaurante / mese / bind) ====================

    /** Restaurantele la care contul dinedroid legat are acces (SUPER_ADMIN le vede pe toate). */
    public void getDinedroidRestaurants(ApiCallback<RestaurantListResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) { callback.onError("Not logged in"); return; }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/dinedroid/restaurants")
                .addHeader("Authorization", "Bearer " + token)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Get restaurants failed", e);
                callback.onError(e.getMessage());
            }
            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    callback.onSuccess(gson.fromJson(body, RestaurantListResponse.class));
                } else {
                    callback.onError(parseError(body, "Failed to get restaurants: " + response.code()));
                }
            }
        });
    }

    /** Mesele unui restaurant (cu numărul de taguri deja atribuite). */
    public void getDinedroidTables(int restaurantId, ApiCallback<TableListResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) { callback.onError("Not logged in"); return; }

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/dinedroid/restaurants/" + restaurantId + "/tables")
                .addHeader("Authorization", "Bearer " + token)
                .get()
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Get tables failed", e);
                callback.onError(e.getMessage());
            }
            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    callback.onSuccess(gson.fromJson(body, TableListResponse.class));
                } else {
                    callback.onError(parseError(body, "Failed to get tables: " + response.code()));
                }
            }
        });
    }

    /** Leagă cipul (uid) de o masă. Re-binding la altă masă doar actualizează legătura. */
    public void bindTagToTable(int tableId, String uid, ApiCallback<BindTagResponse> callback) {
        String token = storage.getAuthToken();
        if (token == null) { callback.onError("Not logged in"); return; }

        BindTagRequest reqBody = new BindTagRequest();
        reqBody.uid = uid;

        Request request = new Request.Builder()
                .url(Config.API_URL + "/api/dinedroid/tables/" + tableId + "/bind")
                .addHeader("Authorization", "Bearer " + token)
                .post(RequestBody.create(gson.toJson(reqBody), JSON))
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override public void onFailure(Call call, IOException e) {
                Log.e(TAG, "Bind tag failed", e);
                callback.onError(e.getMessage());
            }
            @Override public void onResponse(Call call, Response response) throws IOException {
                String body = response.body() != null ? response.body().string() : "";
                if (response.isSuccessful()) {
                    callback.onSuccess(gson.fromJson(body, BindTagResponse.class));
                } else {
                    callback.onError(parseError(body, "Failed to bind tag: " + response.code()));
                }
            }
        });
    }

    private String parseError(String body, String fallback) {
        try {
            ErrorResponse error = gson.fromJson(body, ErrorResponse.class);
            if (error != null && error.error != null) return error.error;
        } catch (Exception ignored) { /* corp non-JSON */ }
        return fallback;
    }

    // ==================== DINEDROID models ====================

    public static class DinedroidRestaurant {
        public int id;
        public String name;
        public String city;
        public String logoUrl;
    }

    public static class RestaurantListResponse {
        public DinedroidRestaurant[] restaurants;
        public int total;
    }

    public static class DinedroidTable {
        public int id;
        public Integer number;
        public Integer seats;
        public int tagCount;
        public boolean programmed;
    }

    public static class TableListResponse {
        public DinedroidTable[] tables;
        public int total;
    }

    public static class BindTagRequest {
        public String uid;
    }

    public static class BindTagResponse {
        public boolean success;
        public int tableId;
        public String uid;
    }

    public interface ApiCallback<T> {
        void onSuccess(T response);
        void onError(String error);
    }
}
