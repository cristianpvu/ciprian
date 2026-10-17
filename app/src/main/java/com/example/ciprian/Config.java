package com.example.ciprian;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Configurație centralizată pentru aplicație.
 *
 * Mediul (PROD / DEV) e comutabil din Settings și salvat în prefs. Comută două
 * lucruri deodată:
 *   - API_URL       — backend-ul (și implicit baza de date) care ține cheile
 *                     cipurilor; verificarea CMAC la tap se face față de acest DB.
 *   - MENU_BASE_URL — URL-ul scris pe cip (entrypoint-ul de redirect care duce
 *                     clientul în meniu). E doar default-ul câmpului la programare;
 *                     operatorul îl poate încă edita manual.
 *
 * Valorile statice de mai jos sunt PROD (fallback) până când init() aplică
 * mediul salvat. init() se apelează din CiprianApp.onCreate ÎNAINTE de orice
 * request, deci ApiClient vede mereu valoarea corectă.
 */
public final class Config {

    private Config() {}

    public enum Env { PROD, DEV }

    private static final String PREFS = "ciprian_env";
    private static final String KEY_ENV = "selected_env";

    // ── PROD ──────────────────────────────────────────────────────────────────
    public static final String PROD_API_URL  = "https://ntag-verify.dinedroid.com";
    public static final String PROD_MENU_URL = "https://go.dinedroid.com/n";

    // ── DEV ───────────────────────────────────────────────────────────────────
    // Ruta /n stă la rădăcina api-ului (portul 5000), iar pe dev
    // api.dev.dinedroid.com -> 5000, deci nu e nevoie de un host `go.dev` separat.
    public static final String DEV_API_URL  = "https://ntag-verify.dev.dinedroid.com";
    public static final String DEV_MENU_URL = "https://api.dev.dinedroid.com/n";

    // Valorile active (setate de init()/switchEnv()). Non-final ca să poată comuta.
    public static String API_URL       = PROD_API_URL;
    public static String MENU_BASE_URL = PROD_MENU_URL;

    /** Aplică mediul salvat. De apelat din CiprianApp.onCreate înainte de orice request. */
    public static void init(Context ctx) {
        apply(load(ctx));
    }

    public static Env current(Context ctx) {
        return load(ctx);
    }

    /** Comută mediul, persistă alegerea și actualizează valorile active. */
    public static void switchEnv(Context ctx, Env env) {
        prefs(ctx).edit().putString(KEY_ENV, env.name()).apply();
        apply(env);
    }

    private static void apply(Env env) {
        if (env == Env.DEV) {
            API_URL = DEV_API_URL;
            MENU_BASE_URL = DEV_MENU_URL;
        } else {
            API_URL = PROD_API_URL;
            MENU_BASE_URL = PROD_MENU_URL;
        }
    }

    private static Env load(Context ctx) {
        String v = prefs(ctx).getString(KEY_ENV, Env.PROD.name());
        try {
            return Env.valueOf(v);
        } catch (IllegalArgumentException e) {
            return Env.PROD;
        }
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
