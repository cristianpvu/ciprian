package com.example.ciprian;

/**
 * Configurație centralizată pentru aplicație.
 * Backend-ul nostru gestionează totul.
 */
public final class Config {

    private Config() {}

    public static final String API_URL = "https://ntag-verify-api.vercel.app";

    // URL-ul pentru verificarea cipurilor
    public static final String VERIFY_URL = API_URL + "/verify";
}
