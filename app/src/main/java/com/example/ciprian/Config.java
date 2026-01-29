package com.example.ciprian;

/**
 * Configurație centralizată pentru aplicație.
 * Backend-ul nostru gestionează totul.
 */
public final class Config {

    private Config() {}

    // URL-ul backend-ului (schimbă cu URL-ul tău de producție)
    // Pentru development local: "http://10.0.2.2:3000" (emulator) sau IP-ul local
    // Pentru producție: "https://ciprian-nfc-api.onrender.com" sau domeniul tău
    // TODO: Schimbă înapoi la producție după deploy
    // Pentru telefon fizic: folosește IP-ul computerului (192.168.1.156)
    // Pentru emulator: folosește 10.0.2.2
    public static final String API_URL = "http://192.168.1.156:3000";

    // URL-ul pentru verificarea cipurilor
    public static final String VERIFY_URL = API_URL + "/verify";
}
