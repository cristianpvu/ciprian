# Ciprian NFC - NTAG 424 DNA Programming System

Sistema complet pentru programarea și verificarea cipurilor NFC NTAG 424 DNA cu Secure Dynamic Messaging (SDM).

## Arhitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                    APLICAȚIE ANDROID                            │
│  • Programează cipuri NTAG 424 DNA                             │
│  • Setează chei AES-128 + configurare SDM                      │
│  • Management cipuri programate                                │
└─────────────────────┬───────────────────────────────────────────┘
                      │ HTTPS
┌─────────────────────▼───────────────────────────────────────────┐
│                      SUPABASE                                   │
│  ┌─────────────────┐  ┌─────────────────┐                      │
│  │   PostgreSQL    │  │  Edge Function  │                      │
│  │   (Database)    │  │   (Verificare)  │                      │
│  └─────────────────┘  └─────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

## Setup Rapid

### 1. Creează proiect Supabase

1. Du-te la [supabase.com](https://supabase.com) și creează cont gratuit
2. Creează un proiect nou
3. Din **Project Settings > API**, notează:
   - **Project URL** (ex: `https://xxxxx.supabase.co`)
   - **anon public key**

### 2. Configurează baza de date

1. În Supabase, mergi la **SQL Editor**
2. Copiază conținutul din `supabase/schema.sql`
3. Rulează-l (click **Run**)

### 3. Creează organizația ta

În SQL Editor, rulează:

```sql
INSERT INTO organizations (name, api_key)
VALUES ('Numele Tau', 'cpn_cheie_secreta_aleasa_de_tine');
```

Salvează `cpn_cheie_secreta_aleasa_de_tine` - vei avea nevoie de ea în aplicație.

### 4. Deploy Edge Function (pentru verificare)

```bash
# Instalează Supabase CLI
npm install -g supabase

# Login
supabase login

# Link la proiectul tău
supabase link --project-ref YOUR_PROJECT_REF

# Deploy funcția de verificare
supabase functions deploy verify --project-ref YOUR_PROJECT_REF
```

### 5. Configurează aplicația Android

1. Deschide proiectul în Android Studio
2. Build și instalează pe telefon
3. Deschide Settings și completează:
   - **Project URL**: URL-ul Supabase (ex: `https://xxxxx.supabase.co`)
   - **Anon Key**: Cheia publică din Supabase
   - **Organization API Key**: Cheia pe care ai creat-o la pasul 3

### 6. Programează primul cip

1. Apasă "Program Tag"
2. Introdu un nume și URL-ul de verificare (ex: `https://xxxxx.supabase.co/functions/v1/verify`)
3. Apropie cipul NTAG 424 DNA de telefon
4. Gata!

## Cum funcționează verificarea

Când cineva scanează cipul NFC:

1. **Cipul generează URL dinamic**:
   ```
   https://xxxxx.supabase.co/functions/v1/verify?enc=...&cmac=...
   ```

2. **Edge Function**:
   - Decriptează `enc` pentru a obține UID și counter
   - Verifică semnătura CMAC
   - Verifică counter-ul (protecție anti-replay)
   - Returnează rezultatul

3. **Răspuns**:
   ```json
   {
     "valid": true,
     "uid": "04A1B2C3D4E5F6",
     "counter": 42,
     "tagName": "Acces Magazin",
     "timestamp": "2024-01-15T10:30:00Z"
   }
   ```

## Structura Proiectului

```
ciprian/
├── app/                          # Aplicația Android
│   └── src/main/
│       ├── java/com/example/ciprian/
│       │   ├── CiprianApp.java
│       │   ├── data/
│       │   │   ├── ApiClient.java        # Client Supabase
│       │   │   └── SecureStorage.java
│       │   ├── nfc/
│       │   │   ├── crypto/
│       │   │   │   ├── AesUtils.java
│       │   │   │   └── CmacAes.java
│       │   │   ├── Ntag424DnaCommands.java
│       │   │   ├── Ntag424DnaAuth.java
│       │   │   └── Ntag424DnaProgrammer.java
│       │   └── ui/
│       │       ├── MainActivity.java
│       │       ├── ProgramTagActivity.java
│       │       ├── SettingsActivity.java
│       │       └── TagDetailsActivity.java
│       └── res/
│
└── supabase/
    ├── schema.sql                # Schema bază de date
    └── functions/
        └── verify/               # Edge function pentru verificare
            └── index.ts
```

## Multi-Tenant

Sistemul suportă mai multe organizații - poți oferi serviciul și altora:

- Fiecare organizație are propria cheie API
- Tag-urile sunt izolate per organizație
- Statisticile sunt separate

## Securitate

- **AES-128** pentru toate cheile
- **CMAC** pentru verificarea autenticității
- **Counter anti-replay** pe fiecare cip
- **Chei stocate** în Supabase (poți adăuga encryption at rest)
- **RLS (Row Level Security)** pe toate tabelele

## Costuri

Cu Supabase Free Tier ai:
- 500MB bază de date
- 2GB bandwidth
- 500K Edge Function invocations/lună

Pentru majoritatea cazurilor de utilizare, e gratuit!

## Troubleshooting

### "NFC not available"
- Asigură-te că telefonul are NFC
- Verifică că NFC e activat în Settings

### "Tag not recognized"
- Asigură-te că e un cip NTAG 424 DNA (nu NTAG 213/215/216)
- Ține cipul nemișcat lângă telefon

### "Authentication failed"
- Cipul a fost deja programat cu alte chei
- Încearcă cu un cip nou sau resetează-l
