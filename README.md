# EtherCalc PA

Gateway di autenticazione e autorizzazione davanti a
[EtherCalc](https://github.com/audreyt/ethercalc), pensato per l'uso nella
Pubblica Amministrazione: fogli di calcolo collaborativi in cui ogni utente
vede e modifica **solo i propri**, mentre all'esterno resta pubblico soltanto
l'export in sola lettura, da pubblicare come risorsa in un catalogo open data.

EtherCalc, di suo, non ha autenticazione: chiunque conosca l'indirizzo di un
foglio può modificarlo. Questo progetto non tocca EtherCalc; gli si mette
davanti.

## Architettura

```
                         ┌───────────────────────────────┐
  browser ── HTTPS ────▶ │  nginx (già esistente)         │
                         │  auth_request ──┐              │
                         └────────┬────────┼──────────────┘
                                  │        │ 204 / 401 / 403
                                  │        ▼
                                  │   ┌──────────────────┐
                                  │   │ gateway          │
                                  │   │ FastAPI + SQLite │
                                  │   └──────────────────┘
                                  ▼
                         ┌──────────────────┐
                         │ ethercalc        │  non esposto
                         └──────────────────┘
```

Per ogni richiesta diretta a EtherCalc, nginx interroga il gateway con
`auth_request`. La politica è **default deny**: passa solo ciò che è
esplicitamente previsto.

| Percorso | Chi può accedere |
|---|---|
| `GET /<id>.csv` e gli altri export | chiunque, se l'esportazione pubblica è attiva |
| interfaccia del foglio, `/<id>/edit`, API REST, WebSocket | solo il proprietario autenticato |
| `/_new`, `/_rooms`, `/_from`, `/_auth`, `/socket.io` | nessuno |

Il token di scrittura di EtherCalc (`ETHERCALC_KEY`, HMAC-SHA256 sul nome del
foglio) è calcolato dal gateway e consegnato solo al proprietario. I fogli non
registrati nel gateway non sono raggiungibili dall'esterno.

## Funzioni

- Utenti locali creati dall'amministratore, password con argon2id, cambio
  obbligatorio al primo accesso, blocco dopo 5 tentativi falliti.
- Sessioni lato server revocabili, protezione CSRF, nessuna risorsa esterna
  nelle pagine (niente font o script di terze parti).
- Interruttore per foglio: esportazione pubblica attiva o disattivata.
- Importazione CSV fino a 10 MB, con riconoscimento di UTF-8, UTF-8 con BOM e
  Windows-1252.
- Pannello amministrativo: utenti, elenco di tutti i fogli con riassegnazione,
  acquisizione dei fogli preesistenti, registro attività esportabile in CSV.
- Interfaccia e guida in linea in italiano, traduzione completa di EtherCalc
  inclusa.

## Contenuto del repository

```
gateway/                     applicazione FastAPI (Dockerfile incluso)
deploy/nginx/                blocco da inserire nel virtual host esistente
docker-compose.gateway.yml   override da usare con il compose di EtherCalc
l10n/it-IT.json, it.json     traduzione italiana di EtherCalc (388 voci)
patches/                     modifica necessaria a EtherCalc per la lingua
backup-ethercalc.sh          backup giornaliero con rotazione
```

## Installazione

Si parte da un'installazione di EtherCalc self-host funzionante
(`docker-compose.proxy.yml` del progetto originale).

1. Copia `gateway/`, `deploy/`, `docker-compose.gateway.yml` e
   `backup-ethercalc.sh` nella cartella del progetto EtherCalc; copia
   `l10n/it*.json` nella sua cartella `l10n/`.

2. Genera la chiave e configura l'ambiente:

   ```bash
   echo "ETHERCALC_KEY=$(openssl rand -hex 32)" >> .env
   echo "ETHERCALC_EXPIRE=0" >> .env        # 0 disattiva la scadenza dei fogli
   echo "GW_PREFIX=/sheet" >> .env          # vuoto se sta sulla radice del dominio
   echo "GW_COOKIE_SECURE=1" >> .env        # richiede HTTPS
   echo "COMPOSE_FILE=docker-compose.proxy.yml:docker-compose.gateway.yml" >> .env
   chmod 600 .env
   mkdir -p gateway-data && chown 1000:1000 gateway-data
   ```

3. Applica la modifica descritta in `patches/build-assets-locales.md`, poi:

   ```bash
   docker compose up -d --build
   docker compose exec gateway python manage.py create-admin <utente> "<Nome Cognome>"
   ```

4. Inserisci il contenuto di `deploy/nginx/ckan-sheet-location.conf` dentro il
   blocco `server { listen 443 ssl; ... }` del tuo nginx, prima della graffa di
   chiusura, e ricarica:

   ```bash
   nginx -t && nginx -s reload
   ```

   Il blocco presuppone il prefisso `/sheet` e i container raggiungibili come
   `ethercalc` e `gateway`: i due servizi vanno collegati alla stessa rete
   Docker dell'nginx (vedi `docker-compose.gateway.yml`).

5. Pianifica il backup:

   ```bash
   (crontab -l; echo "50 3 * * * /home/ubuntu/backup-ethercalc.sh >> /home/ubuntu/backup/ethercalc/cron.log 2>&1") | crontab -
   ```

## Configurazione

| Variabile | Predefinito | Significato |
|---|---|---|
| `ETHERCALC_KEY` | — | obbligatoria, almeno 32 caratteri; senza di essa il gateway non parte |
| `GW_PREFIX` | vuoto | prefisso del percorso pubblico, es. `/sheet` |
| `GW_COOKIE_SECURE` | `0` | `1` in produzione, richiede HTTPS |
| `GW_IDLE_TIMEOUT` | `28800` | scadenza della sessione per inattività, in secondi |
| `GW_ABS_TIMEOUT` | `86400` | durata massima della sessione, in secondi |

## Test

```bash
cd gateway
GW_PREFIX=/sheet python -m pytest -q test_policy.py
```

Coprono la politica di accesso per utente anonimo, proprietario e altro utente,
la consegna del token di scrittura, il CSRF e il blocco dell'account.

## Limiti noti

- **L'incollaggio dalla scheda Appunti di EtherCalc non salva.** È un
  comportamento di EtherCalc, non del gateway: il comando viene rifiutato e il
  WebSocket chiuso con codice 1008. La scheda è nascosta via CSS e i dati si
  caricano con l'importazione CSV. Le modifiche a singola cella si salvano
  regolarmente.
- I nomi delle funzioni restano in inglese (`SUM`, non `SOMMA`), perché fanno
  parte della sintassi delle formule.
- Il gateway gestisce utenti locali. L'aggancio a SPID/CIE o a un provider OIDC
  non è implementato.
- La condivisione di un foglio tra più utenti non è implementata: un foglio ha
  un solo proprietario, riassegnabile dall'amministratore.

## Licenza

EUPL-1.2, vedi `LICENSE.md`. Il progetto non include né modifica il codice di
EtherCalc, distribuito separatamente dai suoi autori sotto la propria licenza.

## Sicurezza

Non versionare mai `.env`, `gateway-data/`, `ethercalc-data/` e gli archivi di
backup: contengono la chiave di scrittura, le password e i dati. Il
`.gitignore` li esclude già.
