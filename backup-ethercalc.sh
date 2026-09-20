#!/bin/bash
# Backup giornaliero di EtherCalc e del gateway.
#
# Cosa salva:
#   - ethercalc-data : i fogli (file SQLite dei Durable Object)
#   - gateway-data   : utenti, proprieta' dei fogli, registro attivita'
#   - .env           : ETHERCALC_KEY, senza la quale i fogli restano
#                      leggibili ma nessun link di scrittura torna valido
#   - la configurazione nginx di CKAN che contiene il blocco /sheet
#
# Per ottenere una copia coerente dei file SQLite, EtherCalc viene fermato
# per la durata dell'archiviazione (pochi secondi) e riavviato subito dopo.
# Il gateway resta attivo: il suo database viene copiato con l'API di backup
# di SQLite, che è sicura anche a servizio acceso.

set -euo pipefail

PROGETTO="${PROGETTO:-/home/ubuntu/ethercalc/ethercalc}"
NGINX_CONF="${NGINX_CONF:-/etc/nginx/conf.d/default.conf}"
DESTINAZIONE="${DESTINAZIONE:-/home/ubuntu/backup/ethercalc}"
GIORNI_DA_TENERE="${GIORNI_DA_TENERE:-30}"
MINIMO_LIBERO_MB="${MINIMO_LIBERO_MB:-500}"

DATA="$(date +%Y-%m-%d_%H%M)"
LAVORO="$(mktemp -d)"
ARCHIVIO="$DESTINAZIONE/ethercalc_$DATA.tar.gz"
REGISTRO="$DESTINAZIONE/backup.log"
AVVIATO=0

messaggio() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$REGISTRO"; }

ripristina() {
    local esito=$?
    if [ "$AVVIATO" -eq 1 ]; then
        docker compose -f "$PROGETTO/docker-compose.proxy.yml" \
                       -f "$PROGETTO/docker-compose.gateway.yml" \
                       --project-directory "$PROGETTO" start ethercalc >/dev/null 2>&1 || \
            messaggio "ATTENZIONE: riavvio di ethercalc non riuscito, intervenire a mano"
    fi
    rm -rf "$LAVORO"
    [ "$esito" -ne 0 ] && messaggio "BACKUP FALLITO (codice $esito)"
    exit "$esito"
}
trap ripristina EXIT

mkdir -p "$DESTINAZIONE"
messaggio "avvio backup"

LIBERO_MB="$(df -Pm "$DESTINAZIONE" | awk 'NR==2 {print $4}')"
if [ "$LIBERO_MB" -lt "$MINIMO_LIBERO_MB" ]; then
    messaggio "spazio insufficiente: ${LIBERO_MB}MB liberi, minimo ${MINIMO_LIBERO_MB}MB"
    exit 1
fi

cd "$PROGETTO"

# 1. Database del gateway, a caldo: l'API di backup di SQLite produce una
#    copia coerente anche mentre il servizio scrive.
mkdir -p "$LAVORO/gateway-data"
if [ -f gateway-data/gateway.sqlite ]; then
    python3 - "$PWD/gateway-data/gateway.sqlite" "$LAVORO/gateway-data/gateway.sqlite" <<'PY'
import sqlite3, sys
origine = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True)
copia = sqlite3.connect(sys.argv[2])
with copia:
    origine.backup(copia)
copia.close(); origine.close()
PY
    messaggio "database del gateway copiato"
else
    messaggio "ATTENZIONE: gateway-data/gateway.sqlite non trovato"
fi

# 2. Fogli: EtherCalc fermo per il tempo della copia.
AVVIATO=1
docker compose stop ethercalc >/dev/null 2>&1
cp -a ethercalc-data "$LAVORO/ethercalc-data"
docker compose start ethercalc >/dev/null 2>&1
AVVIATO=0
messaggio "fogli copiati, ethercalc riavviato"

# 3. Configurazione: chiave, compose, blocco nginx.
mkdir -p "$LAVORO/config"
cp -a .env docker-compose.yml docker-compose.proxy.yml docker-compose.gateway.yml "$LAVORO/config/" 2>/dev/null || true
[ -f "$NGINX_CONF" ] && cp -a "$NGINX_CONF" "$LAVORO/config/nginx-ckan-default.conf"

tar czf "$ARCHIVIO" -C "$LAVORO" .
chmod 600 "$ARCHIVIO"
DIMENSIONE="$(du -h "$ARCHIVIO" | cut -f1)"

# 4. Verifica che l'archivio sia leggibile e contenga il database del gateway.
#    L'elenco viene raccolto in una variabile invece che passato a una pipe:
#    `grep -q` chiuderebbe la pipe al primo risultato e, con `pipefail`, tar
#    riceverebbe SIGPIPE facendo fallire il controllo su archivi grandi.
if ! CONTENUTO="$(tar tzf "$ARCHIVIO" 2>/dev/null)"; then
    messaggio "archivio illeggibile: $ARCHIVIO"
    exit 1
fi
case "$CONTENUTO" in
    *gateway-data/gateway.sqlite*) ;;
    *) messaggio "ATTENZIONE: nell'archivio manca il database del gateway" ;;
esac

# 5. Rotazione.
RIMOSSI="$(find "$DESTINAZIONE" -maxdepth 1 -name 'ethercalc_*.tar.gz' -mtime "+$GIORNI_DA_TENERE" -print -delete | wc -l)"
RIMASTI="$(find "$DESTINAZIONE" -maxdepth 1 -name 'ethercalc_*.tar.gz' | wc -l)"

messaggio "completato: $ARCHIVIO ($DIMENSIONE) — archivi rimossi: $RIMOSSI, presenti: $RIMASTI"
