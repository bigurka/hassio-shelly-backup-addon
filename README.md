# Shelly Backup/Restore Add-on (scaffold)

### Installazione
1. Copia la cartella nell'add-on folder del tuo Home Assistant custom repository.
2. Builda l'add-on da Supervisor > Add-on store > Repositories (aggiungi repo se serve) e avvia.
3. Configura `subnet` e `http_port` nelle opzioni dell'add-on.

### Endpoints principali
- `GET /scan` - scansiona la subnet configurata
- `POST /backup` - {"ips": ["192.168.x.y"]}
- `POST /backup_all` - esegue backup su tutti i device trovati
- `GET /backups` - lista file di backup
- `POST /restore` - form-data (file, target_ip)
- `POST /restore_specific` - restore avanzato con mappatura per device (gen1/gen2)

### Note
- Questo scaffold è un punto di partenza: per produzione aggiungere autenticazione, gestione delle credenziali, preview/diff prima di restore e mapping per conversione Gen1->Gen2.
