# Contributi

Segnalazioni e proposte sono benvenute tramite issue e pull request.

Prima di aprire una pull request:

- esegui i test della politica di accesso, che sono la parte critica:

  ```bash
  cd gateway
  GW_PREFIX=/sheet python -m pytest -q test_policy.py
  python -m pytest -q test_policy.py
  ```

- verifica la configurazione nginx con `nginx -t` prima di proporla;
- non includere mai `.env`, database o archivi di backup.

Ogni modifica alla politica di accesso in `app.py` deve essere accompagnata da
un test corrispondente: e' il punto in cui un errore espone i dati.
