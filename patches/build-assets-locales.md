# Aggiungere l'italiano alle lingue incluse nella build

EtherCalc copia in `assets/` solo le lingue elencate esplicitamente in
`scripts/build-assets.ts`. Senza questa modifica i file `l10n/it*.json`
restano nel repository ma il server risponde 404 e l'interfaccia resta
in inglese.

Riga da modificare (numero indicativo: 20):

```ts
// prima
export const REQUIRED_LOCALES = ['en', 'de', 'es-ES', 'fr', 'ru-RU', 'zh-CN', 'zh-TW'] as const;

// dopo
export const REQUIRED_LOCALES = ['en', 'de', 'es-ES', 'fr', 'it', 'it-IT'] as const;
```

Le lingue non elencate non vengono servite: toglierle riduce la dimensione
dell'immagine e non ha altri effetti, se non che un browser impostato su
quella lingua vedra' l'inglese.

Comando equivalente:

```bash
sed -i "s/\['en', 'de', 'es-ES', 'fr', 'ru-RU', 'zh-CN', 'zh-TW'\]/['en', 'de', 'es-ES', 'fr', 'it', 'it-IT']/" scripts/build-assets.ts
```

Dopo la modifica serve `docker compose up -d --build ethercalc`.
