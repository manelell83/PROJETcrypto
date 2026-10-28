# TP — Canary Q-Day : ML-KEM, canaris et réponse à incident

> **À lire avant de commencer.**
> - L'implémentation ML-KEM de ce TP est un **objet d'étude** en Python pur. Elle n'est **pas à temps constant** et **ne doit pas servir en production**.
> - L'étape « attaquant » (partie 5) est une **simulation**. Aucune attaque cryptanalytique n'est réalisée : le « cassage » est remplacé par un *oracle de laboratoire* (voir `docs/m8-status.md`). Ce TP ne montre **pas** que ML-KEM ou X-Wing sont affaiblis. Il montre comment un système détecte l'**utilisation** d'un secret volé et y répond.

## Objectifs pédagogiques

À la fin du TP, vous saurez :

1. vérifier une implémentation de ML-KEM (FIPS 203) contre les vecteurs officiels du NIST, et expliquer ce que ce test prouve et ne prouve pas ;
2. décrire la structure d'un KEM de type Kyber (Module-LWE, K-PKE, transformation de Fujisaki-Okamoto avec rejet implicite) et le rôle des paramètres (n, k, η, du, dv) ;
3. expliquer un KEM hybride (X-Wing) et ce que son combineur lie ;
4. comprendre un canal chiffré qui lie le profil cryptographique à la dérivation de clés (anti-*downgrade*) ;
5. suivre une chaîne de détection : piège (*canary*) → événement → SIEM → alerte signée → réponse automatisée ;
6. distinguer ce qu'une réponse à incident peut neutraliser de ce qui est **irrécupérable** ;
7. lire des résultats de tests et de mesures (taux d'échec de déchiffrement) avec un esprit critique : ce qui est mesuré, ce qui est simulé, ce qui reste à vérifier.

**Notions abordées :** Module-LWE, NTT, distribution binomiale centrée, compression, transformation FO, KEM hybride, HKDF, AEAD et nonces, *downgrade* et rejeu, canaris (*honeytokens*), SIEM, authentification de webhook (HMAC), politique de réponse, *dry-run*, idempotence, exposition et rotation de secrets.

## Prérequis

- Python ≥ 3.12 (le TP a été exécuté avec Python 3.13.4 sous Windows 11).
- Git. Docker n'est **pas** nécessaire pour ce TP.
- Environ 1 Go d'espace disque libre. Les ports locaux 8081, 8088, 8090 et 9443 doivent être libres.
- Notions : arithmétique modulaire, polynômes, chiffrement authentifié, HTTP.

Toutes les commandes se lancent **depuis la racine du projet**. Sous Windows, `python` désigne l'interpréteur de votre système pour l'installation ; ensuite, `tools/run.py` utilise automatiquement `.venv`.

---

## Partie 0 — Installation (≈ 5 min)

```bash
python tools/run.py setup
```

**Résultat attendu :** un dossier `.venv/` est créé et la dernière ligne de pip indique `Successfully installed ... canary-qday-0.1.0 ...`.

**Vérification :**

```bash
python tools/run.py
```

La commande affiche la liste des cibles (`setup lint test kat check-vectors lab-up lab-down gen demo scenario exp audit`) et se termine avec le code 2 (aucune cible donnée), ce qui est normal.

---

## Partie 0.1 — Arborescence et configuration (≈ 5 min)

```
PROJEThanin/
├─ src/canary_qday/
│  ├─ kem/        ML-KEM (FIPS 203) et profils jouets — bibliothèque standard uniquement
│  ├─ hybrid/     X-Wing (brouillon -11) et combineur « à la TLS » (comparaison)
│  ├─ channel/    trames, handshake KEM, HKDF, ChaCha20-Poly1305
│  ├─ traffic/    générateur, pièges, registre, oracle de labo (simulation)
│  ├─ services/   proxy, services backend factices, serveur canary
│  ├─ siem/       interface SiemSink, sink fichier, sink Splunk HEC, SIEM mock
│  ├─ response/   webhook, politique, exposition, actions, rapport
│  └─ common/     erreurs, configuration, journaux masqués, registre SQLite
├─ lab/attacker/guard.py          garde-fous de laboratoire
├─ lab/scenario/simulated_attacker.py   scénario d'attaquant SIMULÉ
├─ experiments/runners/e4_dfr.py  mesure du taux d'échec de déchiffrement
├─ tools/run.py                   lanceur de tâches (remplace make)
├─ tools/lab.py                   démarrage/arrêt des services locaux
├─ tools/check_vectors.py         vérification des vecteurs officiels
├─ tests/                         unit/, security/, e2e/ (pytest)
├─ vectors/                       vecteurs NIST ACVP et X-Wing + provenance
├─ siem/splunk/                   configuration Splunk (NON testée en conditions réelles)
└─ docs/                          documentation technique (EN) et ce guide
```

**Configuration.** Tout passe par des variables d'environnement `CQ_*` (voir `src/canary_qday/common/config.py` et `.env.example`). Pour ce TP, vous n'avez **rien à configurer** : `tools/lab.py` fixe les variables, génère des secrets de laboratoire aléatoires dans `var/demo/secrets/` et les transmet par fichiers (`CQ_*_FILE`). Le dossier `var/` n'est pas versionné.

| Variable | Rôle | Valeur dans le labo |
|---|---|---|
| `CQ_DATA_DIR` | dossier des données (registre, politique, rapports, journaux) | `var/demo` |
| `CQ_SIEM_SINK` | `file` ou `hec` | `hec` (vers le SIEM mock) |
| `CQ_APPLY` | `1` = exécuter les actions ; sinon **dry-run** | `0`, puis `1` à l'étape 4b |
| `CQ_LAB`, `CQ_LAB_SIM` | autorisent le scénario simulé | positionnées par `tools/run.py demo` |

---

## Partie 0.2 — Tests automatisés et qualité du code (≈ 5 min)

```bash
python tools/run.py test
```

**Résultat attendu** (exécution de référence du 2026-10-28) : `90 passed, 1 warning`, en ≈ 45 s. L'avertissement provient de FastAPI/Starlette (`StarletteDeprecationWarning` sur `httpx`) et non du projet. Le test `tests/e2e/test_simulated_scenario.py` démarre de vrais processus locaux sur les ports 8281, 8288, 8290 et 9643 (décalage de 200).

| Dossier | Ce qui est testé |
|---|---|
| `tests/unit/test_response_policy.py` | matrice de politique RED/ORANGE/GREEN, jeton non fiable, `--auto-lab` |
| `tests/unit/test_response_engine.py` | exposition (vérité terrain synthétique), rotation, idempotence, dry-run octet pour octet, limitation de débit, approbations |
| `tests/unit/test_siem_and_services.py` | pièges, registre sans secret en clair, canary (réponses identiques), services backend, oracle (jamais GREEN), SIEM mock (règle, signature, HTTP) |
| `tests/unit/test_proxy_inprocess.py` | proxy et vrai générateur dans le même processus : flux RED/ORANGE/GREEN, profil interdit, clé révoquée, rechargement de la politique, IP bloquée, service arrêté, trames malformées |
| `tests/unit/test_config_and_factories.py` | configuration par variables d'environnement, secrets par fichier, fabriques des services (`app_from_env`) et leurs cas d'erreur |
| `tests/security/test_webhook.py` | HMAC, fraîcheur, rejeu, schéma strict, taille, limitation de débit, jeton admin, mode « secret dans l'URL » |
| `tests/security/test_guard_and_redaction.py` | garde-fous, masquage des journaux, sink HEC (pas de jeton affiché, tampon disque), fichiers secrets |
| `tests/e2e/test_simulated_scenario.py` | scénario complet (21 vérifications) et absence de `FAKE-` dans les journaux, événements et rapports |

Pour lancer seulement une partie :

```bash
.venv/Scripts/python -m pytest tests/unit -q
```

Sous Linux et macOS, l'interpréteur est `.venv/bin/python`.

Qualité du code :

```bash
python tools/run.py lint
```

**Attendu :** `All checks passed!` (ruff) puis `Success: no issues found in 51 source files` (mypy `--strict` sur `src/`).

> Le cœur cryptographique est vérifié par les vecteurs officiels (partie 1), par le scénario de bout en bout et, indirectement, par les tests du proxy. Les tests unitaires dédiés (NTT, codecs, trames altérées) ne font **pas** partie de cette livraison (voir `docs/test-results.md`).

Couverture mesurée : `.venv/Scripts/python -m pytest tests --cov=canary_qday --cov-precision=2` donne **88,23 %** au total lors de l'exécution de référence.

---

## Partie 1 — ML-KEM face aux vecteurs officiels (≈ 10 min)

### 1.1 Lancer la vérification

```bash
python tools/run.py check-vectors
```

**Résultat attendu** (mesuré le 2026-10-28) : une ligne par jeu de paramètres et par fonction, toutes à `0 fail`, puis :

```
TOTAL 243/243 vectors match
```

Ce total se décompose ainsi :
- 75 cas `keyGen` ;
- 135 cas `encapDecap` : encapsulation, décapsulation, et vérifications des clés de FIPS 203 §7.2–7.3 ;
- 3 cas X-Wing.

La provenance et l'empreinte SHA-256 de chaque fichier sont dans `vectors/README.md`.

### 1.2 Vérifier l'intégrité des vecteurs

```bash
sha256sum vectors/acvp/*/internalProjection.json vectors/xwing/*.txt
```

Comparez les empreintes avec celles de `vectors/README.md`. Sous PowerShell : `Get-FileHash -Algorithm SHA256 <fichier>`.

### 1.3 Explorer les tailles et le rejet implicite

```bash
.venv/Scripts/python -c "from canary_qday.kem.params import STANDARD; [print(p.name, p.ek_bytes, p.dk_bytes, p.ct_bytes) for p in STANDARD.values()]"
```

**Attendu :** `ML-KEM-512 800 1632 768`, `ML-KEM-768 1184 2400 1088`, `ML-KEM-1024 1568 3168 1568` (FIPS 203, tableau 3).

```bash
.venv/Scripts/python -c "from canary_qday.kem import kem; from canary_qday.kem.params import ML_KEM_768 as p; ek,dk=kem.keygen(p); ss,ct=kem.encaps(p,ek); bad=bytes([ct[0]^1])+ct[1:]; print('ok:', kem.decaps(p,dk,ct)==ss, '| ct modifié -> même clé ?', kem.decaps(p,dk,bad)==ss)"
```

**Attendu :** `ok: True | ct modifié -> même clé ? False`. Un chiffré modifié ne produit pas d'erreur : il produit une clé pseudo-aléatoire. C'est le **rejet implicite**.

### Questions — partie 1

1. Pourquoi des vecteurs de test qui passent ne prouvent-ils **pas** que l'implémentation est sûre ? (Pensez aux canaux auxiliaires : ce code n'est pas à temps constant.)
2. Dans `Decaps`, pourquoi renvoyer `J(z‖c)` plutôt qu'une erreur quand le chiffré est invalide ? Quelle attaque cela empêche-t-il ?
3. Les vecteurs « encapsulationKeyCheck » contiennent des clés rejetées. Quelle propriété de l'encodage la vérification de modulus contrôle-t-elle (`src/canary_qday/kem/kem.py`, fonction `check_ek`) ?

---

## Partie 2 — Profils cryptographiques et canal (≈ 15 min)

Le laboratoire utilise trois profils :

| Profil | KEM | Rôle |
|---|---|---|
| `RED` | Kyber « jouet » n=64, k=1 (multiplication naïve) | volontairement faible |
| `ORANGE` | Kyber « jouet » n=64, k=2 | faible, un peu plus coûteux |
| `GREEN` | X-Wing = X25519 + ML-KEM-768 | standard ; jamais attaqué dans ce TP |

> Les paramètres jouets sont **provisoires**. Ils n'ont pas encore été calibrés par mesure du coût d'attaque (voir `docs/decisions.md`, OPEN 3).

### 2.1 Comparer les tailles

```bash
.venv/Scripts/python -c "from canary_qday.kem.profiles import PROFILE_PARAMS as P; [print(k, v.name, 'ek', v.ek_bytes, 'ct', v.ct_bytes) for k,v in P.items()]"
```

**Attendu :**
- `RED toy-n64-k1 ek 128 ct 112`
- `ORANGE toy-n64-k2 ek 224 ct 192`
- `GREEN ML-KEM-768 ek 1184 ct 1088`

Avec X-Wing, le profil GREEN transporte en pratique 1216 octets de clé publique et 1120 octets de chiffré.

### 2.2 Lire le handshake

Ouvrez `src/canary_qday/channel/handshake.py` et repérez :
- le message `HELLO` : profil, époque, `key_id`, `stream_id`, chiffré KEM ;
- la clé de session `K = HKDF(ss, info = "canary-qday/v1" ‖ profile_id ‖ H(transcript))` ;
- les nonces ChaCha20-Poly1305 = compteur de 64 bits par direction.

### 2.3 Expérience E4 : mesurer le taux d'échec de déchiffrement (≈ 3 min)

Un KEM de type Kyber peut, avec une faible probabilité, échouer à déchiffrer. La clé décapsulée diffère alors de la clé encapsulée, et le rejet implicite masque l'erreur. Ce taux (DFR) dépend de n, k, η et surtout de la compression (du, dv).

```bash
python tools/run.py exp e4 2000
```

Le script essaie chaque candidat jouet 2000 fois (200 fois pour les deux témoins négatifs `du4dv2`), avec des **graines déterministes réservées à l'expérience**. Il écrit dans `experiments/results/e4/<horodatage>/` :
- `config.yaml` ;
- `raw.jsonl` (un essai par ligne) ;
- `env.json` ;
- `summary.csv` ;
- `fig.png`.

**Résultats attendus** (exécution de référence du 2026-10-28 ; détail dans `docs/calibration.md`). Durée ≈ 2,5 min.

| Candidat | Essais | Échecs | Borne sup. 95 % | Seuil 10⁻³ atteint ? |
|---|---|---|---|---|
| toy-n64-k1 (RED), toy-n64-k2 (ORANGE), toy-n64-k3, toy-n128-k2 | 2000 chacun | 0 | 1,5 × 10⁻³ | non (`meets_threshold = False` : pas assez d'essais) |
| toy-n64-k1-du4dv2, toy-n64-k2-du4dv2 (témoins) | 200 chacun | 200 | 1 | non |

Avec 5000 essais (`python tools/run.py exp e4 5000`, ≈ 6 à 7 min), les quatre candidats `du = 10, dv = 4` restent à 0 échec et leur borne descend à 6 × 10⁻⁴ : ils franchissent alors le seuil. Les graines étant fixées, vous devez retrouver **exactement** les mêmes nombres d'échecs. Les durées, elles, dépendent de votre machine.

**Comment interpréter.** Avec 0 échec sur N essais, on ne peut **pas** conclure que la DFR est nulle. On peut seulement borner : DFR < 3/N à 95 % (« règle de trois »), soit 1,5 × 10⁻³ pour N = 2000. Le seuil d'acceptation documenté est une borne supérieure à 95 % **inférieure à 10⁻³**. Il faut donc au moins 3000 essais sans échec pour qu'un candidat le franchisse. Pour les vrais paramètres ML-KEM, la DFR vaut 2⁻¹³⁹ (512), 2⁻¹⁶⁴ (768) et 2⁻¹⁷⁴ (1024) d'après FIPS 203, tableau 1 : elle ne se mesure pas, elle se calcule.

### Questions — partie 2

4. Si un intermédiaire remplace l'identifiant de profil `GREEN` par `RED` dans le `HELLO`, que se passe-t-il ? Citez **deux** mécanismes du code qui l'empêchent.
5. Pourquoi le combineur X-Wing hache-t-il aussi `ct_X` et `pk_X`, et pas seulement les deux secrets partagés ?
6. Pourquoi garde-t-on n ≥ 64 pour les profils jouets, même si on veut qu'ils soient faibles ? (Indice : taille du message chiffré par K-PKE.)

---

## Partie 3 — Démarrer le laboratoire et générer du trafic (≈ 10 min)

### 3.1 Démarrer

```bash
python tools/run.py lab-up
```

Quatre processus démarrent sur `127.0.0.1` :

| Service | Port | Rôle |
|---|---|---|
| mock SIEM | 8088 | collecteur compatible HEC, règle d'alerte, webhook signé |
| moteur de réponse | 8090 | reçoit les alertes ; **dry-run** par défaut |
| serveur canary | 8081 | `GET /t/<token>` |
| proxy | 9443 | termine le canal KEM et relaie vers les services backend |

**Attendu :** `lab up: {'mock-siem': ..., 'response': ..., 'canary': ..., 'proxy': ...}`. Les journaux sont dans `var/demo/logs/`.

> Si vous avez **déjà lancé la démo** (partie 5), son fichier `var/demo/policy.json` a retiré RED de la liste autorisée. Dans ce cas, `gen RED` est refusé (`stream refused ... PolicyError`). Arrêtez le labo, supprimez le dossier `var/demo`, puis relancez `lab-up`.

### 3.2 Générer quelques flux

```bash
python tools/run.py gen RED 2
```

```bash
python tools/run.py gen GREEN 1
```

**Attendu :** un JSON par flux avec `"responses": [200, 200]`. Le premier démarrage d'un profil prend quelques secondes : c'est la génération de la clé du serveur, en Python pur.

### 3.3 Observer ce qui est visible

```bash
.venv/Scripts/python -c "import json; [print(e['event']['profile'], e['event']['key_id'], e['event']['outcome']) for e in map(json.loads, open('var/demo/siem/events.jsonl')) if e['event'].get('event')=='handshake']"
```

**Attendu :** une ligne par handshake (`RED <key_id> accepted`, …). Ces métadonnées sont **publiques**. Elles ne contiennent ni le contenu des messages, ni les identifiants, ni les tokens.

### 3.4 Arrêter

```bash
python tools/run.py lab-down
```

---

## Partie 4 — Le serveur canary n'est pas un oracle (≈ 5 min)

Relancez le labo (`python tools/run.py lab-up`), puis :

```bash
curl -s -i http://127.0.0.1:8081/t/00000000000000000000000000000000
```

```bash
curl -s -i http://127.0.0.1:8081/t/pas-un-token
```

**Attendu :** les deux réponses sont **identiques** (`200`, même corps « This password reset link has expired… »). La réponse est la même pour un token valide. Seul un token enregistré provoque un événement, émis *après* l'envoi de la réponse.

### Questions — partie 4

7. Que pourrait apprendre un attaquant si le serveur répondait 404 aux tokens inconnus et 200 aux tokens valides ?
8. Le journal du serveur canary contient `token_id` et non le token. Pourquoi ? (Voir `src/canary_qday/common/redact.py`.)

Arrêtez le labo : `python tools/run.py lab-down`.

---

## Partie 5 — Scénario d'attaquant **simulé** (≈ 15 min)

### 5.1 Ce qui est simulé, et ce qui ne l'est pas

| Étape | Nature |
|---|---|
| « Casser » la clé RED et lire le contenu d'un flux | **SIMULÉ** : lecture d'un enregistrement d'*oracle de laboratoire* écrit par le générateur (`CQ_LAB_SIM=1`), uniquement pour RED et ORANGE |
| Réutiliser un identifiant volé, utiliser le piège, détection, alerte, réponse, confinement | **RÉEL** : code du projet, services lancés localement, SIEM *mock* |

Le *guard* (`lab/attacker/guard.py`) est appelé avant chaque action d'attaquant. Il exige `CQ_LAB=1`, n'accepte que les profils jouets et que des hôtes du laboratoire.

### 5.2 Lancer le scénario

```bash
python tools/run.py demo --keep
```

Le scénario repart d'un dossier `var/demo` neuf, démarre le labo, génère 2 flux RED, 1 ORANGE et 1 GREEN, puis enchaîne les étapes ci-dessous. Avec `--keep`, le labo reste démarré à la fin pour vous laisser inspecter. Durée mesurée : ≈ 30 s, dont ≈ 15 s de génération de clés au démarrage.

### 5.3 Résultats attendus, étape par étape

Ce sont les résultats observés lors de l'exécution de référence (2026-10-28). Les identifiants changent à chaque exécution.

| Étape | Ce qui se passe | Vérification affichée |
|---|---|---|
| 0 | Labo démarré, réponse en **DRY-RUN**, trafic généré | `[PASS] all generated requests accepted` |
| 1 | Observation passive : seuls les profils et `key_id` sont visibles | `[PASS] no alert after passive observation` |
| 2 | Bannière `SIMULATED BREAK - no cryptanalysis performed` | aucune (étape simulée) |
| 3 | L'attaquant ouvre **son propre** canal (GREEN) et présente l'identifiant volé | `http_status: 200`, `[PASS] credential accepted before any response` |
| 4a | L'attaquant ouvre le lien piège → canary → mock SIEM → webhook signé → réponse | rapport produit, `dry_run`, registre et `policy.json` **identiques octet pour octet**, `firewall_block` et `service_stop` en attente d'approbation |
| C | Cas témoins | token inconnu : réponse identique et aucune alerte ; alerte forgée : 401 ; alerte rejouée : 202 puis 409 ; *guard* qui refuse GREEN |
| 4b | Moteur de réponse redémarré avec `--apply`, second piège RED utilisé | `[PASS] applied report produced` |
| 5 | Confinement | `allowed_profiles: ['ORANGE', 'GREEN']`, clé RED révoquée, époque RED = 2, `rotated_secrets: 8` |
| 6 | L'attaquant réessaie | identifiant volé : **401** ; nouveau flux RED : `E_POLICY` ; trafic GREEN : `[200, 200]` |

Ligne finale attendue :

```
RESULT: 21/21 checks passed -> OK
```

### 5.4 Observer par vous-même

Gardez le labo démarré (`--keep`) et inspectez :

```bash
ls var/demo/reports/
```

Ouvrez le rapport `.md` le plus récent : il est rédigé en anglais. Repérez les sections **Irrecoverable** et **Neutralised**.

```bash
cat var/demo/policy.json
```

```bash
cat var/demo/scenario-summary.json
```

Le second fichier contient le journal horodaté des étapes (`t_s`) et la liste des vérifications.

```bash
grep -c "FAKE-" var/demo/logs/*.log var/demo/siem/*.jsonl var/demo/reports/*
```

**Attendu :** `0` partout. Aucun identifiant factice ne fuit dans les journaux, les événements ou les rapports.

Arrêtez ensuite le labo :

```bash
python tools/run.py lab-down
```

### Questions — partie 5

9. À l'étape 1, aucune alerte n'est levée. Expliquez pourquoi un *canary* **ne peut pas** détecter la collecte passive de trafic (« harvest now, decrypt later »).
10. Le rapport distingue l'exposition « key-level » et l'exposition « algorithmic ». Donnez un exemple où les deux ensembles diffèrent.
11. Pourquoi la rotation rend-elle l'identifiant volé inutilisable (étape 6), alors que les données déjà lues par l'attaquant restent perdues ?
12. Pourquoi `firewall_block` et `service_stop` attendent-ils une approbation humaine, même pour RED ?
13. Pourquoi l'alerte forgée est-elle rejetée avant même d'être analysée ? Et pourquoi une alerte valide rejouée est-elle rejetée ? Quels champs du code de `response/auth.py` et `response/engine.py` interviennent ?
14. Que démontre ce scénario, et que **ne démontre-t-il pas**, sur la sécurité des profils RED et ORANGE ? (Relisez `docs/m8-status.md`.)

---

## Partie 5bis — Le SIEM mock et les limites de l'intégration Splunk (≈ 10 min)

### Ce que fait le SIEM mock

`src/canary_qday/siem/mock_hec.py` **n'est pas Splunk**. Il reproduit seulement le contrat sur lequel le projet s'appuie :

1. un point d'entrée compatible HEC, `POST /services/collector/event`, avec l'en-tête `Authorization: Splunk <jeton>` comparé en temps constant ;
2. une règle de corrélation : `event = trap_triggered`, au plus une alerte par `token_id` toutes les 60 s ;
3. un webhook vers le moteur de réponse, **signé** par HMAC-SHA256 (en-têtes `X-Timestamp` et `X-Signature`).

Pendant la démo, il stocke chaque événement reçu dans `var/demo/siem/events.jsonl` et expose les alertes émises sur `GET /alerts`. Avec le labo démarré (`python tools/run.py lab-up`) :

```bash
curl -s http://127.0.0.1:8088/alerts
```

**Attendu :** `[]` tant qu'aucun piège n'a été utilisé. Sinon, une liste de `{"alert_id": ..., "fired_at": ...}`.

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8088/services/collector/event -d "{}"
```

Sous PowerShell : `curl.exe -s -o NUL -w "%{http_code}" -X POST http://127.0.0.1:8088/services/collector/event -d "{}"`.

**Attendu :** `401`, car aucun jeton HEC n'est fourni.

### Ce qui n'est PAS testé : Splunk réel

| Élément | Fichier | Statut |
|---|---|---|
| Sink HEC (envoi, tampon disque si le SIEM est indisponible) | `src/canary_qday/siem/splunk_hec.py` | testé contre un point d'accès **injoignable** (mise en tampon, jeton jamais affiché), **jamais** contre un vrai Splunk |
| Type de source, règle d'alerte | `siem/splunk/props.conf`, `siem/splunk/savedsearches.conf` | **non testés** |
| Webhook natif Splunk vers le moteur de réponse | — | **ne fonctionnera pas tel quel** : Splunk envoie son propre format JSON (`sid`, `result`, …), alors que le moteur attend le schéma `Alert`. Un adaptateur est nécessaire et **n'est pas implémenté**. |

Le webhook natif de Splunk ne permet pas d'ajouter un en-tête de signature (seul `param.user_agent` est documenté). C'est pourquoi le moteur propose aussi le mode `SharedSecretPath` (secret dans l'URL, à combiner avec l'isolement réseau). La liste de contrôle pour un futur test réel est dans `siem/splunk/README.md`.

### Questions — partie 5bis

15. Pourquoi la règle limite-t-elle les alertes à une par `token_id` et par minute ? Que se passerait-il sans cette limite, côté moteur de réponse ?
16. Comparez `HmacHeader` et `SharedSecretPath` : contre quelle menace chacun protège-t-il, et laquelle reste ouverte avec le secret dans l'URL ?
17. Pourquoi un test réussi avec le SIEM mock ne prouve-t-il **pas** que l'intégration Splunk fonctionne ?

---

## Partie 6 — Bilan : ce qui a été vérifié

| Élément | Statut lors de l'exécution de référence (2026-10-28) |
|---|---|
| Vecteurs ACVP (240) et X-Wing (3) | vérifiés : 243/243 |
| Suite pytest (unitaires, sécurité, e2e) | 90 réussis, 1 avertissement tiers |
| Scénario simulé de bout en bout (SIEM mock) | vérifié : 21/21 |
| Absence d'identifiants factices dans les journaux | vérifiée par le test e2e et par grep |
| ruff, mypy `--strict` (`src/`), bandit | propres (constats bandit justifiés, voir `docs/test-results.md`) |
| E4 : taux d'échec de déchiffrement | mesuré (voir partie 2.3 et `docs/calibration.md`) |
| Couverture de code | 88,23 % au total : seuil de 80 % atteint ; `response` ≈ 95 % ; `kem` (≈ 85 %) et `channel` (≈ 88 %) **sous** leur cible de 90 % |
| Attaque réelle sur les profils jouets (M8, E3) | **non livrée** |
| Calibrage par lattice-estimator | **non fait** (Docker indisponible) : paramètres provisoires |
| Intégration avec un vrai Splunk | **non testée** ; adaptateur de webhook manquant |
| Interopérabilité à grande échelle (1000 échanges) | **non faite** : 20 échanges avec OpenSSL ont réussi |
| pip-audit, gitleaks, CI | **non exécutés** |

Le détail par exigence est dans `docs/status.md` ; les résultats bruts sont dans `docs/test-results.md`.

### Comment interpréter ces résultats

- **Un test qui passe** montre que le comportement correspond aux cas testés. Il ne prouve **pas** la sécurité cryptographique.
- **Une vérification « simulée »** (étape 2 du scénario) ne démontre rien sur la difficulté de casser RED ou ORANGE.
- **Une mesure** (E4) vaut pour cette machine, ce nombre d'essais et ces graines. Une absence d'échec se traduit par une **borne**, pas par une valeur nulle.
- **Un élément « non testé »** doit être considéré comme inconnu, pas comme fonctionnel.

---

## Limites scientifiques à retenir

1. **Le canary ne détecte pas la collecte passive.** Il détecte seulement l'**utilisation** d'un piège synthétique déchiffré. Un attaquant prudent peut ignorer les pièges.
2. **Le trafic synthétique** renseigne sur une classe de cryptographie, pas sur la capture effective de trafic réel.
3. **L'implémentation ML-KEM** est un objet d'étude : pas de temps constant, pas d'usage en production. Un déploiement réaliste du niveau GREEN doit utiliser une bibliothèque relue.
4. **Les profils jouets** sont volontairement faibles. Leur DFR est mesurée, mais leur **coût d'attaque ne l'est pas** (E3 et lattice-estimator différés). Le choix RED/ORANGE est donc **provisoire**.
5. **Le régime jouet** (petites dimensions) n'est pas le régime standard. Rien ne s'extrapole directement à ML-KEM-512/768/1024.
6. **L'étape « attaquant » est simulée.** Aucune cryptanalyse n'est implémentée, et rien dans ce TP ne suggère un affaiblissement de ML-KEM ou de X-Wing.
7. **Aucune revendication de nouveauté** n'est faite sans recherche bibliographique approfondie.

---

## Dépannage

| Symptôme | Cause probable | Solution |
|---|---|---|
| `RuntimeError: mock-siem did not start; see var/demo/logs/mock-siem.log` | port déjà utilisé (souvent un labo précédent encore démarré) | `python tools/run.py lab-down`, puis relancer. Sinon, `python -m lab.scenario.simulated_attacker --port-offset 100` décale tous les ports. |
| `GuardError: lab mode not enabled` | `CQ_LAB=1` absent (lancement direct du module) | passer par `python tools/run.py demo`, qui le positionne ; sinon `CQ_LAB=1 python -m lab.scenario.simulated_attacker` (sous PowerShell : `$env:CQ_LAB="1"`) |
| `ModuleNotFoundError: canary_qday` | `.venv` absent ou projet non installé | `python tools/run.py setup` |
| `E_POLICY` dès le premier flux RED | `var/demo/policy.json` d'une exécution précédente a désactivé RED | `python tools/run.py lab-down`, puis supprimer `var/demo`. La cible `demo` repart toujours d'un dossier neuf. |
| L'étape 4a ou 4b reste bloquée puis échoue (« incident report produced » en FAIL) | le webhook n'a pas atteint le moteur de réponse | consulter `var/demo/logs/mock-siem.log` (`webhook delivery failed`) et `var/demo/logs/response.log` |
| Première génération très lente | génération des clés en Python pur (X-Wing inclus) | normal : ≈ 15 s au premier démarrage |
| `No space left on device` | disque plein (les images Docker occupent souvent beaucoup d'espace) | libérer de l'espace ; ce TP n'a pas besoin d'images Docker |
| `sha256sum` introuvable sous PowerShell | outil absent | `Get-FileHash -Algorithm SHA256 <fichier>` |
| `curl` se comporte différemment sous PowerShell | `curl` y est un alias | utiliser `curl.exe` |
| Accents mal affichés (`modifi�`) dans les sorties `python -c` | encodage de la console Windows | sans effet sur le résultat ; pour un affichage correct : `$env:PYTHONUTF8="1"` (PowerShell) ou `set PYTHONUTF8=1` (cmd) |
| `python tools/run.py test` échoue sur l'e2e avec un port occupé | les ports 8281, 8288, 8290 et 9643 sont pris | libérer ces ports ou arrêter le processus qui les utilise ; les autres tests ne sont pas concernés |
| `PermissionError` dans `var/pytest-tmp` | un précédent pytest tient encore un fichier (Windows) | fermer les processus Python restants, puis supprimer `var/pytest-tmp` |
| `python tools/run.py audit` échoue sur pip-audit | pas d'accès réseau, ou disque système plein (cache) | non bloquant pour le TP ; relancer avec une connexion et de l'espace libre |
| `exp e4` très long | `toy-n128-k2` est le candidat le plus lent (Python pur) | réduire le nombre d'essais (`exp e4 500`) pour un essai rapide ; la borne à 95 % sera alors plus large |
| Plusieurs rapports dans `var/demo/reports/` après la démo | normal : 3 incidents (dry-run, alerte témoin du rejeu, `--apply`), chacun en `.json` et `.md` | le rapport de l'étape 4b est le plus récent |

---

## Pour aller plus loin (hors TP)

- Comparer le coût de ML-KEM-512/768/1024 dans l'implémentation Python et dans `cryptography` (expérience E2 : pas encore implémentée).
- Modifier `du`/`dv` d'un candidat dans `src/canary_qday/kem/profiles.py` (sur une copie de travail), relancer E4 et observer à partir de quand la DFR devient mesurable.
- Lire la section *Security Considerations* du brouillon X-Wing (`vectors/xwing/`).
