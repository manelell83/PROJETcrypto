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
6. distinguer ce qu'une réponse à incident peut neutraliser de ce qui est **irrécupérable**.

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

La commande affiche la liste des cibles (`setup lint test kat check-vectors lab-up lab-down gen demo scenario audit`) et se termine avec le code 2 (aucune cible donnée), ce qui est normal.

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

## Partie 6 — Bilan : ce qui a été vérifié

| Élément | Statut lors de l'exécution de référence |
|---|---|
| Vecteurs ACVP (240) et X-Wing (3) | vérifiés : 243/243 |
| Scénario simulé de bout en bout (mock SIEM) | vérifié : 21/21 |
| Absence d'identifiants factices dans les journaux | vérifiée manuellement (grep) |
| Suite pytest, CI, couverture | **non faites** |
| Attaque réelle sur les profils jouets (M8, E3) | **non livrée** |
| Calibrage des paramètres jouets (E4, lattice-estimator) | **non fait** : paramètres provisoires |
| Intégration avec un vrai Splunk | **non testée** |
| Interopérabilité à grande échelle (1000 échanges) | **non faite** : 20 échanges avec OpenSSL ont réussi |

Le détail par exigence est dans `docs/status.md`.

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
| Plusieurs rapports dans `var/demo/reports/` après la démo | normal : 3 incidents (dry-run, alerte témoin du rejeu, `--apply`), chacun en `.json` et `.md` | le rapport de l'étape 4b est le plus récent |

---

## Pour aller plus loin (hors TP)

- Comparer le coût de ML-KEM-512/768/1024 dans l'implémentation Python et dans `cryptography` (expérience E2 : pas encore implémentée).
- Mesurer le taux d'échec de déchiffrement des profils jouets et comparer les variantes `du4dv2` (expérience E4).
- Lire la section *Security Considerations* du brouillon X-Wing (`vectors/xwing/`).
