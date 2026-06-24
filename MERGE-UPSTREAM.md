# Rattraper l'amont sslh (yrutschle/sslh)

État établi le 23/06/2026.

## Situation

- **Fork** : `smarrazzo/ssl2shell`, modifications redteam (rvshell / redirection reverse-shell, AES, ordre de probing).
- **Point de fork** : commit `842f6b0` — *"Add mention of QUIC example (fix #376)"*, 19/02/2023 (≈ sslh **v2.0**).
- **Travail redteam** : 9 commits au-dessus du point de fork (`5a18774 add rvshell` → `486016d add switch to disable auto redirect reverseshell`).
- **Amont actuel** : **v2.3.1**. ~3 ans de commits à rattraper.

Le remote `upstream` est déjà configuré dans ton dépôt :
`upstream = https://github.com/yrutschle/sslh.git`

## Ce que la partie redteam touche (= surface de conflit)

Seulement 7 fichiers modifiés entre `842f6b0` et `HEAD` :

| Fichier | +/- | Nature | Risque de conflit |
|---|---|---|---|
| `probe.c` | +131 | **cœur logique** (rvshell, ordre/regex de probing) | **Élevé** — fichier très modifié en amont |
| `sslhconf.cfg` | +14 | schéma de conf (source) | Moyen |
| `Makefile` | +16 | build (AES, etc.) | Moyen |
| `sslh.pod` | ±491 | doc (man) | Faible (cosmétique) |
| `sslh-main.c` | -1 | une ligne | Faible |
| `sslh-conf.c` / `sslh-conf.h` | générés | **généré par conf2struct** | À **régénérer**, ne pas merger à la main |

Bonne nouvelle : la surface réelle est petite. Le seul vrai point chaud est `probe.c`.

## Sécurité — à prendre en compte pendant le merge

Une revue de sécurité OpenSUSE (13/06/2025) a révélé des DoS distants, dont deux CVE corrigés en amont :

- **CVE-2025-46806** — accès mémoire mal alignés dans `is_openvpn_protocol()` → **dans `probe.c`**, donc en plein dans ton fichier de conflit. À réconcilier soigneusement avec tes modifs de probing.
- **CVE-2025-46807** — épuisement de descripteurs de fichiers dans `sslh-select` et `sslh-ev`.

Autres apports notables depuis v2.0 : support UDP dans `sslh-select`, sonde syslog, support Landlock LSM, `max_connections` par `listen`/`protocol`, proxyprotocol en entrée, fuite mémoire de la sonde regex corrigée.

## Avant de merger : régler les fins de ligne (CRLF)

Ton arbre de travail a **tous les fichiers en CRLF** alors que les blobs Git sont en LF (≈ 20 990 lignes vues comme modifiées, mais ce ne sont **pas** de vraies modifs — uniquement l'EOL). Si tu fais `git add -A` en l'état, tu committes du CRLF partout et le merge devient ingérable.

Corrige d'abord (PowerShell/terminal dans le dépôt) :

```sh
# 1) Vérifier que ces "modifs" sont bien uniquement des fins de ligne
git diff --ignore-all-space --stat   # doit être quasiment vide

# 2) Normaliser et nettoyer l'arbre de travail (les changements EOL ne sont pas réels)
git config core.autocrlf input
git checkout -- .
git status                            # doit être "clean"
```

(Optionnel mais recommandé : ajouter un `.gitattributes` avec `* text=auto eol=lf` pour figer le comportement.)

## Procédure de merge (dans ton propre terminal)

À exécuter localement — github n'est pas joignable depuis l'environnement Cowork.

```sh
# Sauvegarde
git branch backup/avant-merge-upstream

# Récupérer l'amont
git fetch upstream --tags

# Voir l'écart
git merge-base HEAD upstream/master          # doit afficher 842f6b0...
git log --oneline 842f6b0..upstream/master   # tout ce qui arrive

# Merge dans une branche dédiée
git switch -c merge/upstream-2.3.1
git merge upstream/master
```

### Résoudre les conflits

1. **`sslh-conf.c` / `sslh-conf.h`** : ne pas résoudre à la main. Prendre la version amont, puis régénérer depuis `sslhconf.cfg` avec `conf2struct` (cf. `Makefile`). Réconcilier d'abord `sslhconf.cfg` (garder tes clés rvshell).
2. **`probe.c`** : conflit principal. Réappliquer tes hooks rvshell / ton ordre de probing **par-dessus** la version amont, en conservant le correctif `is_openvpn_protocol()` (CVE-2025-46806). Vérifier `probe.h`.
3. **`Makefile`** : garder les cibles amont + tes ajouts (AES). Attention aux nouvelles dépendances amont (autoconf/landlock).
4. **`sslh.pod`** : prendre l'amont, ré-ajouter ta section rvshell.

### Vérifier

```sh
make clean && make            # compilation
make test                     # suite de tests amont
# + un test fonctionnel de ton rvshell (redirection reverse-shell)
```

Quand tout est vert : `git switch master && git merge merge/upstream-2.3.1`.

## Alternative : rebase

Si tu préfères garder tes 9 commits redteam en tête d'historique :

```sh
git switch -c rebase/upstream-2.3.1
git rebase upstream/master
```

Le merge est plus simple ici (un seul jeu de conflits à traiter, pas 9 replays). Recommandé sauf si tu tiens à un historique linéaire.
