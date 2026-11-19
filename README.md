# proxmox-rolling-update

Mise à jour glissante (*rolling update*) d'un cluster **Proxmox VE** —
`apt full-upgrade` + reboot, **un nœud à la fois**, sans fencing inattendu,
avec gestion du HA, de Ceph (si présent) et rééquilibrage final du cluster.

Deux scripts Python 3 (dépendances : `proxmoxer`, `paramiko`) :

- `proxmox_rolling_update.py` — mise à jour des nœuds PVE (ce README) ;
- `proxmox_ceph_rolling_update.py` — mise à jour glissante de Ceph :
  mineure par défaut, `--major RELEASE` (ex. tentacle 20.2 ; montée
  d'exactement une release — descente et saut refusés, prérequis
  pve-manager/ceph vérifiés, `require-osd-release` précédé de la
  preuve que TOUTES les OSDs sont sur la nouvelle release). En montée
  majeure, les OSDs sont mises à jour UNE PAR UNE (arrêt → test réel
  du sharding RocksDB via `ceph-bluestore-tool show-sharding` pendant
  l'arrêt → démarrage sur les nouveaux binaires → gate) : vérité
  terrain du piège META du wiki (OSDs créées sous Octopus), récapitulé
  au bilan. Le retour « up » de chaque OSD après son redémarrage est
  vérifié dans le dump RÉEL de `ceph osd dump` (champ « osd », avec
  repli sur « id » et sur les entiers historiques `up`/`in` : lire le
  mauvais champ faisait attendre des OSDs pourtant revenues) ; pendant
  la convergence, la gate attend en NOMMANT les OSDs attendues, et au
  timeout elle liste celles jamais revenues « up ». Tous les messages
  de la Phase E (sharding, arrêt/démarrage, gates), de `--rotate-keys`
  et du bilan affichent l'étiquette `nœud/osd.N` — le serveur à gauche
  de l'OSD. La bascule du dépôt apt détecte les fichiers RÉELS qui le
  déclarent (`grep -rls` sur `/etc/apt/sources.list.d/` et
  `/etc/apt/sources.list`) : le nom n'est pas standardisé (ceph.list,
  ceph.sources, pveceph.list…) et un sed sur des chemins codés en dur
  échoue quand ils n'existent pas. Un chemin en erreur (ex.
  `/etc/apt/sources.list` absent sur un nœud migré 100 % en `.sources`
  deb822) ne masque PAS les correspondances de l'autre : grep sort 2
  dans ce cas, mais les fichiers trouvés restent valides. Si aucun
  fichier n'est trouvé, le
  run indique la bascule à faire manuellement au lieu d'échouer en
  plein vol. La santé « effective » des gates filtre le check
  `OSDMAP_FLAGS` quand il signale EXCLUSIVEMENT des flags de
  maintenance (`noout`, `nobackfill`…) : posés pendant toute la
  fenêtre du run, ils maintiennent un WARN permanent — sans ce
  filtrage, chaque gate attendrait son timeout (30 min) sans pouvoir
  jamais atteindre HEALTH_OK ; un flag non-maintenance (`pause`,
  `full`, `noup`…) reste bloquant. Ces mêmes flags GÈLENT le
  backfill/recovery pendant la fenêtre : les gates exigent donc des
  PGs **ACTIVES** (pas « clean ») — une PG `active+remapped` doit
  backfiller POUR revenir sur l'OSD revenue, l'exiger « clean »
  pendant la fenêtre serait un blocage auto-infligé (cas vécu : osd.0).
  Le « clean » n'est vérifié qu'en **convergence finale**, APRÈS le
  retrait des flags (timeout réglable
  `PVE_CEPH_FINAL_CONVERGE_TIMEOUT`, défaut = `PVE_CEPH_STABLE_TIMEOUT` ;
  au timeout le run a RÉUSSI, le cluster converge seul). Les logs sont
  **anti-bruit** : l'avertissement cephx (`PVE_CEPH_ALLOW_AUTH_INSECURE`)
  et le diagnostic détaillé ne sont (ré)imprimés que si la santé
  **CHANGE** — les gates pollant toutes les 15 s pendant la fenêtre, un
  état identique au précédent n'est pas redumpé ; le diagnostic ne
  liste que les dégradations **BLOQUANTES** (checks `AUTH_INSECURE_*`
  tolérés et flags de maintenance attendus masqués, signalés par la
  mention « hors N check(s) toléré(s)/attendu(s) ») ; sur les chemins
  d'échec (timeout de gate, refus de preflight, échec de rotation),
  le contexte complet est réimprimé de force — rien n'est perdu en
  cas de problème réel. Comme « non clean », les checks PG gelés par
  les flags (`PG_DEGRADED`, `PG_UNDERSIZED` — une PG ressortie
  dégradée d'un « stuck peering » ne PEUT PAS guérir tant que
  `norecover`/`nobackfill` sont posés, et les scrubs en retard tant
  que `noscrub` l'est — vécu : gate condamnée au timeout pendant
  14 min alors que santé réelle, quorum, PGs actives et OSDs up
  étaient tous OK) sont **attendus** : ils ne comptent pas dans la
  santé effective dès que des flags de maintenance sont posés sur
  le cluster — posés par ce run PENDANT la fenêtre, **ou déjà
  présents** (le check `OSDMAP_FLAGS` du statut en est la preuve :
  run précédemment interrompu brutalement, ou administrateur).
  Vécu : un preflight exigeait la guérison de 2 PG
  `active+recovery_wait+degraded` que des flags déjà posés
  empêchaient de guérir — le run était condamné à refuser
  éternellement. Ces checks restent listés en **WARNING** au
  preflight (avec « ceph osd dump | grep flags » si les flags ne
  sont pas de vous), sont re-vérifiés pour de vrai à la
  **convergence finale** après retrait des flags, et le message de
  convergence NOMME les checks qui bloquent encore. Hors flags,
  une PG dégradée reste BLOQUANTE au preflight.

  Même logique pour `OSD_UPGRADE_FINISHED` (« all OSDs are running
  tentacle or later but require_osd_release < tentacle ») : c'est le
  signal du monitor que TOUTES les OSDs tournent déjà en release
  cible — il ne disparaît QUE quand « require-osd-release » est
  relevé, ce que le run ne fait qu'en Phase G (APRÈS les MDS, ordre
  du wiki Proxmox). L'exiger HEALTH_OK à la gate de la Phase E
  attendait une condition que le run lui-même ne crée qu'à la fin
  (vécu : restart ceph-osd.target, OSDs up/quorum complet/PGs
  actives tous OK, > 5 min de polls sur ce SEUL check restant, run
  tué au Ctrl-C avant la phase MDS). Il est donc **attendu** si (et
  seulement si) la release qu'il nomme est la CIBLE du run `--major`
  ; déjà présent au preflight (reprise d'un run tué avant la Phase
  G), il est toléré et listé en WARNING (« require_osd_release » pas
  encore relevé) ; la Phase G le pose, puis la convergence finale
  re-vérifie la santé réelle une fois le check disparu. Hors run
  `--major` vers cette release (mode mineur, rotate-keys, montée
  précédente inachevée), il reste BLOQUANT. La Phase E est **idempotente à la reprise** : la
  version COURANTE de chaque daemon OSD (`ceph osd metadata`) est
  lue avant la passe — un nœud dont TOUTES les OSDs tournent déjà
  sur la release cible est SAUTÉ (aucun restart inutile, pas de gate
  re-subie) ; sinon ses OSDs sont redémarrées d'un coup via
  `systemctl restart ceph-osd.target` (une seule gate par nœud —
  plus rapide, impact plus large : aucune OSD du nœud ne sert d'IO
  pendant le restart). Le même version-check s'applique désormais
  aux MONs, MGRs et MDS en mode `--major` : la version COURANTE de
  chaque daemon est lue avant tout restart — un daemon qui tourne
  déjà sur la release cible est SAUTÉ (« tourne déjà en … — rien à
  faire »). Source 1 : `ceph tell <type>.<id> version` ; source 2
  (repli) : `ceph <type> metadata`, listé par le mon pour TOUS les
  daemons du type — les mgrs STANDBY ne répondent pas tous au tell
  (vécu : 2 mgrs sur 3 déjà en cible annoncés à tort « à
  redémarrer » en dry-run). C'est une preuve, pas une hypothèse :
  un daemon qui tourne sur la cible a déjà été redémarré après
  l'upgrade des paquets. Les DEUX sources illisibles →
  avertissement EXPLICITE puis restart quand même (échec sûr) —
  jamais de « à redémarrer » sans avoir vérifié la version. En
  mode mineur (patch) les restarts restent inconditionnels. En
  DRY-RUN, `apt-get update -q` est exécuté RÉELLEMENT sur chaque
  nœud (sans risque : il ne rafraîchit que le cache des paquets
  disponibles), suivi de `apt-get -s full-upgrade` (simulation
  pure) qui AFFICHE les paquets réellement en attente — Ceph
  détaillés, plus le décompte des non-Ceph (full-upgrade est
  global) ; le full-upgrade lui-même reste simulé. En EXÉCUTION,
  c'est cette MÊME simulation (lecture pure, lancée après le vrai
  `apt-get update -q`) qui décide : si elle n'a RIEN à faire, le
  `apt-get full-upgrade` n'est PAS lancé du tout (vécu : 3
  « 0 upgraded, 0 newly installed » streamés pour rien sur des
  nœuds déjà à jour) ; si elle est illisible, le full-upgrade est
  lancé quand même (échec sûr — on ne saute JAMAIS une upgrade sur
  une lecture manquée). Le test du sharding RocksDB par OSD (piège
  META du wiki, il exige l'arrêt INDIVIDUEL de chaque OSD) est un
  OPT-IN explicite `--force-detection-sharding` (`--major`
  uniquement) : OSDs redémarrées UNE PAR UNE (arrêt → show-sharding
  → démarrage), SANS exemption de version — la date de création des
  répertoires n'est qu'une heuristique, la vérité terrain est ce
  test (sinon surveillez la colonne META de `ceph osd df`). Les flags
  orphelins d'un run précédent interrompu sont **adoptés** puis
  retirés à la fin — MÊME si ce run s'interrompt à son tour (un
  écrasement de variable les perdait, les laissant en place à vie) ;
  les flags posés par un administrateur restent en place et le bilan
  liste les commandes `ceph osd unset` exactes pour les retirer. Les vérifications post-restart qui
  dépendent du CONSENSUS (`min_mon_release` de la monmap après le
  dernier MON, élection du MGR actif) sont POLLÉES jusqu'à 5 min
  (configurable) : leur mise à jour automatique prend quelques
  secondes, et un check immédiat lirait l'ancien état. Le fichier
  d'état accepte aussi un chemin relatif (répertoire créé seulement
  s'il y en a un). Les MDS suivent la procédure wiki par daemon : actives
  identifiées via `ceph fs dump` (fiable en multi-FS, décodage
  tolérant aux lignes traînées par la CLI — « dumped fsmap epoch
  N » imprimé après le JSON — qui sinon faisait avorter le run en
  Phase F), standbys
  arrêtées unité par unité, actives redémarrées en dernier — jamais de
  stop/start de `ceph-mds.target` ; une MDS dont la version courante
  est déjà la cible (standby ou active) est SAUTÉE, rendant la Phase F
  idempotente à la reprise. Et `--rotate-keys` (remédiation CVE-2025-30156, entités déjà migrées
  re-détectées et sautées) : ses vérifications « check AUTH_INSECURE_*
  disparu » (étapes 7/8/9/12) sont POLLÉES jusqu'à
  `PVE_CEPH_ROTATE_CHECK_TIMEOUT_S` (défaut 120 s) — le health check
  est recalculé ASYNCHRONEMENT par les mons, une lecture immédiate
  relisait l'état d'avant la dernière rotation (vécu : FATAL 7 s
  après la rotation de la DERNIÈRE MDS alors que le check avait
  disparu une seconde plus tard) ; un FATAL après timeout garde le
  run relançable, la reprise ne traite que le reste. L'étape 10
  (rotation de `client.admin`) importe la nouvelle clé dans chaque
  keyring admin VIA la clé de secours `client.admin-backup` qui vient
  d'être créée — après la rotation, les keyrings locaux ne contiennent
  plus que l'ANCIENNE clé invalidée, et un `ceph auth get client.admin`
  par la CLI locale échoue en `RADOS permission denied` (vécu : FATAL
  11:40, CLI admin de tout le cluster coupée) ; le keyring de secours
  est DIFFUSÉ vers les autres nœuds le temps de l'import (puis
  supprimé), et si le keyring de secours est illisible la rotation est
  REFUSÉE avant d'avoir cassé quoi que ce soit. La détection des
  keyrings admin couvre le keyring AUTHORITATIF de Proxmox VE —
  `/etc/pve/priv/ceph.client.admin.keyring`, celui que lit la CLI
  `ceph` du root — ainsi que `/etc/pve/priv/ceph.mon.keyring` (mon. +
  client.admin : l'import par entité de `ceph-authtool` remplace
  client.admin sans toucher à mon.), la copie `/etc/ceph/…` et les
  keyrings des storages `/etc/pve/priv/ceph/*.keyring` (vécu 12:29 :
  importer dans `/etc/ceph/…` et le keyring du storage ne répare PAS
  la CLI — `ceph -s` reste en `monclient(hunting):
  handle_auth_bad_method … (13) Permission denied` tant que
  l'authoritatif garde l'ancienne clé) ; `ceph -s` est vérifié sur
  CHAQUE nœud après les imports. Enfin, la reprise
  détecte une clé de secours ORPHELINE (run interrompu avant sa
  suppression : une backdoor `mon allow *`) et la supprime, ET
  vérifie que les keyrings LOCAUX contiennent bien la clé
  `client.admin` COURANTE de l'auth DB — la reprise juge l'étape
  acquise sur l'auth DB seule, or un run interrompu à l'étape 10 +
  une réparation manuelle partielle laissent des keyrings locaux
  périmés : sur Proxmox VE, les storages CephFS/RBD de
  `/etc/pve/priv/ceph/<storage>.keyring` authentifient par ces
  fichiers (vécu 13:0x : les 4 storages CephFS « non Active » après
  un run pourtant terminé en santé OK) ; chaque keyring divergent
  est ré-importé (idempotent), les frais ne sont pas retouchés.
  Et les storages CephFS de PVE sans `username` explicite gardent la
  clé de `client.admin` dans `/etc/pve/priv/ceph/<STORAGE_ID>.secret`
  — la clé NUE (pas un keyring, donc invisible pour la détection par
  section `[client.admin]`) : après rotation de `client.admin`, le
  storage reste coupé tant que le `.secret` n'est pas régénéré
  (« A CephFS storage holds only the bare key » — doc PVE) ; le script
  régénère désormais ces `.secret` dans le flux normal de l'étape 10
  (après les imports) ET à la reprise (vécu 13:1x : 4 storages CephFS
  « non Active », `pvesm` en timeout, cluster pourtant HEALTH_OK). À l'étape
  11, le keyring local `bootstrap-<type>`
  (`/var/lib/ceph/<type>/ceph.keyring`) n'est mis à jour QUE là où le
  répertoire du service existe déjà — sur un cluster sans rbd-mirror
  ni rgw déployés, ces répertoires n'existent pas et l'écriture
  échouerait en `No such file or directory` (vécu 12:52 : FATAL à la
  distribution de `client.bootstrap-rbd` alors que sa rotation dans
  l'auth DB avait RÉUSSI) ; les services non déployés sont donc
  sautés avec un message explicite, comme pour `client.crash`.
  Connexion SSH persistante par nœud
  (`PVE_SSH_RETRIES`), stderr capturé dans le fichier de log, bilan
  signalant explicitement les runs interrompus — voir son docstring.

---

## Sommaire

1. [Principe](#principe)
2. [Prérequis](#prérequis)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Utilisation](#utilisation)
6. [Déroulé du run](#déroulé-du-run)
7. [Sécurités intégrées](#sécurités-intégrées)
8. [Reprise après interruption](#reprise-après-interruption)
9. [Ceph : fenêtre de maintenance et gates](#ceph--fenêtre-de-maintenance-et-gates)
10. [Estimations du dry-run et statistiques de durées](#estimations-du-dry-run-et-statistiques-de-durées)
11. [Variables d'environnement](#variables-denvironnement)
12. [Limites connues](#limites-connues)

---

## Principe

Le script applique la méthode officielle Proxmox pour vider un nœud sans
provoquer de fencing :

1. les ressources HA de ce nœud sont détachées du CRM (état `ignored` +
   label `[proxmox-rolling-update]`), les migrations sont pilotées par le
   script ;
2. le nœud passe en **mode maintenance HA** (`ha-manager node-maintenance`) ;
3. ses VMs sont migrées ailleurs (live migration) ;
4. `apt update` + `apt full-upgrade`, puis reboot si un nouveau noyau a été
   installé ;
5. vérifications post-reboot (quorum, systemd, syslog, Ceph) ;
6. sortie de maintenance + réactivation des ressources HA dans leur état
   d'origine.

Puis on passe au nœud suivant. En fin de run, un **rééquilibrage** RAM/CPU
repositionne les VMs au plus près de l'équilibre.

Tout échec **arrête le run proprement** : les blocs `finally` restaurent
l'état zéro (sortie maintenance, réactivation HA, retrait des flags Ceph),
et un fichier d'état JSON permet au run suivant de finir le travail.

## Prérequis

- Cluster Proxmox VE (testé sur PVE 9.x), quorum fonctionnel.
- Un **token API** avec droits suffisants (lectures cluster, `qm migrate`,
  `reboot`, `ha-manager`, `ceph` si présent).
- Un accès **SSH par clé** vers les nœuds (root, ou utilisateur avec sudo
  restreint) pour : `apt`, `ha-manager node-maintenance`, commandes `ceph`,
  `systemctl`, `df`.
- Python 3 avec `proxmoxer` et `paramiko` sur la machine d'exécution.
- La machine d'exécution doit résoudre en DNS les **noms** des nœuds
  (sinon figer `PVE_API_HOSTS`).

## Installation

```bash
git clone <ce dépôt>
cd proxmox-rolling-update
pip install proxmoxer paramiko        # ou apt install python3-proxmoxer

sudo mkdir -p /etc/proxmox-updater
sudo cp env.example /etc/proxmox-updater/proxmox.env
sudo chmod 600 /etc/proxmox-updater/proxmox.env
# renseigner les valeurs (voir ci-dessous)
```

## Configuration

Tout est dans le fichier d'environnement (voir `env.example`, commenté) :
point d'entrée API + token, clé SSH, options de migration et de Ceph.
Priorité : variable d'environnement > fichier env > défauts du script.

Points notables :

- **Hôtes API** : seul `PVE_API_HOST` (nœud graine) est nécessaire ; la
  liste des nœuds est découverte dynamiquement, avec bascule automatique
  de l'hôte API si le nœud courant tombe (reboot).
- **SSH non supervisé** : pour un run en tâche de fond (cron/systemd),
  utiliser une clé **sans passphrase** dédiée, restreinte dans
  `authorized_keys` (`from=…,no-pty,no-port-forwarding,…`).
- **Disques locaux** : `PVE_WITH_LOCAL_DISKS=true` migre aussi les disques
  des VMs hors storage partagé.

## Utilisation

```bash
# Simulation complète (aucune écriture) : pré-vérifications réelles,
# plans de migration simulés, tables d'occupation
python3 proxmox_rolling_update.py --dry-run

# Exécution réelle sur tout le cluster
python3 proxmox_rolling_update.py --execute

# Un seul nœud
python3 proxmox_rolling_update.py --execute --node pve-node3

# Reprise rapide après incident : ignorer les nœuds dont les seules MAJ
# en attente sont des paquets Debian mineurs (v19)
python3 proxmox_rolling_update.py --execute --skip-minor-updates

# Fichier env et log spécifiques, verbosité
python3 proxmox_rolling_update.py --execute \
    --env-file ./proxmox.env.mycluster \
    --log-file ./run-$(date +%F).log -v
```

Le fichier env est **obligatoire** (`--env-file`, défaut
`/etc/proxmox-updater/proxmox.env`) : sans lui le script s'arrête.

**`--skip-minor-updates` (v19)** : conçu pour la **reprise après
incident**. Un run complet dure ~5 h ; Debian publie des MAJ mineures
pendant ce temps, et chaque nœud déjà traité se verrait sinon infliger
une évacuation complète (~25 min) pour quelques paquets sans importance.
Avec l'option, un nœud dont les seules MAJ en attente sont des paquets
Debian mineurs est **ignoré** : ni évacuation ni upgrade ni reboot,
les VMs restent en place. Un nœud reste **toujours traité** si sa
simulation apt montre un **changement de noyau** (`proxmox-kernel`/
`linux-image`), un **changement de version PVE** (paquet `pve-*` ou
`proxmox-*` : pve-manager, pve-qemu-kvm…) ou un **reboot en attente**
(noyau courant ≠ dernier installé, `/var/run/reboot-required`, ou le cas
« run interrompu entre l'upgrade et le reboot »). Les MAJ ignorées ne
sont **pas supprimées, seulement différées** — les mineures Debian
contiennent souvent des correctifs de sécurité : repasser un run
**sans** l'option dans une autre fenêtre pour les appliquer. L'option
n'est pas active par défaut ; un récap en fin de run liste les nœuds
ignorés et le rappelle.

**Version du script** : la **première ligne de chaque run** (console ET
fichier de log) affiche `proxmox-rolling-update — version <N>`, et la
bannière reprend `v<N>` — c'est le moyen fiable de vérifier QUELLE
version tourne sur un cluster donné (une copie périmée a déjà été prise
pour une version à jour). Le numéro est la constante `SCRIPT_VERSION`
en tête du script, à incrémenter à chaque publication.

## Déroulé du run

**Étape 0 — Pré-vérifications** : lecture pure (quorum corosync, versions
PVE par nœud, ressources HA et règles d'affinité, état Ceph). Si un run
précédent s'est arrêté avant d'avoir tout restauré, un fichier d'état est
détecté et la **récupération** s'exécute (voir plus bas). En dry-run,
simple rapport — sauf pour les règles `node-affinity` du fichier d'état,
qui sont réactivées POUR DE VRAI (cf. ci-dessous).

**Étape 0-bis — Cohérence des `/etc/hosts` (v15-v17)** : chaque
`/etc/hosts` doit résoudre TOUS les nœuds du cluster par leur nom court
(corosync, migrations live, ceph, SSH inter-nœuds s'appuient dessus
quand le DNS n'a pas réponse). Audit complet en lecture AVANT la
première évacuation, nœud par nœud sur le fichier entier : nœud
**manquant** (ajout « IP FQDN nom »), **incohérent** (IP ≠ l'IP de
gestion connue de l'API, ou FQDN sans alias court — `getent` ne résout
alors pas le nom court), **doublon**, entrée **obsolète** de la famille
du cluster. En dry-run : rapport seulement ; en `--execute` :
correction par nœud après **sauvegarde datée**, puis re-vérification
(le run est refusé si un nœud ne peut pas être corrigé : un
`/etc/hosts` faux en pleine migration casse la résolution de noms au
pire moment). Les fichiers **conformes ne sont pas réécrits** ; le
fichier corrigé garde sa structure d'origine — les ajouts atterrissent
dans leur **bloc canonique** (bouclage, nœuds du cluster, le reste,
section IPv6, retraits en dernier — tri v17 au lieu d'un empilement en
fin de fichier), et la comparaison avant/après écriture est normalisée
`\r`/`\n` (écriture via PTY, v16 — sinistre : le fichier réputé identique
était réécrit en boucle à chaque diff fantôme). Désactivable via
`PVE_HOSTS_CHECK=0`.

**Étape 1 — par nœud** (dans l'ordre du cluster) :
- `apt update` + diagnostic espace disque : besoin estimé
  (`2 × taille installée + téléchargements + marge max(1 G, 5 %)`) comparé
  au libre (`/`, `/var`, `/boot/efi`). Si rien à mettre à jour : nœud
  sauté, ni évacuation ni reboot (sauf **reboot en attente** sans
  paquets : maintenance complète SANS upgrade, cf. « Reprise après
  interruption »). Avec `--skip-minor-updates` (v19), un nœud dont les
  seules MAJ sont des paquets **Debian mineurs** est ignoré de la même
  façon à ce stade : ni évacuation ni upgrade ni reboot, VMs en place,
  nœud listé dans le récap final — sauf si la simulation apt montre un
  noyau (`proxmox-kernel`/`linux-image`), un paquet `pve-*`/`proxmox-*`
  ou un reboot en attente : ces changements sont **significatifs** et
  le nœud passe en maintenance normalement (un noyau en attente n'est
  JAMAIS ignoré).
- Détachement HA (`ignored` + label, état d'origine mémorisé) puis mode
  maintenance HA.
- **Mise en sommeil temporaire de TOUTES les règles `node-affinity`**
  du cluster (une seule fois par run, définitions intactes) : ni le
  planning du script ni le CRM ne subissent de préférence/contrainte
  node-affinity pendant TOUTE l'Étape 1 — une règle `strict=1` ne peut
  plus bloquer l'évacuation du nœud, et le CRM ne décide plus de relocate
  à chaque sortie de maintenance (churn en pleine évacuation du nœud
  suivant). Les règles sont restaurées à la FIN de l'Étape 1,
  avant le rapatriement/rééquilibrage, qui redeviennent contraints par les
  règles ; en mode `--node`, la fin d'Étape 1 est la sortie de maintenance
  du nœud. Les règles déjà désactivées par un admin ne sont pas touchées ;
  les `resource-affinity` (« keep separate » / « together ») ne sont
  **jamais** touchées : contraintes de sécurité, actives du début à la
  fin. Les mises en sommeil sont persistées dans le fichier d'état.
  **Mode adapté au schéma de l'API PVE** (constat d'un run réel sur
  PVE 9.1/9.2 : le schéma des règles est type-dépendant, le PUT EXIGE
  `type` et peut refuser `disable`) — cascade par règle, le mode qui
  fonctionne étant mémorisé pour tout le run : 1. `disable=1` (PUT
  `type`+`disable=1`) ; 2. à défaut, `resources=""` (PUT `type`+`resources`
  vides : la règle ne s'applique plus à rien, définition conservée) ;
  3. à défaut, suppression temporaire (DELETE, recréation à l'identique
  à la restauration). **Chaque PUT est VÉRIFIÉ par re-lecture** : sur
  PVE 9, un PUT accepté (HTTP 200) peut rester SANS EFFET côté HA
  Manager (bug officiel — cf. correctif pve-manager ≥ 9.0.7) ; si
  l'effet n'est pas constaté, la cascade continue vers le mode
  suivant au lieu de croire le code retour. La restauration applique
  le mode inverse : pour le mode `disable`, la réactivation
  **SUPPRIME la propriété `disable`** (PUT `type` + `delete=disable`,
  le paramètre standard des PUT PVE) avec `disable=0` en repli pour un
  PVE antérieur — car depuis un changement du HA Manager PVE 9,
  `disable=0` seul **ne réactive plus** une règle désactivée (le PUT
  est accepté mais reste sans effet : constat d'un run réel, c'est le
  bug officiel corrigé côté GUI) ; l'effet est ensuite **vérifié par
  re-lecture**, et un échec réel devient une ERROR explicite (la règle
  reste dans le fichier d'état, le prochain run la réactivera) — plus
  jamais de « réactivée ✔ » de façade. Pour les autres modes :
  ressources d'origine rendues à la règle (fusion avec les ressources
  courantes), ou recréation par POST (`rule`, pas `rid`).
  **En dry-run, ces mises en sommeil/restaurations sont effectuées POUR DE
  VRAI** : c'est une action réversible
  et sans effet de bord — retirer une préférence ne déplace aucune
  ressource, et une restauration sur des placements conformes n'en
  déplace pas non plus — et c'est le seul moyen de tester le mécanisme
  avant le run réel. Tout le reste du dry-run (migrations, apt, reboot,
  maintenance, détachement HA) reste simulé ; le fichier d'état trace
  ces actions réelles (un dry-run interrompu par Ctrl-C est donc
  rattrapé au run suivant), en préservant toute section d'un run
  `--execute` interrompu.
- **Plan de migration** affiché (quelle VM va où, impact RAM/CPU estimé,
  affinités respectées), puis migrations réelles, en respectant les marges
  de sécurité RAM (AUTO : `min(max(10 % × RAM, 8 G), 48 G, 30 % × RAM)`)
  et 80 % de CPU.
- **VMs arrêtées : laissées sur place** (aucune migration) — une VM éteinte
  ne court aucun risque pendant l'upgrade et le reboot ; sa ressource HA
  reste détachée puis réactivée dans son état d'origine (`stopped`), sans
  churn. Garde-fou : une VM arrêtée avec `onboot: 1` (ou de config
  illisible) reste **migrée** comme avant — laissée sur place, elle
  partirait au boot du nœud (plus gérée par le HA en `ignored`), puis le
  CRM l'éteindrait à la réactivation de sa ressource. **Exception v20 —
  disques locaux** : si ses disques sont sur un storage NON partagé
  (inexistant sur les autres nœuds), la migration est vouée à l'échec
  (PVE refuse cluster-wide « storage … is not available on node … »,
  vécu : VM 405, 2 tentatives FATA) : la VM est alors **laissée sur
  place** avec `onboot` **temporairement désactivé** (PUT de config avec
  digest), restauré en fin de traitement du nœud et **tracé dans le
  fichier d'état** — la reprise d'un run interrompu le restaure. Si ni
  la migration ni la suspension ne sont possibles : arrêt AVANT
  évacuation (un reboot ne doit jamais démarrer une VM contre toute
  intention). L'erreur 500 « is not available on node » est par
  ailleurs classée **déterministe** : aucun carrousel d'hôtes API.
- `apt full-upgrade` en streaming dans les logs ; si noyau nouveau :
  re-contrôle Ceph, **flags de maintenance Ceph** (si Ceph), reboot,
  attente du retour (uptime réinitialisé, max 15 min).
- Vérifications post-reboot : quorum, `systemd` running, services en
  échec (avec retries pour les échecs transitoires), syslog (120 s), Ceph
  (2f-bis, voir section Ceph).
- `finally` en **tout état de cause** : retrait des flags Ceph, sortie de
  maintenance, réactivation des ressources HA dans leur état d'origine,
  fenêtre de stabilité CRM de 60 s (les règles `node-affinity` restent
  désactivées jusqu'à la fin de l'Étape 1, sauf en mode `--node` où elles
  sont réactivées ici). L'état est persisté dans le JSON à chaque
  mutation. **Budget de stabilité adapté (v22)** : la fenêtre CRM n'a pas
  un budget fixe — le failback du CRM est une live migration
  RAM-dépendante qui peut largement dépasser 10 min ; le budget monte
  donc à la durée estimée de la migration la plus longue en cours et
  chaque nouvelle tâche CRM rouvre une manche (cf.
  `PVE_HA_SETTLE_TIMEOUT` / `PVE_HA_SETTLE_MAX_TOTAL`).

**Étape 2 — Rééquilibrage final** : AVANT l'optimisation RAM, un
**rapatriement des hors-règle** ramène sur un nœud de leur règle
node-affinity toute ressource HA qui s'y trouve encore — repli
strict=0 pendant une évacuation, OU déplacement pendant le sommeil
des règles (une VM de règle mono-nœud est forcément déplacée hors
règle quand son nœud est évacué), règle soft comme DURE, VM running
(le CRM la re-migrerait au dégel) comme stopped (migration hors
ligne : elle sera conforme à sa prochaine mise en route, `onboot=1`
compris). Le rééquilibrage optimise ensuite AUTOUR de ce placement
conforme : les VMs (HA détachées temporairement pour piloter les
migrations) sont repositionnées pour minimiser l'écart
de pression RAM entre nœuds (optimum théorique approché, avec tolérance
d'un point) ; les nœuds vides sont d'abord remplis (résilience), puis
l'écart optimisé. CPU surveillé (≤ 80 %). Skip si Ceph n'est pas
HEALTH_OK (sauf `PVE_CEPH_ALLOW_WARN=1`). Si aucun nœud de la règle ne
respecte la marge RAM/CPU au moment de la **1re passe** de
rapatriement : la ressource reste sur place (WARNING) et le message
annonce qu'une **SECONDE passe de rapatriement** sera rejouée
**après le rééquilibrage** (dans la même fenêtre de gel CRM, avant le
dégel) : les migrations du rééquilibrage peuvent avoir **libéré** le
nœud de règle qui était saturé à la première passe (cas réel : des
DUREs échouaient AVANT le rééquilibrage, leurs nœuds de règle
reprenaient de la place juste après) — elles sont ramenées à ce
moment-là (mention « 2e passe post-rééquilibrage » dans le log) et le
dégel final n'a vraiment plus rien à corriger. Si la seconde passe
échoue aussi, la ressource reste hors règle : le CRM décidera au
dégel — relocalisation certaine pour une règle DURE, probable pour
une soft (comportement attendu, pas une anomalie).

**Bilan final** : tables d'occupation avant/après, synthèse des
migrations et upgrades. En dry-run s'y ajoute l'estimation de durée
(voir [Estimations du dry-run](#estimations-du-dry-run-et-statistiques-de-durées)).

**Sémantique RAM des tables (v9)** : chaque ligne d'hyperviseur porte
DEUX métriques distinctes. À l'**état initial**, « **RAM réelle** » est
la mémoire **consommée mesurée** du nœud, et « **Σ déclarée** » la somme
des RAM max des guests *running* — la **pression** anti-overcommit que
le run répartit. À l'**état final** (dry-run, état simulé), « **RAM
(pression)** » est cette **pression déclarée du modèle** (égale à « Σ
déclarée »), **pas** un usage mesuré : l'état final s'apprécie donc sur
cette métrique, à comparer à « Σ déclarée » de l'état initial, **pas**
à « RAM réelle ». Ne pas confondre les deux donnait l'illusion que la
mémoire des nœuds « gonflait » (~50 % d'usage réel initial ➔ ~85 % de
pression déclarée final) alors qu'une migration **déplace** la mémoire,
elle ne la crée pas : la consommation réelle du cluster est inchangée.
Un « NB : » sous les bandeaux ÉTAT INITIAL et ÉTAT FINAL rappelle
cette sémantique dans le log. En run `--execute` ayant modifié le
cluster, l'état final est **re-lu** après la fenêtre de stabilité CRM :
il montre alors l'usage réel mesuré, sans NB. C'est à cet endroit que
s'est produit l'incident corrigé en **v22** : le CRM rapatriait une
grosse VM par live migration de ~9 min ; le budget global fixe de
600 s a expiré **15 s avant** la fin de la fenêtre de confirmation →
FATAL « cluster instable » à tort, alors que le nœud était traité et
le cluster déjà en état zéro. Le budget est désormais adapté à la RAM
des migrations CRM en cours (vécu 19/11 : VM 500, failback post-run).

## Sécurités intégrées

- **Jamais deux nœuds à la fois** ; arrêt au premier problème.
- **Détection fencing** : les syslogs des AUTRES nœuds sont scrutés en
  continu pendant les phases à risque — tout fencing détecté = arrêt
  immédiat.
- **Bascule automatique de l'hôte API** (y compris préventive avant le
  reboot du nœud hébergeant l'API).
- **Affinités HA** : TOUTES les règles `node-affinity` du cluster sont
  mises **en sommeil** (mode adapté au schéma de l'API PVE : `disable=1`,
  sinon ressources vidées, sinon suppression temporaire ; définitions
  intactes) pendant toute
  l'Étape 1 — sans cela, une règle `strict=1` peut bloquer l'évacuation
  et le `apt full-upgrade` avec lui, et le CRM décide des relocate à
  chaque sortie de maintenance. Restauration à la fin de
  l'Étape 1, avant le rééquilibrage : un seul point de failback, au
  moment où le cluster est de nouveau complet — réactivation PVE 9 par
  **suppression du flag `disable`** (`disable=0` ne suffit plus),
  chaque mise en sommeil et chaque restauration **vérifiées par
  re-lecture** (un PUT accepté sans effet déclenche la cascade ou une
  ERROR explicite). Les `resource-affinity`
  (« keep separate ») ne sont jamais contournées : elles restent
  contraignantes du début à la fin. La reprise d'un fichier d'état de
  l'ANCIENNE version (retrait de VMs des règles) crée la règle manquante
  par POST **uniquement si aucune règle équivalente n'existe déjà** :
  une règle recréée manuellement (autre identifiant, mêmes nœuds,
  ressources couvrantes) est détectée et AUCUN doublon n'est créé.
- **Gate espace disque** avant toute évacuation (pas d'upgrade qui remplit
  la racine d'un nœud vidé… ou pire, pas vide).
- **Marges RAM AUTO** par nœud + plafond CPU 80 %.
- **PVE_CEPH_ALLOW_WARN=0 par défaut** : HEALTH_OK exigé avant chaque
  évacuation/reboot — protection contre la dégradation cumulée de PGs
  entre deux reboots.
- **PVE_CEPH_ALLOW_AUTH_INSECURE=0 par défaut** : depuis Ceph Squid
  19.2.6 (hotfix CVE-2025-30156, 19/08/2026), six checks
  `AUTH_INSECURE_*` signalent les clés CephX encore en « aes »
  (AES-128-CBC, IV fixe, sans HMAC) ; deux sont en sévérité ERR et
  font passer le cluster en `HEALTH_ERR` **sans impact IO/daemons**
  (avis cryptographique, pas une panne de stockage). Poser
  `PVE_CEPH_ALLOW_AUTH_INSECURE=1` filtre UNIQUEMENT ces codes aux
  gates Ceph — toute dégradation réelle (PG/OSD/MON) reste bloquante.
  La remédiation définitive reste la migration des clés vers
  « aes256k » (rotation progressive : MGR/MDS, OSD un par un,
  client.admin, bootstrap-*, puis retrait complet de `aes`).
- **Erreurs API déterministes ≠ panne d'hôte** : une réponse « 400 »,
  « does not exist », « binary not installed », « proxy handshake » ou
  « guest agent is not running » échoue **immédiatement** sans bascule
  d'hôte API (l'appel `agent.ping` est proxifié vers l'hébergeur de la
  VM : tous les hôtes échoueraient à l'identique — sans ce cas, chaque
  VM sans agent vivant déclencherait un carrousel complet des ~10 hôtes).
- **Tâches « WARNINGS: n » = RÉUSSIE (v13)** : Proxmox termine une
  tâche avec `exitstatus: WARNINGS: 1` quand elle a RÉUSSI mais de
  façon non silencieuse (ex. backup avec avertissement, migration avec
  remarque) — seul `ERROR` est un échec (règle Proxmox
  `upid_status_is_error`). La v12 cassait le run pour un simple
  avertissement. Désormais : les lignes `WARNING:` du log de la tâche
  sont remontées (3 max, puis renvoi vers
  `pvesh get /nodes/<nœud>/tasks/<upid>/log`), la migration est
  considérée réussie et le run continue ; `ERROR` échoue toujours
  immédiatement.
- **Reprise sur échec de migration (v18)** : une live migration peut
  échouer **après un transfert complet**, sur une course QEMU au
  « resume » du tunnel (« `ERR: resume failed - VM n not running` »,
  tâche « `migration problems` », VM retrouvée ARRÊTÉE — vécu : VM 374,
  transfert 3,2 Go OK, downtime 94 ms). Le run n'abandonne plus : il
  **localise** la VM (cible ou source), la **redémarre** si elle a été
  assommée par la course (sur la cible si ses disques y sont déjà,
  sinon sur sa source pour restaurer le service), vérifie le guest après
  chaque migration **réussie** aussi (l'agent guest / le statut réel —
  une tâche peut finir en OK avec la VM revenue arrêtée), puis
  **retente** la migration (`PVE_MIGRATE_ATTEMPTS` tentatives au total,
  défaut 2 ; `PVE_START_TIMEOUT` pour le redémarrage). Le FATAL ne
  survient qu'après épuisement des tentatives ou VM irrécupérable —
  jamais une VM éteinte sans avoir tenté de la relancer d'abord.
- **Compatibilité QEMU/machine pendant le rolling upgrade (v13)** :
  une VM démarrée sur un nœud déjà upgradé peut résoudre une machine
  que les nœuds pas encore upgradés refusent
  (« Installed QEMU version '10.1.2' is too old to run machine type
  'pc-i440fx-11.1+pve0', please upgrade node '…' » — la migration est
  alors REFUSÉE par PVE en pleine évacuation). À chaque inventaire,
  une sonde SSH par nœud lit (1) la version du binaire QEMU et (2) la
  machine **réellement exécutée** par chaque VM démarrée dans `ps`
  (l'alias `pc`/`q35` de la config y est déjà résolu en
  `pc-i440fx-X.Y+pveN` — seule façon fiable, `qm listmachines`
  n'existe pas). Le placement ne propose alors chaque VM qu'à des
  nœuds dont le QEMU sait exécuter sa machine ; les invités arrêtés
  ne sont pas migrés (ils restent sur place, reboot inclus) et ne
  sont donc pas contraints. Si **aucune** cible ne sait l'exécuter,
  le run s'arrête avec la remédiation : figer la machine après arrêt
  (`qm set <vmid> --machine <famille>-<X.Y>`, non changeable à chaud),
  laisser la VM arrêtée pendant le run, ou upgrader d'abord un nœud
  cible. Le préflight signale l'hétérogénéité QEMU dès l'Étape 0 ;
  un nœud que la sonde n'a pas pu interroger reste **permissif**
  (aucune contrainte ajoutée : le garde-fou natif de PVE s'applique
  toujours au moment de la migration). Aucune nouvelle variable
  d'environnement : le comportement est automatique.

## Reprise après interruption

Run tué (`kill -9`, coupure) ⇒ le fichier d'état JSON
(`proxmox-rolling-update.state.json`) contient l'état zéro : ressources
HA détachées (avec état et comment d'origine), règles `node-affinity`
désactivées (définitions d'origine persistées), nœuds en maintenance,
flags Ceph posés. Au lancement suivant, l'Étape 0 détecte ce fichier et
restaure tout automatiquement (règles d'affinité d'abord, pour que le
CRM applique les préférences dès la réactivation des ressources ; les
flags Ceph sont globaux : le retrait essaie chaque nœud jusqu'à trouver
un SSH joignable), puis le run repart. En dry-run, la reprise réactive
AUSSI pour de vrai les règles `node-affinity` du fichier (PUT réels et
réversibles, réactivation par suppression du flag `disable` et effet
vérifié par re-lecture) ; ressources HA, maintenance et flags restent simulés.
La reprise accepte AUSSI les
fichiers d'état de l'ancienne version (ressources retirées des règles,
règle éventuellement supprimée) : la règle manquante est recréée via
POST avec l'identifiant `rule` du schéma PVE 9 — sauf si une règle
équivalente a été recréée entre-temps (anti-doublon). Un `Ctrl-C` traverse les `finally` : l'état zéro est restauré
avant même de rendre la main, et le script termine proprement (message
« Interruption utilisateur », code de sortie 130) au lieu d'un traceback
brut.

Cas particulier : un run interrompu **entre l'upgrade et le reboot**
laisse le nœud avec un noyau neuf installé mais non démarré
(`uname -r` ≠ dernier `vmlinuz-*`). Le run suivant détecte ce reboot en
attente même sans paquet à mettre à jour et planifie une maintenance
complète (évacuation + reboot, sans upgrade) — le nœud ne reste jamais
bloqué sur un noyau obsolète. De même, un `dpkg` interrompu en pleine
exécution (paquets `half-configured`) est détecté au run suivant via
`dpkg --audit` et rattrapé automatiquement (`dpkg --configure -a`) avant
tout `apt-get update`. Un `Ctrl-C` pendant le traitement d'un nœud
**fige** l'état (nœud laissé en maintenance, ressources HA laissées en
`ignored`) : un apt tué à mi-chemin laisse un nœud potentiellement
incohérent, la reprise se fera par le fichier d'état au run suivant.

**Reprise après incident avec `--skip-minor-updates` (v19)** : le pire
moment d'un long run, c'est de le RELANCER — Debian a publié des MAJ
mineures pendant les ~5 h du premier passage, et chaque nœud déjà
traité se voit infliger une évacuation complète (~25 min) pour
quelques paquets. L'option rend ces nœuds quasi-gratuits : seuls les
nœuds avec un vrai changement **significatif** (noyau, paquet
`pve-*`/`proxmox-*`, reboot en attente) ou pas encore traités passent
en maintenance — moins d'événements de migration, donc aussi moins de
courses QEMU au « resume ». **Caveat sécurité** : les mineures Debian
contiennent souvent des correctifs de sécurité — l'option les DIFFÈRE
par choix, n'en faites pas le mode par défaut. Usage recommandé :
relancer avec l'option pour la reprise, puis repasser un run SANS
l'option dans une autre fenêtre pour rattraper les paquets différés.

Si le fichier d'état a disparu alors que des flags de maintenance
`CEPH_MAINT_FLAGS` sont encore posés (flags « orphelins »), l'Étape 0 les
détecte et alerte avec la procédure de retrait manuel
(`ceph osd unset <flag>`) — le script ne les retire pas lui-même car
sans trace du run ils sont indiscernables de flags posés
volontairement par un administrateur.

## Ceph : fenêtre de maintenance et gates

Si le cluster a du Ceph (détection automatique, silencieuse sinon) :

- **Avant chaque évacuation/reboot** : gate `HEALTH_OK` exigé
  (`PVE_CEPH_READY_TIMEOUT`, défaut 900 s) — ne JAMAIS faire tomber un
  second nœud pendant un recovery/backfill (risque de perte simultanée de
  plusieurs copies d'un même PG). Les OSDs du nœud doivent être `up`.
- **Avant le reboot** : pose de `noout, norecover, norebalance,
  nobackfill, noscrub, nodeep-scrub` (fenêtre de maintenance : les OSDs du
  nœud redescendent `down` sans être marqués `out`, donc pas de
  reconstruction massive ni de churn au retour). Persistés dans le JSON
  avant le reboot. Les flags déjà posés par l'administrateur ne sont
  jamais touchés ni retirés.
- **Au retour du nœud** (avant les checks post-reboot) : retrait des
  flags — sans quoi l'attente de HEALTH_OK ne pourrait jamais aboutir
  (les flags eux-mêmes maintiennent un `OSDMAP_FLAGS` WARN et bloquent
  la reprise des PGs).
- **2f-bis-0, après reboot** : auto-réparation du mon Ceph de ce
  nœud (`ceph_mon_ensure`). Si le service `ceph-mon@<nœud>` est
  inactif — vécu sur un nœud dont l'instance était `disabled` : aucun
  log au boot, mon hors quorum à chaque reboot, alors qu'un restart
  manuel « fonctionnait » (sans réactiver l'instance) — le script
  logge le journal systemd (preuves), **réactive l'instance si elle
  est `disabled`/`masked`** (correctif durable, loggé), puis la
  redémarre et attend ~30 s qu'elle soit active.
- **2f-bis, après reboot** : attente de convergence
  (`PVE_CEPH_POSTBOOT_TIMEOUT`, défaut 300 s) avec trois verdicts :
  1. **Cassé** (mon hors quorum ou OSD down) → échec net ;
  2. **En convergence** (mons en quorum, tous les OSDs up, seules des PGs
     en récupération et le nombre d'objets dégradés **diminue**) →
     toléré, la récupération continue en arrière-plan — indispensable
     sur un gros cluster où le recovery peut durer des heures ;
  3. **HEALTH_OK** → succès.
- **MON_CLOCK_SKEW, auto-remédiation (v12)** : après le reboot d'un
  nœud (upgrade noyau), Ceph passe couramment en `HEALTH_WARN` «
  `mon.<nœud> clock skew 0.157s > max 0.05s` » — le mon du nœud qui
  revient mesure une horloge encore décalée (RTC au boot, chrony pas
  resynchronisé). Le warning part seul une fois l'horloge d'aplomb
  (les mons ré-évaluent au `mon_timecheck_skew_interval`, ~30 s), MAIS
  un chrony lent/coincé laissait le run échouer à la gate pour un
  problème d'**horloge**, bénin pour le stockage (vécu : verdict
  « mon/OSD probablement tombé » sur un cluster parfaitement sain).
  La ligne du health **nomme le coupable** (`mon.<nœud>` = le nœud,
  sur PVE le mon porte le nom de son hôte) : le script lit l'état
  chrony de ce nœud (`systemctl is-active chrony` + `chronyc
  tracking`, une seule commande SSH) et applique, dans l'ordre :
  `systemctl restart chrony` si le service est inactif ou
  désynchronisé ; `chronyc makestep` s'il est synchronisé mais
  l'offset dépasse 0.05 s (le rattrapage progressif laisse le
  warning vivre des minutes) ; **rien** si l'horloge est déjà juste
  (reliquat : les mons ré-évalueront seuls) ; puis attend la
  ré-évaluation des mons. **Dernier recours** uniquement : `systemctl
  restart ceph-mon@<nœud>`, si (et seulement si) l'horloge est prouvée
  juste ET que le quorum garde la majorité **stricte** — refusé à 2
  mons (sans majorité, tout le cluster figerait ses IO), désactivable
  via `PVE_CEPH_CLOCK_MON_RESTART=0`. La remédiation agit aux DEUX
  gates (post-reboot **et** avant évacuation d'un cluster resté
  skewé d'un reboot antérieur). En dry-run : rien n'est exécuté, le
  check est toléré avec l'explication de ce que le run réel ferait.
  `mon_clock_drift_allowed` n'est JAMAIS relevé (déconseillé par la
  documentation Ceph). Prévention durable : `makestep 1.0 3` dans
  `chrony.conf` fait sauter l'heure d'office au boot.
- **Parsing du health check robuste (v14)** : le champ « summary » du
  health est normalisé en texte AVANT tout parsing — PVE 9.x le
  renvoie comme **objet** `{"message": …, "severity": …}` (format
  dominant de `/cluster/ceph/status`) tandis que d'autres
  versions/chemins renvoient la chaîne brute ; passer le dict
  directement à `re.search` levait « expected string or bytes-like
  object, got 'dict' » et faisait planter la gate post-reboot en
  plein milieu de run (vécu : nœud p-proxpra-c01, 18/11). Un point
  unique de normalisation couvre les trois sites qui lisent ce champ.
- **Diagnostic détaillé** (codes des checks, sévérité, résumé, 3
  détails) loggé à chaque état non-OK rencontré.

Vérification manuelle équivalente : `ceph osd dump | grep flags` (flags
posés), `ceph -s` (santé) ; dans l'UI PVE : bouton « Manage Global Flags »
du panneau Ceph → OSD.

### Cluster client d'un Ceph externe

Sur un cluster Proxmox qui ne fait que **consommer** du stockage RBD/CephFS
d'un autre cluster (client uniquement, pas de mon/OSD local), l'endpoint
`/cluster/ceph/status` échoue (« pveceph configuration not initialized »,
501…) : le script se comporte comme « sans Ceph » — gates silencieuses,
variables `PVE_CEPH_*` ignorées. C'est le comportement voulu : rebooter un
nœud client ne fait tomber aucun daemon Ceph. Points d'attention :

- la santé du cluster Ceph **fournisseur** n'est pas vérifiée par un run
  sur le cluster client — vérifiez-la manuellement avant le run si les VMs
  dépendent de ce stockage ;
- les disques RBD externes sont du stockage partagé : migrations normales,
  pas de contrainte `PVE_WITH_LOCAL_DISKS` ;
- un montage CephFS local (LXC) qui ne remonte pas après un reboot est
  attrapé par le check « services en échec ».

## Estimations du dry-run et statistiques de durées

En fin de dry-run, un **bilan d'estimation** affiche la durée totale
approximative du run (±30 %), son détail (migrations, apt/upgrade/reboot,
fenêtres de stabilité CRM) et les fenêtres de risque des anti-affinités
« keep separate » (pics de pression RAM, durée du risque).

### Des estimations qui s'affinent toutes seules

Chaque run `--execute` **mesure** ses durées réelles et les accumule dans
`.proxmox-rolling-update.stats` (JSON, à côté du script, écriture
atomique) :

| Catégorie | Mesuré |
|---|---|
| `apt_update_s` | `apt update` + simulation apt, par nœud |
| `apt_upgrade_s` | `apt full-upgrade`, par nœud |
| `reboot_s` | reboot → retour en ligne → quorum → post-checks |
| `migrate` | live migrations QEMU sur stockage partagé (RAM + durée) |

Les LXC (migration en mode *restart* : coupure, pas de transfert RAM en
continu) et les VMs à disques locaux (copie des disques, non modélisée)
sont **exclues** des échantillons de migration pour ne pas fausser le
modèle.

Au run suivant, les moyennes observées remplacent les défauts :

- **apt / upgrade / reboot** : moyenne arithmétique des durées mesurées ;
- **migrations** : régression des moindres carrés sur le modèle
  `durée = overhead + RAM / débit` (le modèle exact du bilan), avec
  garde-fous (au moins 4 échantillons, débit borné, overhead non
  négatif) — sinon retour aux défauts ;
- **fenêtre glissante** : seuls les `PVE_STATS_MAX_SAMPLES` derniers
  échantillons par catégorie sont conservés (défaut 20) — un cluster qui
  évolue ne reste pas esclave de vieilles mesures ;
- **priorité** : variable d'environnement `PVE_EST_*` > statistiques
  observées > défauts du script — une variable d'env a toujours le
  dernier mot.

Détails d'implémentation :

- le fichier est écrit dans le `finally` du run : **même un run partiel**
  (erreur en cours de route, sortie de maintenance en filet de sécurité)
  contribue ses échantillons ;
- une écriture impossible (permissions, disque plein) n'échoue **jamais**
  le run ;
- un fichier corrompu est ignoré silencieusement (retour aux défauts) ;
- le bilan affiche la provenance de chaque hypothèse : `stats (n=X)`
  (moyenne observée), `défaut` ou `env`.

## Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `PVE_API_HOST` | — | Nœud graine (point d'entrée API) |
| `PVE_API_HOSTS` | auto | Liste CSV figée des hôtes API (sinon découverte auto) |
| `PVE_API_USER` | `automation@pam` | Utilisateur API |
| `PVE_API_TOKEN_NAME` | `rolling-update` | Nom du token |
| `PVE_API_TOKEN_VALUE` | — | Secret du token |
| `PVE_VERIFY_SSL` | `false` | Vérifier le certificat TLS |
| `PVE_SSH_USER` | `root` | Utilisateur SSH |
| `PVE_SSH_KEY` | `/etc/proxmox-updater/id_ed25519` | Clé privée SSH |
| `PVE_SSH_PASSPHRASE` | vide | Passphrase de la clé (vide = sans) |
| `PVE_SSH_PORT` | `22` | Port SSH |
| `PVE_SSH_RETRIES` | `3` | Retentatives SSH par commande (délais 15/30/45 s) ; connexion persistante par nœud |
| `PVE_WITH_LOCAL_DISKS` | `true` | Migrer les disques locaux des VMs |
| `PVE_CEPH_ALLOW_WARN` | `0` | Tolérer HEALTH_WARN aux gates Ceph (risqué) |
| `PVE_CEPH_ALLOW_AUTH_INSECURE` | `0` | Tolérer les avis cephx AUTH_INSECURE_* (CVE-2025-30156, Ceph ≥ 19.2.6) |
| `PVE_CEPH_ROTATE_CHECK_TIMEOUT_S` | `120` | Attente de propagation des checks AUTH_INSECURE_* après chaque étape de `--rotate-keys` (recalcul asynchrone des mons, s) |
| `PVE_CEPH_POSTBOOT_TIMEOUT` | `300` | Attente de convergence après reboot (s) |
| `PVE_CEPH_READY_TIMEOUT` | `900` | Attente HEALTH_OK avant évacuation/reboot (s) |
| `PVE_CEPH_CLOCK_SKEW_MAX_S` | `0.05` | Seuil d'offset horloge déclenchant `chronyc makestep` (=`mon_clock_drift_allowed`, s) |
| `PVE_CEPH_CLOCK_CHRONY_TIMEOUT_S` | `120` | Attente de resynchronisation chrony après son restart (remédiation MON_CLOCK_SKEW, s) |
| `PVE_CEPH_CLOCK_REEVAL_TIMEOUT_S` | `150` | Attente de la ré-évaluation de MON_CLOCK_SKEW par les mons avant tout restart de mon (s) |
| `PVE_CEPH_CLOCK_MON_REJOIN_TIMEOUT_S` | `180` | Attente du retour du mon dans le quorum après son restart (dernier recours, s) |
| `PVE_CEPH_CLOCK_MON_RESTART` | `1` | `0` : interdire le restart du mon en dernier recours (chrony/makestep restent actifs) |
| `PVE_EST_MIGRATE_SPEED_MBPS` | `250` | Débit effectif d'une migration live (Mo/s), bilan dry-run |
| `PVE_EST_MIGRATE_OVERHEAD_S` | `60` | Overhead fixe par migration (s), bilan dry-run |
| `PVE_EST_APT_MIN` | `2` | apt update + simulation (min/nœud), bilan dry-run |
| `PVE_EST_UPGRADE_MIN` | `6` | apt full-upgrade (min/nœud), bilan dry-run |
| `PVE_EST_REBOOT_MIN` | `9` | reboot + retour + post-checks (min/nœud), bilan dry-run |
| `PVE_STATS_FILE` | auto | Fichier de statistiques de durées (défaut : `.proxmox-rolling-update.stats` à côté du script) |
| `PVE_STATS_MAX_SAMPLES` | `20` | Fenêtre glissante d'échantillons par catégorie |
| `PVE_MIGRATE_TIMEOUT` | `600` | Plancher du timeout d'attente d'une tâche du script (s). La live migration QEMU d'une VM running reçoit un timeout **adapté à sa taille** : `max(plancher, 2 × durée estimée par le débit observé)`, plafonné à 3600 s — une VM de 160 Go à ~150 Mo/s converge en plus de 600 s. **v22 : n'agit plus sur l'attente de stabilité CRM** (désormais `PVE_HA_SETTLE_TIMEOUT`) |
| `PVE_MIGRATE_ATTEMPTS` | `2` | Tentatives totales d'une même migration quand la première échoue sur un échec transitoire (reprise v18 sur course QEMU au « resume » ; `1` = comportement antérieur : FATAL immédiat) |
| `PVE_START_TIMEOUT` | `300` | Attente max (s) du démarrage d'un guest (`qm`/`pct start`) pendant la reprise v18 — un gros guest met du temps à démarrer |
| `PVE_HA_SETTLE_TIMEOUT` | `600` | **v22** — Plancher (s) du budget d'attente de stabilité du CRM HA (`wait_ha_settled`). Le budget est **adapté à la RAM** des migrations CRM en cours (même modèle de débit que les migrations du script) + fenêtre de confirmation 60 s + marge de décision CRM ; chaque changement du set de tâches CRM **rouvre une manche** avec budget recalculé (failback multi-VMs légitime — vécu : failback CRM de ~9 min tué à tort par le budget fixe, 15 s avant la réussite) ; `recover`/`fence`/`freeze`/`lost` ne réarment pas |
| `PVE_HA_SETTLE_MAX_TOTAL` | `14400` | **v22** — Plafond **dur** (s) de la durée TOTALE d'attente de stabilité CRM, toutes manches de réarmement confondues (garde-fou anti-orage : migrations sans fin, recover/fence répétés) — 4 h par défaut |
| `PVE_HOSTS_CHECK` | `1` | `0` : désactiver l'audit/correction des `/etc/hosts` de l'Étape 0-bis |
| `PVE_LOG_FILE` | vide | Fichier de log parallèle (sans ANSI, stderr capturé) |
| `PVE_STATE_FILE` | auto | Emplacement du fichier d'état JSON |

## Limites connues

- Le rééquilibrage final peut faire « voyager » une même VM entre deux
  runs successifs si l'optimum change (anti-churn à l'étude).
- `--node` ne fait pas de failback CRM spécifique (le nœud traité est
  remis en service normalement).
- Les valeurs « RAM ~0.0G » des mini-VMs sont cosmétiques.
