# proxmox-rolling-update

Mise à jour glissante (*rolling update*) d'un cluster **Proxmox VE** —
`apt full-upgrade` + reboot, **un nœud à la fois**, sans fencing inattendu,
avec gestion du HA, de Ceph (si présent) et rééquilibrage final du cluster.

Deux scripts Python 3 (dépendances : `proxmoxer`, `paramiko`) :

- `proxmox_rolling_update.py` — mise à jour des nœuds PVE (ce README) ;
- `proxmox_ceph_rolling_update.py` — mise à jour glissante de Ceph :
  mineure par défaut, `--major RELEASE` (ex. tentacle 20.2) et
  `--rotate-keys` (remédiation CVE-2025-30156, entités déjà migrées
  re-détectées et sautées) — voir son docstring.

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

# Fichier env et log spécifiques, verbosité
python3 proxmox_rolling_update.py --execute \
    --env-file ./proxmox.env.mycluster \
    --log-file ./run-$(date +%F).log -v
```

Le fichier env est **obligatoire** (`--env-file`, défaut
`/etc/proxmox-updater/proxmox.env`) : sans lui le script s'arrête.

## Déroulé du run

**Étape 0 — Pré-vérifications** : lecture pure (quorum corosync, versions
PVE par nœud, ressources HA et règles d'affinité, état Ceph). Si un run
précédent s'est arrêté avant d'avoir tout restauré, un fichier d'état est
détecté et la **récupération** s'exécute (voir plus bas). En dry-run,
simple rapport.

**Étape 1 — par nœud** (dans l'ordre du cluster) :
- `apt update` + diagnostic espace disque : besoin estimé
  (`2 × taille installée + téléchargements + marge max(1 G, 5 %)`) comparé
  au libre (`/`, `/var`, `/boot/efi`). Si rien à mettre à jour : nœud
  sauté, ni évacuation ni reboot.
- Détachement HA (`ignored` + label, état d'origine mémorisé) puis mode
  maintenance HA.
- **Plan de migration** affiché (quelle VM va où, impact RAM/CPU estimé,
  affinités respectées), puis migrations réelles, en respectant les marges
  de sécurité RAM (AUTO : `min(max(10 % × RAM, 8 G), 48 G, 30 % × RAM)`)
  et 80 % de CPU.
- `apt full-upgrade` en streaming dans les logs ; si noyau nouveau :
  re-contrôle Ceph, **flags de maintenance Ceph** (si Ceph), reboot,
  attente du retour (uptime réinitialisé, max 15 min).
- Vérifications post-reboot : quorum, `systemd` running, services en
  échec (avec retries pour les échecs transitoires), syslog (120 s), Ceph
  (2f-bis, voir section Ceph).
- `finally` en **tout état de cause** : retrait des flags Ceph, sortie de
  maintenance, réactivation des ressources HA dans leur état d'origine,
  fenêtre de stabilité CRM de 60 s. L'état est persisté dans le JSON à
  chaque mutation.

**Étape 2 — Rééquilibrage final** : les VMs (HA détachées temporairement
pour piloter les migrations) sont repositionnées pour minimiser l'écart
de pression RAM entre nœuds (optimum théorique approché, avec tolérance
d'un point) ; les nœuds vides sont d'abord remplis (résilience), puis
l'écart optimisé. CPU surveillé (≤ 80 %). Skip si Ceph n'est pas
HEALTH_OK (sauf `PVE_CEPH_ALLOW_WARN=1`).

**Bilan final** : tables d'occupation avant/après, synthèse des
migrations et upgrades. En dry-run s'y ajoute l'estimation de durée
(voir [Estimations du dry-run](#estimations-du-dry-run-et-statistiques-de-durées)).

## Sécurités intégrées

- **Jamais deux nœuds à la fois** ; arrêt au premier problème.
- **Détection fencing** : les syslogs des AUTRES nœuds sont scrutés en
  continu pendant les phases à risque — tout fencing détecté = arrêt
  immédiat.
- **Bascule automatique de l'hôte API** (y compris préventive avant le
  reboot du nœud hébergeant l'API).
- **Affinités HA** : les règles `node-affinity` sont traitées comme
  STRICTES pour le placement ; les contraintes internes du CRM ne sont
  pas contournées pendant les migrations (c'est le but du détachement).
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

## Reprise après interruption

Run tué (`kill -9`, coupure) ⇒ le fichier d'état JSON
(`proxmox-rolling-update.state.json`) contient l'état zéro : ressources
HA détachées (avec état et comment d'origine), nœuds en maintenance, flags
Ceph posés. Au lancement suivant, l'Étape 0 détecte ce fichier et
restaure tout automatiquement (les flags Ceph sont globaux : le retrait
essaie chaque nœud jusqu'à trouver un SSH joignable), puis le run
repart. Un `Ctrl-C` traverse les `finally` : l'état zéro est restauré
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
| `PVE_WITH_LOCAL_DISKS` | `true` | Migrer les disques locaux des VMs |
| `PVE_CEPH_ALLOW_WARN` | `0` | Tolérer HEALTH_WARN aux gates Ceph (risqué) |
| `PVE_CEPH_ALLOW_AUTH_INSECURE` | `0` | Tolérer les avis cephx AUTH_INSECURE_* (CVE-2025-30156, Ceph ≥ 19.2.6) |
| `PVE_CEPH_POSTBOOT_TIMEOUT` | `300` | Attente de convergence après reboot (s) |
| `PVE_CEPH_READY_TIMEOUT` | `900` | Attente HEALTH_OK avant évacuation/reboot (s) |
| `PVE_EST_MIGRATE_SPEED_MBPS` | `250` | Débit effectif d'une migration live (Mo/s), bilan dry-run |
| `PVE_EST_MIGRATE_OVERHEAD_S` | `60` | Overhead fixe par migration (s), bilan dry-run |
| `PVE_EST_APT_MIN` | `2` | apt update + simulation (min/nœud), bilan dry-run |
| `PVE_EST_UPGRADE_MIN` | `6` | apt full-upgrade (min/nœud), bilan dry-run |
| `PVE_EST_REBOOT_MIN` | `9` | reboot + retour + post-checks (min/nœud), bilan dry-run |
| `PVE_STATS_FILE` | auto | Fichier de statistiques de durées (défaut : `.proxmox-rolling-update.stats` à côté du script) |
| `PVE_STATS_MAX_SAMPLES` | `20` | Fenêtre glissante d'échantillons par catégorie |
| `PVE_MIGRATE_TIMEOUT` | `600` | Plancher du timeout d'attente d'une tâche (s). La live migration QEMU d'une VM running reçoit un timeout **adapté à sa taille** : `max(plancher, 2 × durée estimée par le débit observé)`, plafonné à 3600 s — une VM de 160 Go à ~150 Mo/s converge en plus de 600 s |
| `PVE_LOG_FILE` | vide | Fichier de log parallèle (sans ANSI) |
| `PVE_STATE_FILE` | auto | Emplacement du fichier d'état JSON |

## Limites connues

- Le rééquilibrage final peut faire « voyager » une même VM entre deux
  runs successifs si l'optimum change (anti-churn à l'étude).
- `--node` ne fait pas de failback CRM spécifique (le nœud traité est
  remis en service normalement).
- Les valeurs « RAM ~0.0G » des mini-VMs sont cosmétiques.