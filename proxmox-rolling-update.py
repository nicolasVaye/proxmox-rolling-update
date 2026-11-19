#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxmox_rolling_update.py
=========================
Mise à jour glissante d'un cluster Proxmox VE avec HA, sans fencing inattendu.

Méthode : mode maintenance HA officiel (ha-manager node-maintenance), un nœud
à la fois, sans passer au suivant si un problème survient.

Connexion (Option C hybride) :
  - proxmoxer backend 'https' (token API) -> inventaire, migrations, reboot,
    vérifications, lecture syslogs (détection fencing).
  - proxmoxer backend 'ssh' (clé SSH)    -> ha-manager node-maintenance,
    apt full-upgrade (sortie streamée), vérification noyau.

Mode dry-run (--dry-run) : n'exécute RIEN sur les nœuds. Simule chaque étape
en mémoire (chaque action simulée est supposée réussir) et affiche, étape
par étape et nœud par nœud : tables d'occupation RAM/CPU, VMs présentes par
nœud, et plans de migration détaillés (quelle VM va où, avec impact).

Arrêt propre sur toute erreur : le bloc `finally` tente de sortir tous les
nœuds du mode maintenance avant de quitter. L'erreur est loggée (⛔ Échec)
dans le fichier de log AVANT l'exit — y compris un échec de connexion
initiale ; stderr (tracebacks, diagnostics bibliothèques) y est aussi
dupliqué, plus jamais d'échec silencieux.

Robustesse SSH : connexion PERSISTANTE par nœud (un seul handshake par
nœud et par run, réutilisée pour toutes les commandes, recréée si morte —
y compris après le reboot du nœud) ; retentatives PVE_SSH_RETRIES
(défaut 3) avec délais progressifs 15/30/45 s.

Reprise sur échec de migration (v18) : une live migration peut échouer
APRÈS un transfert complet, sur une course QEMU au « resume » du tunnel
(« tunnel replied 'ERR: resume failed - VM n not running' », vécu
18/11/2026 sur la VM 374 : transfert 3.2 GiB OK, downtime 94 ms, VM
retrouvée ARRÊTÉE sur le nœud cible et run entier interrompu). Le script
diagnostique alors où vit réellement la VM, la REDEMARRE si elle a été
assassinée par la course (sur la cible si ses disques y sont déjà, sinon
sur sa source), et retente la migration (PVE_MIGRATE_ATTEMPTS tentatives
au total, défaut 2). Le FATAL ne survient qu'après épuisement — plus
jamais une VM éteinte sans avoir tenté de la relancer.

Option --skip-minor-updates (v19) : reprise rapide après incident. Un run
complet dure ~5 h ; si Debian publie des MAJ mineures PENDANT ce run, la
relance refait chaque nœud déjà traité (évacuation complète ~25 min pour
quelques paquets sans importance). Avec l'option, un nœud dont les seules
MAJ en attente sont des paquets Debian mineurs (PAS de noyau, PAS de
paquet pve-*/proxmox-* = changement de version PVE, PAS de reboot en
attente) est IGNORÉ ce run : ni évacuation ni upgrade ni reboot — les
VMs restent en place. Les MAJ Debian contiennent souvent des correctifs
de sécurité : elles ne sont pas supprimées, seulement DIFFÉRÉES —
repasser un run SANS l'option dans une autre fenêtre pour les appliquer.

Garde-fou onboot + disques locaux (v20) : une VM stopped avec onboot=1
était TOUJOURS migrée (laissée sur place, elle partirait au boot du nœud
au retour d'upgrade — vécu 19/11 : VM 405, disques sur un storage NON
PARTAGÉ inexistant sur les autres nœuds, 2 tentatives de migration
vouées d'avance, chacune déclenchant un carrousel complet des 13 hôtes
API sur une erreur 500 pourtant DÉTERMINISTE, puis FATAL). Désormais :
sur stockage partagé → migration comme avant ; disques LOCAUX (ou
storages illisibles) → laissée sur place avec 'onboot' TEMPORAIREMENT
suspendu (PUT de config avec digest), restauré en fin de traitement du
nœud et TRACÉ dans le fichier d'état (la reprise d'un run interrompu le
restaure). L'erreur « storage … is not available on node … » est
classée déterministe : plus aucun carrousel d'hôte API. Si ni la
migration ni la suspension ne sont possibles : arrêt AVANT évacuation
(remédiation manuelle), jamais rebooter un nœud qui ferait démarrer une
VM contre toute intention.

Correctif v21 : le cache des storages partagés (_shared_storages_cache)
n'était JAMAIS initialisé dans le constructeur du client — le premier
appel à shared_storages() levait AttributeError. En dry-run l'exception
était silencieusement avalée (invocations protégées) : tous les guests
étaient classés « disques locaux : indéterminé ». En EXÉCUTION, la
porte v20 sur les VMs stopped onboot=1 (vécu 19/11, VM 405) la laissait
remonter : FATAL « 'ProxmoxClient' object has no attribute
'_shared_storages_cache' » AVANT toute migration, à la première VM
stopped du nœud. Correctif : initialisation du dict dans __init__ (et
audit AST complet : aucun autre attribut de données lu sans
initialisation).

Budget de stabilité CRM adapté (v22) : l'attente de stabilité du CRM
(wait_ha_settled) reconduisait un budget FIXE de 600 s — vécu 19/11
13:14 : le failback CRM de la VM 500 (live migration RAM-dépendante
de ~9 min) a consommé tout le budget + presque la fenêtre de
confirmation de 60 s → FATAL « cluster instable » 15 s AVANT la
réussite, à tort : le CRM TRAVAILLAIT légitimement. Le budget est
désormais DÉCOUPLÉ (PVE_HA_SETTLE_TIMEOUT, défaut 600 s) et ADAPTÉ :
il monte à la durée ESTIMÉE de la migration la plus longue en cours
(même modèle de débit que nos propres migrations, RAM lue dans
/cluster/resources) + fenêtre de confirmation + marge de décision
CRM ; chaque changement du set de tâches CRM ROUVERTE une manche avec
budget recalculé (le CRM peut légitimement enchaîner plusieurs
migrations, gros failback multi-VMs) ; les états recover/fence/… ne
réarment pas (déjà un signe de souci) ; garde-fou dur : plafond TOTAL
PVE_HA_SETTLE_MAX_TOTAL (défaut 4 h) au-delà duquel seul le FATAL
« cluster instable » est justifié.

Usage :
    python3 proxmox_rolling_update.py --dry-run
    python3 proxmox_rolling_update.py --execute
    python3 proxmox_rolling_update.py --execute --node pve-node3   # un seul nœud
    python3 proxmox_rolling_update.py --execute --skip-minor-updates  # reprise rapide
"""

# ---------------------------------------------------------------------------
# VERSION DU SCRIPT — affichée EN PREMIER dans les logs de chaque run : c'est
# la seule façon fiable de savoir QUELLE version tourne sur un cluster donné
# (des copies périmées ont déjà été prises pour des versions à jour). À
# incrémenter à CHAQUE publication.
# ---------------------------------------------------------------------------
SCRIPT_VERSION = "22"

import argparse
import base64
import json
import logging
import re
import socket
import sys
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# CONFIGURATION — à adapter à votre plateforme
# ---------------------------------------------------------------------------
# Les valeurs sensibles sont surchargées par (dans l'ordre de priorité) :
#   1) la variable d'environnement correspondante,
#   2) le fichier d'environnement passé via --env-file, chargé au démarrage
#      (ex. /etc/proxmox-updater/proxmox.env — chmod 600, root only),
#   3) les valeurs par défaut ci-dessous.
import os

def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


# Label inséré dans le champ « comment » des ressources HA passées en
# état 'ignored' : distingue les modifications faites PAR CE SCRIPT de
# celles faites manuellement par un collègue (visible dans ha.cfg/UI).
PRU_LABEL = "[proxmox-rolling-update]"


class SshTransportLost(Exception):
    """Perte de la connexion SSH (établissement ou mi-exécution) :
    retentable — l'enveloppe _ssh() reconnecte et rejoue la commande."""

API_HOST = _env("PVE_API_HOST", "pve-node1.example.com")   # nœud "graine" : point d'entrée initial
# La liste des hôtes API est DÉCOUVERTE DYNAMIQUEMENT via le cluster Proxmox
# (GET /nodes) à partir du nœud graine — plus besoin de la maintenir à la main.
# Option : la figer via PVE_API_HOSTS (liste CSV), sinon vide => découverte auto.
API_HOSTS = [h.strip() for h in _env("PVE_API_HOSTS", "").split(",") if h.strip()]
# NB : les nœuds découverts sont identifiés par leur NOM Proxmox ; il faut donc
# que ce nom soit résolvable en DNS depuis la machine qui exécute le script
# (sinon, renseigner PVE_API_HOSTS avec les FQDN/IP dans l'ordre des nœuds).
API_USER = _env("PVE_API_USER", "automation@pam")
API_TOKEN_NAME = _env("PVE_API_TOKEN_NAME", "rolling-update")
API_TOKEN_VALUE = _env("PVE_API_TOKEN_VALUE", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
VERIFY_SSL = _env("PVE_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

SSH_USER = _env("PVE_SSH_USER", "root")        # ou user dédié + sudo restreint
SSH_PRIVATE_KEY = _env("PVE_SSH_KEY", "/etc/proxmox-updater/id_ed25519")
SSH_PORT = int(_env("PVE_SSH_PORT", "22"))
# MODE NON SUPERVISÉ (cron/systemd) : utiliser une clé SANS passphrase,
# dédiée au script et restreinte dans authorized_keys des nœuds :
#   from="<ip_worker>",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA...
# Une passphrase ne peut pas être demandée de manière interactive en tâche de fond.
SSH_KEY_PASSPHRASE = _env("PVE_SSH_PASSPHRASE", "")   # "" => clé sans passphrase
# Retentatives SSH par commande (PVE_SSH_RETRIES+1 tentatives), délais
# progressifs 15/30/45 s (plafond 60) : de quoi traverser un ban
# fail2ban temporaire ; la connexion persistante par nœud limite de
# toute façon drastiquement le nombre de handshakes.
SSH_RETRIES = int(_env("PVE_SSH_RETRIES", "3"))

# Nœuds à traiter, dans l'ordre. Vide => tous les nœuds du cluster.
NODE_ORDER: List[str] = []
NODES_TO_EXCLUDE: List[str] = []

# Marges de sécurité pour le placement des VMs
# MARGE DE SÉCURITÉ RAM — calculée AUTOMATIQUEMENT par le script, nœud par
# nœud, à partir de la RAM DÉCOUVERTE lors de l'inventaire initial du
# cluster (aucune variable d'env à régler) :
#   marge(nœud) = min( max(PCT × RAM_du_nœud, MIN), MAX, PART × RAM_du_nœud )
#   - PCT  : part proportionnelle (la marge suit la taille du nœud) ;
#   - MIN  : plancher absolu (même sur un petit nœud, il faut de la marge
#            pour absorber KSM/ballooning/overhead KVM) ;
#   - MAX  : plafond absolu : 10% d'un nœud à 1 To = 100 Go inexploitables,
#            on borne la perte de capacité sur les gros nœuds (48 G ne
#            représentent plus que ~5% sur 1 To, ~13% sur 376 G) ;
#   - PART : part MAXIMALE de la RAM du nœud : sur un mini nœud (7,7 G par
#            ex.), le plancher de 8 G dépasserait sa RAM et rendrait le
#            nœud inutilisable ("allouable" négatif). On borne donc la
#            marge à 30% de la RAM : un nœud garde toujours ≥ 70% de sa
#            RAM allouable, quel que soit le cluster.
# La formule s'adapte donc au cluster découvert : marge généreuse sur les
# petits nœuds, resserrée en pourcentage sur les gros, et jamais bloquante
# sur les mini nœuds.
RAM_MARGIN_PCT = 0.10             # part proportionnelle de la RAM du nœud
RAM_MARGIN_MIN = 8 * 1024 ** 3    # plancher : 8 Go
RAM_MARGIN_MAX = 48 * 1024 ** 3   # plafond : 48 Go
RAM_MARGIN_PART = 0.30            # la marge ne dépasse jamais 30% de la RAM
                                  # du nœud (mini nœuds restent utilisables)


def margins_desc() -> str:
    """Description des marges RAM actuelles, pour les logs et erreurs."""
    return (f"AUTO — min( max({RAM_MARGIN_PCT:.0%} × RAM du nœud, "
            f"{gb(RAM_MARGIN_MIN)}), {gb(RAM_MARGIN_MAX)}, "
            f"{RAM_MARGIN_PART:.0%} × RAM du nœud )")


def rebalance_threshold(state: "ClusterState") -> float:
    """Seuil d'arrêt du rééquilibrage — mode AUTO UNIQUE :
    optimum théorique approché (+1 point de tolérance), calculé au début
    du rééquilibrage et mémorisé sur l'état."""
    if getattr(state, "theoretical_gap", -1.0) >= 0:
        return min(1.0, state.theoretical_gap + 0.01)
    return 0.10
CPU_SAFETY_MARGIN = 0.20        # ne pas dépasser 80% de CPU moyen estimé
MIGRATE_TIMEOUT = int(_env("PVE_MIGRATE_TIMEOUT", "600"))
                                # plancher du timeout d'attente d'une tâche
                                # (s) ; la live migration QEMU d'une VM
                                # running reçoit un timeout ADAPTÉ à sa
                                # taille (cf. _migrate_timeout_for) : une
                                # VM de 160 Go à ~150 Mo/s converge en
                                # >600s — un plancher FIXE la tuerait en
                                # pleine convergence.
MIGRATE_TIMEOUT_MAX = 3600      # plafond du timeout adapté (garde-fou)
MIGRATE_TIMEOUT_FACTOR = 2.0    # marge : timeout = max(plancher, FACTEUR ×
                                # durée estimée par le modèle de débit)
MIGRATE_ATTEMPTS = int(_env("PVE_MIGRATE_ATTEMPTS", "2"))
                                # REPRISE v18 sur échec de migration :
                                # nombre TOTAL de tentatives d'une même
                                # migration quand la première échoue sur
                                # un échec TRANSITOIRE (course QEMU au
                                # « resume » du tunnel, cf.
                                # _migrate_resilient). 1 = comportement
                                # v17 (échec → FATAL immédiat).
START_TIMEOUT = int(_env("PVE_START_TIMEOUT", "300"))
                                # attente max (s) du démarrage d'un
                                # guest (qm/pct start) pendant la reprise
                                # v18 — un guest 192G met du temps à
                                # redémarrer, 300s couvre large.
HA_SETTLE_TIMEOUT = int(_env("PVE_HA_SETTLE_TIMEOUT", "600"))
                                # BUDGET DE STABILITÉ CRM v22 (plancher,
                                # s) — wait_ha_settled. DÉCOUPLÉ de
                                # PVE_MIGRATE_TIMEOUT (qui reste le
                                # plancher du timeout d'UNE tâche de
                                # migration) : c'est le plancher du
                                # budget d'une « manche » d'attente de
                                # stabilité du CRM. Vécu 19/11 13:14 :
                                # le failback CRM de la VM 500 (live
                                # migration RAM-dépendante de ~9 min) a
                                # consommé tout le budget global fixe de
                                # 600 s ; FATAL « cluster instable »
                                # 15 s AVANT la fin de la fenêtre de
                                # confirmation, alors que le CRM
                                # travaillait légitimement. Le budget est
                                # désormais ADAPTÉ à la RAM des guests
                                # en migration (cf. wait_ha_settled).
HA_SETTLE_MAX_TOTAL = int(_env("PVE_HA_SETTLE_MAX_TOTAL", "14400"))
                                # plafond DUR (s) de la durée TOTALE
                                # d'attente de stabilité CRM, toutes
                                # manches de réarmement confondues :
                                # garde-fou anti-orage (migrations qui
                                # s'enchaînent sans fin, recover/fence
                                # répétés). 4 h par défaut.
HA_SETTLE_UNKNOWN_RAM_EST = 1200
                                # durée estimée (s) d'une migration CRM
                                # quand la RAM du guest est illisible
                                # dans /cluster/resources (conservateur :
                                # une VM de 160 Go chargée converge en
                                # ~1100 s réels, vécu).
CEPH_TIMEOUT = 900              # secondes max d'attente d'un Ceph HEALTH_OK
REBOOT_TIMEOUT = 900            # secondes max d'attente du retour d'un nœud

# --- REMÉDIATION CEPH « MON_CLOCK_SKEW » (après reboot d'un nœud) ----
# Après le reboot d'un nœud (upgrade noyau), Ceph passe couramment en
# HEALTH_WARN : « mon.<nœud> clock skew 0.156993s > max 0.05s » — le mon
# du nœud qui revient mesure une horloge encore décalée (RTC au boot,
# chrony pas resynchronisé). Le warning part SEUL une fois l'horloge
# d'aplomb (les mons ré-évaluent l'horloge au mon_timecheck_skew_
# interval, 30 s par défaut), MAIS si chrony est lent ou coincé le run
# reste bloqué à la gate HEALTH_OK pour un problème d'HORLOGE, bénin
# pour le stockage. Remédiation AUTOMATIQUE, dans l'ordre (chaque
# étape ne fait RIEN si l'horloge est déjà juste) :
#   1) chrony inactif/désynchronisé sur le nœud coupable → restart
#      chrony ;
#   2) synchronisé mais offset > CLOCK_SKEW_MAX_S → chronyc makestep
#      (saute l'heure immédiatement, sans toucher au service) ;
#   3) attente de la ré-évaluation par les mons (le warning part seul) ;
#   4) DERNIER RECOURS : restart ceph-mon@<nœud>, si (et seulement si)
#      l'horloge est prouvée juste ET que le quorum garde la majorité
#      STRICTE (refusé à 2 mons : sans majorité, tout le cluster fige
#      ses IO). Désactivable via PVE_CEPH_CLOCK_MON_RESTART=0.
# NB : ne JAMAIS relever « mon_clock_drift_allowed » (déconseillé par
# la documentation Ceph) — le seuil de 0.05s protège le quorum des
# mons. Prévention durable : « makestep 1.0 3 » dans chrony.conf.
CLOCK_SKEW_MAX_S = float(_env("PVE_CEPH_CLOCK_SKEW_MAX_S", "0.05"))
                                # seuil d'offset horloge déclenchant
                                # makestep (= mon_clock_drift_allowed)
CLOCK_CHRONY_TIMEOUT_S = int(_env("PVE_CEPH_CLOCK_CHRONY_TIMEOUT_S",
                                  "120"))
                                # attente max de resynchronisation
                                # chrony après restart (poll 5 s)
CLOCK_REEVAL_TIMEOUT_S = int(_env("PVE_CEPH_CLOCK_REEVAL_TIMEOUT_S",
                                  "150"))
                                # attente max de la ré-évaluation des
                                # mons (~5 cycles de 30 s)
CLOCK_MON_REJOIN_TIMEOUT_S = int(
    _env("PVE_CEPH_CLOCK_MON_REJOIN_TIMEOUT_S", "180"))
                                # attente max du retour au quorum du
                                # mon redémarré (poll 5 s)

# --- ESTIMATION DRY-RUN (bilan de fin : durée approximative du run,
# volume de migrations, fenêtres de non-respect des anti-affinités
# « keep separate ») : ordres de grandeur pour planifier la fenêtre de
# maintenance et évaluer les risques AVANT l'exécution réelle. ----
EST_MIGRATE_SPEED = int(_env("PVE_EST_MIGRATE_SPEED_MBPS", "250")) * 1024 ** 2
                                # débit EFFECTIF d'une migration live (o/s)
EST_MIGRATE_OVERHEAD_S = int(_env("PVE_EST_MIGRATE_OVERHEAD_S", "60"))
                                # overhead par migration (tâche, vm_alive, HA)
EST_APT_MIN = float(_env("PVE_EST_APT_MIN", "2"))
                                # apt update + simulation, par nœud
EST_UPGRADE_MIN = float(_env("PVE_EST_UPGRADE_MIN", "6"))
                                # apt full-upgrade, par nœud maintenu
EST_REBOOT_MIN = float(_env("PVE_EST_REBOOT_MIN", "9"))
                                # reboot + quorum + post-checks + fenêtre
                                # de stabilité CRM 60s, par nœud maintenu

# --- STATISTIQUES DE DURÉES RÉELLES (.proxmox-rolling-update.stats) -----
# Chaque run --execute MESURE les durées réelles de ses opérations
# (apt update + simulation, apt full-upgrade, séquence reboot→quorum→
# post-checks, live migrations QEMU) et les accumule dans un fichier
# JSON. Au démarrage suivant, les moyennes OBSERVÉES remplacent les
# DÉFAUTS des PVE_EST_* ci-dessus quand des échantillons existent :
# les estimations du dry-run collent de plus en plus à VOTRE cluster
# au fil des runs. Précédence : variable d'env (shell ou fichier env)
# > statistiques observées > défaut.
STATS_FILE = _env("PVE_STATS_FILE",
                  os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               ".proxmox-rolling-update.stats"))
STATS_MAX_SAMPLES = int(_env("PVE_STATS_MAX_SAMPLES", "20"))
                                # fenêtre glissante : les N derniers
                                # échantillons par catégorie (le cluster
                                # évolue, les vieilles mesures dérivent)

# provenance des EST_* pour le bilan final : {clé: "stats (n=5)"|"défaut"}
EST_PROV: Dict[str, str] = {}


def _migrate_timeout_for(ram: int) -> int:
    """Timeout EFFECTIF d'une live migration QEMU de `ram` octets :
        max(PVE_MIGRATE_TIMEOUT, FACTEUR × durée estimée), plafonné.
    Durée estimée = ram/EST_MIGRATE_SPEED + EST_MIGRATE_OVERHEAD_S —
    c'est-à-dire le débit OBSERVÉ sur VOTRE cluster dès que le fichier
    de statistiques contient des échantillons, sinon le défaut. Vécu :
    une VM de 160 Go chargée (63% CPU → pages sales sans cesse) converge
    en ~800-1100s au débit réel ; un plancher FIXE de 600s tuait la
    tâche en pleine migration. Le FACTEUR ×2 absorbe la dispersion
    (pages sales, bande passante, charge réseau de migration)."""
    est = ram / max(EST_MIGRATE_SPEED, 1) + EST_MIGRATE_OVERHEAD_S
    return int(min(max(MIGRATE_TIMEOUT, MIGRATE_TIMEOUT_FACTOR * est),
                   MIGRATE_TIMEOUT_MAX))


def load_stats() -> Optional[Dict]:
    """Fichier de statistiques s'il existe et est valide, sinon None.
    Lecture tolérante : fichier corrompu/incompatible => None (on
    repart sur les défauts, sans faire échouer le run)."""
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != 1:
        return None
    samples = data.get("samples")
    if not isinstance(samples, dict):
        return None
    return data


def _stats_mean(values: List[float]) -> Optional[float]:
    """Moyenne arithmétique des valeurs > 0 (None si aucun échantillon)."""
    vals = [float(v) for v in values if v and float(v) > 0]
    return (sum(vals) / len(vals)) if vals else None


def _stats_migrate_fit(samples: List[Dict]) -> Optional[Dict]:
    """Débit EFFECTIF et overhead des migrations depuis les échantillons
    (ram, dur) : droite des moindres carrés  dur = overhead + ram/speed.
    Le modèle du dry-run (dur = ram/EST_MIGRATE_SPEED + EST_MIGRATE_
    OVERHEAD_S) est EXACTEMENT cette droite : les échantillons des VMs
    stopped (ram=0) ancrent l'intercept (overhead), les grosses VMs
    la pente (débit). Garde-fous : ≥ 4 échantillons, rams dispersées,
    pente positive, débit plausible [5, 5000] Mo/s, overhead borné —
    sinon None (pas assez de signal : on garde les défauts)."""
    pts = [(float(s.get("ram") or 0), float(s.get("dur") or 0))
           for s in samples if s.get("dur") and float(s.get("dur")) > 0]
    n = len(pts)
    if n < 4:
        return None
    xs = [p[0] for p in pts]
    ys = [p[1] for p in pts]
    if len(set(xs)) < 2:
        return None                      # rams identiques : pas de pente
    mx, my = sum(xs) / n, sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in pts)
    var = sum((x - mx) ** 2 for x in xs)
    if var <= 0 or cov <= 0:
        return None
    speed = var / cov                    # octets/s (1/pente)
    overhead = my - (cov / var) * mx     # intercept (secondes)
    speed_mbps = speed / (1024 ** 2)
    if not (5 <= speed_mbps <= 5000):
        return None
    overhead = int(round(max(0.0, min(overhead, min(ys), 900))))
    return {"speed_mbps": int(round(speed_mbps)), "overhead_s": overhead}


def stats_derive(data: Optional[Dict]) -> Dict:
    """Paramètres OBSERVÉS (moyennes) depuis le fichier de stats.
    Retourne {clé: (valeur, n)} — une catégorie sans assez d'échantillons
    est ABSENTE : l'appelant garde alors sa valeur par défaut."""
    out: Dict = {}
    if not data:
        return out
    samples = data.get("samples") or {}

    def _put(key: str, src: str, conv):
        m = _stats_mean(samples.get(src) or [])
        if m is not None:
            out[key] = (conv(m), len(samples.get(src) or []))

    _put("apt_min", "apt_update_s", lambda s: round(s / 60, 1))
    _put("upgrade_min", "apt_upgrade_s", lambda s: round(s / 60, 1))
    _put("reboot_min", "reboot_s", lambda s: round(s / 60, 1))
    mig = [s for s in (samples.get("migrate") or [])
           if isinstance(s, dict)]
    fit = _stats_migrate_fit(mig)
    if fit:
        out["speed_mbps"] = (fit["speed_mbps"], len(mig))
        out["overhead_s"] = (fit["overhead_s"], len(mig))
    return out


def save_stats(new_samples: Dict[str, list]) -> int:
    """Fusionne les échantillons de CE run dans le fichier de stats
    (fenêtre glissante STATS_MAX_SAMPLES par catégorie, écriture
    atomique). Retourne le nombre d'échantillons ajoutés ; 0 (et
    fichier intact) si rien à écrire ou erreur d'écriture — les
    statistiques ne font JAMAIS échouer un run."""
    added = sum(len(v) for v in new_samples.values() if v)
    if added <= 0:
        return 0
    data = load_stats() or {"version": 1, "samples": {}}
    samples = data.setdefault("samples", {})
    for key, vals in new_samples.items():
        if not vals:
            continue
        cur = [v for v in (samples.get(key) or []) + list(vals)
               if v is not None]
        samples[key] = cur[-STATS_MAX_SAMPLES:]
    data["updated"] = datetime.now().isoformat(timespec="seconds")
    try:
        tmp = STATS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, STATS_FILE)
    except OSError:
        return 0
    return added


REBOOT_CHECK_INTERVAL = 10
FRESH_BOOT_UPTIME = 300         # uptime (s) sous lequel un nœud est considéré
                                # fraîchement booté (preuve du reboot effectif)
# VMs avec disques LOCAUX (storage non partagé) : activer la migration de ces
# disques (sinon la live migration échoue pour les VMs hors storage partagé).
WITH_LOCAL_DISKS = _env("PVE_WITH_LOCAL_DISKS", "true").lower() in ("1", "true", "yes")

# Mots-clés de fencing à surveiller dans les syslogs des AUTRES nœuds
FENCING_PATTERNS = [
    r"fence[d]? (node|action)",
    r"watchdog.*fence",
    r"pve-ha-crm.*fence",
    r"info: fence",
]


# ---------------------------------------------------------------------------
# LOGS COLORÉS
# ---------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    """Formateur ANSI multi-lignes : couleurs par niveau.
    Les couleurs sont automatiquement désactivées quand stdout n'est pas
    un terminal (redirection vers un fichier, cron, systemd…)."""
    ENABLED = sys.stdout.isatty()
    COLORS = {
        logging.DEBUG:    "\033[90m",   # gris
        logging.INFO:    "\033[0m",    # normal
        logging.WARNING: "\033[93m",    # jaune
        logging.ERROR:   "\033[91m",    # rouge
        logging.CRITICAL:"\033[91;1m",  # rouge gras
    }
    PREFIX = {
        logging.DEBUG:    "··· DEBUG",
        logging.INFO:    "✔",
        logging.WARNING: "⚠ ATTENTION",
        logging.ERROR:   "✘ ERREUR",
        logging.CRITICAL:"⛔ FATAL",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    GREEN = "\033[92m"

    def format(self, record):
        base = f"{time.strftime('%H:%M:%S')} [{record.levelname:<8}] {record.getMessage()}"
        prefix = self.PREFIX.get(record.levelno, "")
        if not self.ENABLED:
            return f"{prefix} {base}".strip()
        color = self.COLORS.get(record.levelno, "")
        return f"{color}{prefix} {base}{self.RESET}"


class PlainFileFormatter(logging.Formatter):
    """Formateur sans ANSI pour le fichier de log (mode --log-file)."""
    PREFIX = {
        logging.DEBUG:    "··· DEBUG",
        logging.INFO:    "✔",
        logging.WARNING: "⚠ ATTENTION",
        logging.ERROR:   "✘ ERREUR",
        logging.CRITICAL:"⛔ FATAL",
    }

    def format(self, record):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return f"{stamp} [{record.levelname:<8}] {self.PREFIX.get(record.levelno, '')} {record.getMessage()}".rstrip()


class _StderrTee:
    """Duplique stderr vers le(s) fichier(s) de log attaché(s) : les
    tracebacks et diagnostics non loggés (paramiko, bibliothèques,
    crash de dernière minute) arrivent AUSSI dans le fichier de log —
    le terminal garde son affichage inchangé."""

    def __init__(self, original):
        self._original = original
        self._sinks = []

    def attach(self, stream) -> None:
        if stream not in self._sinks:
            self._sinks.append(stream)

    def write(self, s):
        try:
            self._original.write(s)
        except Exception:
            pass
        for fh in self._sinks:
            try:
                fh.write(s)
                fh.flush()
            except Exception:
                pass
        return len(s)

    def flush(self) -> None:
        try:
            self._original.flush()
        except Exception:
            pass

    def isatty(self) -> bool:
        return self._original.isatty()

    def fileno(self) -> int:
        return self._original.fileno()

    def writable(self) -> bool:
        return True

    def close(self) -> None:  # ne JAMAIS fermer le vrai stderr
        self.flush()


def _tee_stderr_to(log_stream) -> None:
    """Attache un fichier de log comme récepteur supplémentaire de
    stderr (idempotent)."""
    tee = sys.stderr
    if not isinstance(tee, _StderrTee):
        tee = _StderrTee(tee)
        sys.stderr = tee
    tee.attach(log_stream)


def setup_logger(verbose: bool, log_file: Optional[str] = None,
                 no_color: bool = False, force_color: bool = False) -> logging.Logger:
    logger = logging.getLogger("pve-update")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Couleurs : forçées explicitement, sinon auto-détection TTY
    ColorFormatter.ENABLED = (not no_color) and (force_color or sys.stdout.isatty())

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter())
    handlers = [handler]
    # Log fichier en parallèle : format sans ANSI, horodatage complet
    if log_file:
        # Stream ligne-buffered PARTAGÉ avec le tee stderr : un seul
        # descripteur → ordre d'écriture préservé entre logger et stderr.
        stream = open(log_file, "a", encoding="utf-8", buffering=1)
        fh = logging.StreamHandler(stream)
        fh.setFormatter(PlainFileFormatter())
        handlers.append(fh)
        _tee_stderr_to(stream)
    logger.handlers = handlers
    return logger


def banner(logger: logging.Logger, title: str, color: Optional[str] = None):
    if not ColorFormatter.ENABLED:
        color = None
    c = color or ("" if not ColorFormatter.ENABLED else ColorFormatter.CYAN)
    line = "═" * 74
    bold = ColorFormatter.BOLD if ColorFormatter.ENABLED else ""
    reset = ColorFormatter.RESET if ColorFormatter.ENABLED else ""
    for ln in ("", f"{c}{bold}{line}", f"  {title}", f"{line}{reset}"):
        logger.info(ln)


def gb(bytes_value: float) -> str:
    return f"{bytes_value / (1024 ** 3):.1f}G"


def _est_hms(sec: float) -> str:
    """Secondes -> texte court (pour le bilan d'estimation dry-run)."""
    sec = int(round(sec))
    if sec >= 3600:
        h, rem = divmod(sec, 3600)
        return f"{h}h{rem // 60:02d}min"
    if sec >= 60:
        return f"{sec // 60}min{sec % 60:02d}s"
    return f"{sec}s"


def _est_mark(t: float) -> str:
    """Position dans la timeline simulée du bilan dry-run."""
    return f"T+{_est_hms(t)}"


# ---------------------------------------------------------------------------
# MODÈLE D'ÉTAT DU CLUSTER (utilisé pour le dry-run ET pour l'affichage réel)
# ---------------------------------------------------------------------------
@dataclass
class VmInfo:
    vmid: int
    name: str
    node: str
    maxmem: int          # RAM max déclarée (pour éviter l'OOM-killer)
    mem: int             # RAM réellement consommée
    maxcpu: float        # CPU moyen (0..1) observé
    status: str = "running"
    vmtype: str = "qemu"   # "qemu" ou "lxc"
    cpu_avg: float = 0.0   # CPU moyen 0..1 sur la dernière heure (RRD)
    mem_avg: int = 0       # RAM moyenne (octets) sur la dernière heure (RRD)
    cores: int = 0         # nombre de vCPUs (pour ramener le CPU VM au
                            # CPU nœud : vm.cpu × cores / node.maxcpu)

    def __str__(self):
        if self.vmtype == "lxc":
            return f"CT {self.vmid} ({self.name})"
        return f"VM {self.vmid} ({self.name})"


@dataclass
class NodeInfo:
    name: str
    maxmem: int
    mem: int
    maxcpu: int          # nombre de cœurs
    cpu: float           # usage 0..1
    cpu_avg: float = 0.0  # CPU moyen 0..1 sur la dernière heure (RRD)
    mem_avg: int = 0      # RAM moyenne (octets) sur la dernière heure (RRD)
    status: str = "online"
    in_maintenance: bool = False
    vms: List[VmInfo] = field(default_factory=list)

    def ram_after(self, extra: int) -> int:
        return self.mem + extra

    @staticmethod
    def ram_margin_for(maxmem: int) -> int:
        """Marge de sécurité RAM d'un nœud, calculée automatiquement à
        partir de sa RAM découverte lors de l'inventaire :
            marge = min( max(PCT × maxmem, MIN), MAX, PART × maxmem )
        Proportionnelle à la taille du nœud, avec plancher (petits nœuds),
        plafond (on ne gaspille pas 100 G sur un nœud à 1 To) et part
        maximale de la RAM (30% : un mini nœud reste utilisable même si
        le plancher dépasse sa RAM)."""
        return min(max(int(maxmem * RAM_MARGIN_PCT), RAM_MARGIN_MIN),
                   RAM_MARGIN_MAX, int(maxmem * RAM_MARGIN_PART))

    def ram_free_margin(self) -> int:
        """RAM encore allouable à des guests sur ce nœud, marge déduite."""
        return self.maxmem - self.ram_margin_for(self.maxmem) - self.mem


@dataclass
class ClusterState:
    nodes: Dict[str, NodeInfo] = field(default_factory=dict)
    # vmid des VMs/CT gérés par le cluster HA. Ces ressources sont
    # détachées ('ignored') par le script avant migration, puis
    # réactivées dans leur état d'origine après le traitement du nœud.
    ha_vmids: Set[int] = field(default_factory=set)
    # Affinités HA (règles 'node-affinity', PVE ≥ 9) : vmid ➔ {nœuds de
    # la règle}. Règle strict=1 = CONTRAINTE (aucun repli) ; strict=0 =
    # PRÉFÉRENCE : on tente d'abord les nœuds de la règle, repli hors
    # règle avec WARNING si saturation (sémantique du CRM lui-même).
    ha_affinity: Dict[int, Set[str]] = field(default_factory=dict)
    # Sous-ensemble DUR (règles strict=1 uniquement) : vmid ➔
    # intersection des nœuds des règles strictes. Vide si toutes les
    # règles du cluster sont soft (strict=0).
    ha_affinity_hard: Dict[int, Set[str]] = field(default_factory=dict)
    # Règles 'resource-affinity' (PVE ≥ 9) — affinités ENTRE RESSOURCES
    # (pas de champ « nodes ») : ha_together = à garder sur le MÊME nœud
    # (affinity=positive, préférence — le CRM regroupe au mieux) ;
    # ha_separate / ha_separate_hard = à garder sur des nœuds DIFFÉRENTS
    # (affinity=negative, « keep separate ») : *_hard = strict=1
    # (contrainte), sinon préférence (repli avec WARNING si saturation).
    ha_together: Dict[int, Set[int]] = field(default_factory=dict)
    ha_separate: Dict[int, Set[int]] = field(default_factory=dict)
    ha_separate_hard: Dict[int, Set[int]] = field(default_factory=dict)
    # Règles d'anti-affinité « keep separate » avec leur IDENTITÉ (pour le
    # bilan de fin de dry-run : fenêtres de non-respect PAR règle) :
    # [{"id": <id règle>, "strict": bool, "members": [vmid, ...]}, ...]
    ha_rules_info: List[Dict] = field(default_factory=list)
    # COMPATIBILITÉ QEMU/machine (v13) : une live migration est REFUSÉE
    # par PVE si le nœud cible ne sait pas exécuter la machine de la VM
    # (« Installed QEMU version '10.1.2' is too old to run machine type
    # 'pc-i440fx-11.1+pve0', please upgrade node '…' » — vécu sur un
    # cluster hétérogène). Rempli par la sonde qemu_compat_scan() à
    # chaque fetch_state :
    #   node_qemu : nœud ➔ version du binaire QEMU (« 10.1.2 »)
    #   vm_machine : vmid ➔ machine EN COURS d'exécution
    #               (« pc-i440fx-11.1+pve0 », RÉSOLUE au démarrage —
    #               même quand la config porte l'alias « pc »)
    node_qemu: Dict[str, str] = field(default_factory=dict)
    vm_machine: Dict[int, str] = field(default_factory=dict)
    # Écart de pression RAM optimal approché, calculé au début du
    # rééquilibrage final (recherche locale) et réutilisé pour le seuil
    # AUTO et le verdict du rapport final. -1 = pas encore calculé.
    theoretical_gap: float = -1.0
    # État MUTÉ par les migrations simulées/appliquées (post-inventaire) :
    # passé à True à la première mutation ; les vues affichent alors la
    # PRESSION du modèle (Σ charges des running), plus la RAM réelle de
    # l'inventaire — cf. libellé « RAM (pression) » de print_occupancy_table.
    simulated: bool = False

    def clone(self) -> "ClusterState":
        """Copie profonde pour la simulation dry-run."""
        st = ClusterState(ha_vmids=set(self.ha_vmids),
                          ha_affinity={k: set(v)
                                       for k, v in self.ha_affinity.items()},
                          ha_affinity_hard={k: set(v)
                                            for k, v in
                                            self.ha_affinity_hard.items()},
                          ha_together={k: set(v) for k, v in
                                       self.ha_together.items()},
                          ha_separate={k: set(v) for k, v in
                                       self.ha_separate.items()},
                          ha_separate_hard={k: set(v) for k, v in
                                            self.ha_separate_hard.items()},
                          ha_rules_info=[{**ri, "members": list(ri["members"])}
                                         for ri in self.ha_rules_info],
                          node_qemu=dict(self.node_qemu),
                          vm_machine=dict(self.vm_machine))
        for name, n in self.nodes.items():
            nn = NodeInfo(n.name, n.maxmem, n.mem, n.maxcpu, n.cpu,
                          n.cpu_avg, n.mem_avg, n.status, n.in_maintenance, [])
            nn.vms = [VmInfo(v.vmid, v.name, v.node, v.maxmem, v.mem, v.maxcpu,
                             v.status, v.vmtype, v.cpu_avg, v.mem_avg,
                             v.cores)
                      for v in n.vms]
            st.nodes[name] = nn
        return st


# ---------------------------------------------------------------------------
# TABLES D'OCCUPATION (affichage clair, identique en réel et en dry-run)
# ---------------------------------------------------------------------------
def vm_load(vm) -> int:
    """RAM que la VM fait peser sur son hôte DANS LE MODÈLE DE PRESSION :
    seule une VM running consomme réellement de la mémoire — une VM stopped
    n'en consomme pas. NB : les VÉRIFICATIONS DE PLACEMENT (marge, cible)
    restent basées sur vm.maxmem : une VM éteinte peut être démarrée un
    jour, sa place doit donc rester réservée."""
    return vm.maxmem if vm.status == "running" else 0


def declared_load(node) -> int:
    """Σ RAM max DÉCLARÉE des guests RUNNING hébergés par ce nœud — la
    pression DÉCLARÉE, par opposition à la RAM réellement consommée
    (node.mem). C'est la charge qui pèsera si tous les guests
    consomment réellement leur maximum : base de l'anti-overcommit."""
    return sum(vm_load(v) for v in node.vms)


def declared_fits(node, extra: int) -> bool:
    """Limite ANTI-OVERCOMMIT mémoire : un guest supplémentaire de
    charge déclarée `extra` ne peut être placé sur ce nœud que si la
    Σ RAM max déclarée des guests running (présents + extra) reste
    sous la capacité moins la marge de sécurité AUTO. Empêche d'empiler
    des VMs sur un nœud déjà sur-engagé en RAM déclarée (ex. SPV :
    488G déclarés sur 376G physiques) alors que sa RAM réelle consommée
    paraît disponible — c'est ce qui faisait monter le pic à 140%."""
    return (declared_load(node) + extra
            <= node.maxmem - node.ram_margin_for(node.maxmem))


def pressure_gap(state: ClusterState) -> Optional[float]:
    """Écart de pression RAM du cluster : différence entre le nœud online
    le plus chargé et le moins chargé (mem/maxmem). None si < 2 nœuds online.
    C'est la métrique que plan_rebalance cherche à réduire sous le seuil
    AUTO (optimum théorique approché)."""
    ps = [n.mem / n.maxmem for n in state.nodes.values()
          if n.status == "online" and not n.in_maintenance and n.maxmem]
    if len(ps) < 2:
        return None
    return max(ps) - min(ps)


def print_occupancy_table(logger: logging.Logger, state: ClusterState, title: str,
                          highlight: Optional[str] = None,
                          plans: Optional[List[Dict]] = None,
                          note: Optional[str] = None):
    """Vue arborescente unifiée du cluster : une ligne d'hyperviseur
    (RAM déclarée/consommée/libre/allouable + CPU + % + nb VMs + état)
    suivie de ses VMs en retrait (id, nom, RAM max, CPU, état, HA).
    Utilisée PARTOUT (état initial, avant/après chaque action, état
    final) pour un affichage homogène et facile à lire d'une traite.
    highlight : nœud en cours de traitement (surbrillance cyan).
    note : ligne « NB : … » affichée juste SOUS le bandeau-titre (avant
    les nœuds) pour poser la sémantique des métriques affichées (ex.
    état initial : RAM réelle vs Σ déclarée ; état final simulé :
    pression DÉCLARÉE du modèle, pas un usage mesuré)."""
    banner(logger, title, ColorFormatter.MAGENTA)
    if note:
        logger.info(f"  NB : {note}")
    # VMs qui viennent d'être déplacées (marqueur ◄ MIGRÉE) si l'appelant
    # fournit le plan appliqué (vues « après migration »).
    moved = {p["vm"].vmid: p["from"] for p in (plans or [])}
    # Impact par nœud (avant ➔ après) : RAM réelle du modèle de pression
    # (vm_load). CPU : le CPU d'une VM est une fraction de SES vCPUs, le
    # CPU d'un nœud une fraction de ses cœurs — on ramène donc la part de
    # la VM à l'échelle du nœud (vm.cpu × vCPUs / cœurs nœud, moyenne 1h
    # si disponible).
    ram_in, ram_out, cpu_in, cpu_out = {}, {}, {}, {}
    for p in (plans or []):
        vm = p["vm"]
        ld = vm_load(vm)
        share = (vm.cpu_avg or vm.maxcpu) * vm.cores   # vCPUs consommés
        ram_in[p["to"]] = ram_in.get(p["to"], 0) + ld
        ram_out[p["from"]] = ram_out.get(p["from"], 0) + ld
        tgt_max = max(state.nodes[p["to"]].maxcpu, 1)
        src_max = max(state.nodes[p["from"]].maxcpu, 1)
        cpu_in[p["to"]] = cpu_in.get(p["to"], 0) + share / tgt_max
        cpu_out[p["from"]] = cpu_out.get(p["from"], 0) + share / src_max
    for name in sorted(state.nodes):
        n = state.nodes[name]
        free = n.maxmem - n.mem
        margin = n.ram_free_margin()
        status = "maintenance" if n.in_maintenance else n.status
        mark = " ◄ MAINTENANCE" if n.in_maintenance else ""
        color = ColorFormatter.CYAN if name == highlight else ""
        if n.in_maintenance:
            color = "\033[93m"   # jaune si en maintenance
        # impact (avant ➔ après), INLINE en fin de ligne, pour les nœuds
        # touchés par le plan. Calculé AVANT l'en-tête pour que le CPU
        # affiché en tête soit l'état « après » (cohérent avec la RAM,
        # mutée par la simulation) ; l'impact montre avant ➔ après.
        r_in, r_out = ram_in.get(name, 0), ram_out.get(name, 0)
        c_in, c_out = cpu_in.get(name, 0), cpu_out.get(name, 0)
        impacted = bool(r_in or r_out or c_in or c_out)
        base_cpu = n.cpu_avg if n.cpu_avg else n.cpu
        # l'instantané CPU du nœud date d'AVANT la migration :
        # c'est la valeur « avant » ; « après » = ± charge des VMs
        # déplacées (estimation).
        cpu_after = max(base_cpu + c_in - c_out, 0.0)
        impact = ""
        if impacted:
            ram_before = n.mem - r_in + r_out
            ram_after = n.mem
            d_ram = ram_after - ram_before
            d_txt = ("+" if d_ram >= 0 else "") + gb(d_ram)
            rp_before = (ram_before / n.maxmem * 100.0
                        if n.maxmem else 0.0)
            rp_after = (ram_after / n.maxmem * 100.0
                        if n.maxmem else 0.0)
            cpu_b_txt = (f"~{base_cpu * 100:.0f}%" if n.cpu_avg
                         else f"{base_cpu * 100:.0f}%")
            cpu_a_txt = (f"~{cpu_after * 100:.0f}%" if n.cpu_avg
                         else f"{cpu_after * 100:.0f}%")
            impact = (f" ◄ impact RAM {gb(ram_before)} ➔ {gb(ram_after)} "
                      f"({d_txt}) ({rp_before:.0f}% ➔ {rp_after:.0f}%) | "
                      f"CPU {cpu_b_txt} ➔ {cpu_a_txt} (estimé)")
        # CPU/RAM de l'en-tête : moyenne RRD 1h si disponible (comparable
        # à l'UI Proxmox), sinon instantané ; si le nœud est impacté par
        # le plan, on affiche l'état « après » (RAM mutée + CPU estimé).
        head_cpu = cpu_after if impacted else base_cpu
        # État MUTÉ : un nœud sans guest running est vide en pression
        # — sa moyenne CPU 1h d'inventaire ne signifie plus rien, le
        # modèle la ramène à ~0% (cohérent avec sa RAM (pression) ~0).
        if state.simulated and not any(v.status == "running"
                                      for v in n.vms):
            head_cpu = 0.0
        cpu_txt = (f"~{head_cpu * 100:.0f}%" if n.cpu_avg
                   else f"{head_cpu * 100:.0f}%")
        # Libellé selon la sémantique : « RAM réelle » = consommation
        # mesurée de l'inventaire (moyenne 1h si dispo) ; « RAM
        # (pression) » = état interne MUTÉ (pire cas du modèle : Σ
        # charges des running). L'égalité avec « Σ déclarée » en mode
        # pression est STRUCTURELLE : un nœud vidé puis re-rempli ne
        # reçoit que des charges de guests, d'où RAM == Σ déclarée.
        # (v9 : « RAM » devient « RAM réelle » à l'état initial —
        # comparer sa consommation au « (pression) » DÉCLARÉ de l'état
        # final simulé laissait croire que la mémoire du nœud gonflait.)
        ram_lbl = "RAM (pression)" if state.simulated else "RAM réelle"
        ram_used = n.mem_avg if n.mem_avg else n.mem
        ram_used_tag = " (1h)" if n.mem_avg else ""
        ram_pct = ((ram_used / n.maxmem * 100.0)
                   if n.maxmem else 0.0)
        n_cts = sum(1 for v in n.vms if v.vmtype == "lxc")
        guests_txt = (f"{len(n.vms)} guests "
                      f"({len(n.vms) - n_cts} VMs, {n_cts} CTs)"
                      if n_cts else f"{len(n.vms)} VMs")
        # Σ RAM max DÉCLARÉE des guests running (la pression qui décide
        # du placement anti-overcommit), affichée avec son taux vs RAM
        # physique. ⚠ dès qu'elle dépasse la CAPACITÉ (RAM − marge AUTO)
        # — le sélecteur refuse alors d'y ajouter le moindre guest (seul
        # un dernier recours overcommit documenté peut y passer).
        declared = declared_load(n)
        d_pct = (declared / n.maxmem * 100.0) if n.maxmem else 0.0
        dec_txt = (f"Σ déclarée {gb(declared)} ({d_pct:.0f}%"
                   + (" ⚠" if declared
                      > n.maxmem - n.ram_margin_for(n.maxmem) else "")
                   + ")")
        head = (f"■ {name} — {ram_lbl} ~{gb(ram_used)}{ram_used_tag}/{gb(n.maxmem)} "
                f"({ram_pct:.0f}%) | libre {gb(free)} | "
                f"allouable {gb(margin)} | {dec_txt} | CPU {cpu_txt} | "
                f"{guests_txt} | {status}{mark}")
        logger.info(f"{color}{ColorFormatter.BOLD}{head}"
                    f"{ColorFormatter.CYAN}{impact}"
                    f"{ColorFormatter.RESET}")
        if not n.vms:
            logger.info("        (aucune VM)")
            continue
        for v in sorted(n.vms, key=lambda x: x.vmid):
            ha = " [HA]" if v.vmid in state.ha_vmids else ""
            mig = (f" {ColorFormatter.GREEN}◄ MIGRÉE "
                   f"(depuis {moved[v.vmid]}){ColorFormatter.RESET}"
                   if v.vmid in moved else "")
            # CPU : moyenne RRD 1h (comparable à l'UI Proxmox) ; RAM :
            # moyenne consommée sur 1h vs max déclarée.
            cpu_txt = (f"~{v.cpu_avg * 100:>4.0f}% (1h)"
                       if v.cpu_avg else f"{v.maxcpu * 100:>4.0f}%")
            ram_txt = (f"RAM ~{gb(v.mem_avg)} (1h) / {gb(v.maxmem):>8}"
                       if v.mem_avg else f"RAM max {gb(v.maxmem):>8}")
            logger.info(f"        - {'CT' if v.vmtype == 'lxc' else 'VM'} "
                        f"{v.vmid:<6} {v.name:<28} "
                        f"{ram_txt}   CPU {cpu_txt}  "
                        f"[{v.status}]{ha}{mig}")


def print_migration_plan(logger: logging.Logger, plans: List[Dict], title: str,
                          ha_vmids: Optional[Set[int]] = None,
                          ha_affinity: Optional[Dict[int, Set[str]]] = None,
                          ha_affinity_hard: Optional[Dict[int, Set[str]]] = None,
                          ha_live: bool = False):
    """Affiche un plan de migration. ha_live=True (rééquilibrage) : les
    VMs HA sont détachées ('ignored' — gel CRM : le CRM ne les touche
    pas) le temps du rééquilibrage, puis restaurées."""
    banner(logger, title, ColorFormatter.GREEN)
    if not plans:
        logger.info("Aucune migration nécessaire.")
        return
    ha_vmids = ha_vmids or set()
    ha_affinity = ha_affinity or {}
    ha_affinity_hard = ha_affinity_hard or {}
    has_ha = False
    step = 0
    for p in plans:
        vm = p["vm"]
        tgt = p["to"]
        ha = ""
        if vm.vmid in ha_vmids:
            ha = (" [HA → gelée 'ignored']" if ha_live
                  else " [HA → détachée 'ignored']")
            if vm.vmid in ha_affinity_hard:
                ha += (" [affinité DURE (strict=1): "
                       + ",".join(sorted(ha_affinity_hard[vm.vmid])) + "]")
            elif vm.vmid in ha_affinity:
                ha += (" [affinité soft (strict=0): "
                       + ",".join(sorted(ha_affinity[vm.vmid])) + "]")
            has_ha = True
        # rééquilibrage : pressions source/cible AU MOMENT DE LA DÉCISION
        # (l'état simulé est muté après chaque migration, chaque étape est
        # donc calculée sur les % réellement à jour à ce moment-là).
        pct = p.get("impact_pct")
        pct_txt = ""
        if pct:
            step += 1
            sn, sb, sa, tn, tb, ta = pct
            pct_txt = (f" [étape {step} — pression {sn}: {sb:.0%} ➔ {sa:.0%} | "
                       f"{tn}: {tb:.0%} ➔ {ta:.0%}]")
        cpu_txt = (f"~{vm.cpu_avg * 100:.0f}%" if vm.cpu_avg
                   else f"{vm.maxcpu * 100:.0f}%")
        # LXC : pas de live migration — mode restart = ARRET/redémarrage
        # (courte coupure si le CT est running) ; QEMU = à chaud.
        kind = "CT" if vm.vmtype == "lxc" else "VM"
        ct_txt = ""
        if vm.vmtype == "lxc":
            ct_txt = (" [CT — mode RESTART : arrêt/redémarrage, courte "
                      "COUPURE]" if vm.status == "running"
                      else " [CT — déjà à l'arrêt]")
        # repli overcommit (dernier recours du placement) : la cible
        # hébergera plus de RAM max déclarée que sa capacité − marge.
        oc_txt = (" [OVERCOMMIT mémoire : Σ RAM max déclarée des guests "
                  "running > capacité − marge]"
                  if p.get("overcommit") else "")
        logger.info(
            f"➤ {kind} {vm.vmid:<6} {vm.name:<26} {p['from']} ➔ {tgt:<14} "
            f"(RAM max {gb(vm.maxmem):>8}, CPU {cpu_txt:>6}) "
            f"➔ Σ déclarée cible après: {gb(p['target_mem_after'])} / "
            f"{gb(p['target_maxmem'])}{ct_txt}{oc_txt}{pct_txt}{ha}"
        )
    if has_ha:
        if ha_live:
            logger.info("  NB : les VMs marquées [HA] sont GELÉES (état "
                        "'ignored' — détachement temporaire : ni recovery, ni "
                        "relocate du CRM) pendant le rééquilibrage — les "
                        "migrations sont pilotées par le script, puis les "
                        "ressources sont restaurées dans leur état "
                        "d'origine. La cible respecte la règle d'affinité "
                        "(sinon le CRM re-migrerait la VM après le dégel : "
                        "churn en fin de run).")
        else:
            logger.info("  NB : les VMs marquées [HA] sont D'ABORD détachées "
                    "(état 'ignored' + label " + PRU_LABEL + " dans le "
                    "comment) — le CRM ne les gère plus, la migration est "
                    "pilotée par le script. Elles sont réactivées dans "
                    "leur état d'origine après le traitement du nœud.")


# ---------------------------------------------------------------------------
# COMPATIBILITÉ QEMU/MACHINE (v13)
# ---------------------------------------------------------------------------
# PVE refuse une migration vers un nœud dont le binaire QEMU est trop
# ancien pour la machine de la VM :
#   TASK ERROR: Installed QEMU version '10.1.2' is too old to run machine
#   type 'pc-i440fx-11.1+pve0', please upgrade node '…'
# Une machine « pc-i440fx-X.Y » (ou « q35-X.Y ») exige QEMU ≥ X.Y ; les
# alias « pc »/« q35 » sont RÉSOLUS au DÉMARRAGE de la VM (dans la
# version courante du QEMU du nœud d'exécution) — c'est pourquoi la
# sonde lit la machine RÉSOLUE dans la ligne de commande du processus,
# pas la valeur brute de la config. Tant que le cluster est hétérogène
# (rolling upgrade en cours), ce filtre dirige chaque VM uniquement
# vers des nœuds capables de l'exécuter.
def _machine_version(machine: Optional[str]) -> Optional[Tuple[int, int]]:
    """Extrait (majeur, mineur) d'un nom de machine PVE, ou None si
    inconnu/alias (pc, q35) ➔ pas de contrainte explicite de version."""
    if not machine:
        return None
    m = re.search(r"-(\d+)\.(\d+)", machine)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def _qemu_version(version: Optional[str]) -> Optional[Tuple[int, int]]:
    """Extrait (majeur, mineur) d'une version de binaire QEMU
    (« 10.1.2 » ➔ (10, 1)). None/absent ➔ None : sonde indisponible,
    on reste PERMISSIF (le garde-fou de PVE s'applique quand même)."""
    if not version:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?", version)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0))


def _check_summary_text(summary) -> str:
    """Normalise le « summary » d'un check de santé Ceph en TEXTE.
    PVE 9.x le renvoie comme OBJET {"message": "...", "severity": ...}
    (format dominant de /cluster/ceph/status), mais d'autres versions /
    chemins l'ont déjà renvoyé en chaîne brute : passer l'un ou l'autre
    directement à re.search passait le dict entier et levait « expected
    string or bytes-like object, got 'dict' » (crash v13 du 18/11,
    gate post-reboot de p-proxpra-c01). Un point unique de normalisation
    pour les TROIS sites qui parsent ce champ."""
    if isinstance(summary, dict):
        s = summary.get("message")
    else:
        s = summary
    if s is None:
        return ""
    return s if isinstance(s, str) else str(s)


# ---------------------------------------------------------------------------
# /etc/hosts — AUDIT DE COHÉRENCE INTER-NOEUDS (v15)
#
# Chaque /etc/hosts d'un nœud doit permettre de résoudre TOUS les nœuds
# du cluster par leur nom court (corosync, migrations live, ceph, ssh
# inter-nœuds s'appuient dessus quand le DNS n'a pas réponse). Format
# de référence (vécu sur le cluster SPV) :
#     10.158.15.70   p-c4-proxspv-21.mgmt-esx.dc.u-bordeaux.fr   p-c4-proxspv-21
# Règles de l'audit, appliquées nœud PAR nœud sur le fichier ENTIER :
#   - MANQUANT : un nœud du cluster n'apparaît nulle part par son nom
#     court (ni en alias) → correction : ligne « IP FQDN nom » ajoutée
#     en fin de fichier ;
#   - INCOHÉRENT : le nom est présent mais pointe une IP ≠ l'IP de
#     gestion connue de l'API (ou alias court absent d'une ligne qui ne
#    porte que le FQDN — getent ne résout alors PAS le nom court) →
#     correction : IP de la ligne remplacée / alias court ajouté ;
#   - DOUBLON : le nom figure sur plusieurs lignes → correction : une
#     seule ligne conservée, les autres mises en commentaire ;
#   - OBSOLÈTE : entrée qui RESSEMBLE à un nœud de CE cluster (même
#     préfixe de famille, ex. « p-c4-proxspv- » + numéro) sans être un
#     nœud actuel (ex-nœud retiré du cluster) → correction : mise en
#     COMMENTAIRE (jamais effacée — reversible, trace datée).
#
# Prudence volontaire : tout ce qui ne matche pas la famille des noms
# actuels (autres clusters, serveurs de backup/stockage, VIP…) est
# IGNORÉ — l'outil ne connaît QUE le cluster qu'il met à jour.
# Les corrections en mode --execute passent par une sauvegarde datée
# (/etc/hosts.proxmox-rolling-update.bak-AAAAMMJJ-HHMMSS) puis une
# ré-écriture atomique par base64 (pas d'échappement de shell
# possible), suivie d'une relecture de vérification.
# ---------------------------------------------------------------------------

def hosts_family_prefixes(names) -> Set[str]:
    """Préfixes de « famille » des noms de nœuds : le nom sans ses
    chiffres finaux (« p-proxpra-a01 » ➔ « p-proxpra-a », « p-c4-proxspv-21 »
    ➔ « p-c4-proxspv- »). Sert UNIQUEMENT à reconnaître, dans un
    /etc/hosts, les entrées qui ressemblent à un nœud de CE cluster
    (ex-nœud retiré du cluster mais resté dans les fichiers) : on ne
    touche à RIEN qui ne matche pas."""
    out: Set[str] = set()
    for n in names or []:
        m = re.match(r"^(.*\D)(\d+)$", str(n).strip())
        if m and m.group(1):
            out.add(m.group(1).lower())
    return out


def _hosts_entries(content: str) -> List[Dict]:
    """Lignes actives de /etc/hosts : [{idx, ip, aliases, raw}] — les
    commentaires (IPv6 désactivé, etc.) et lignes vides sont ignorés.
    Aliases en minuscules (hosts est insensible à la casse)."""
    out: List[Dict] = []
    for i, raw in enumerate((content or "").splitlines()):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            continue
        out.append({"idx": i, "ip": parts[0], "raw": raw,
                    "aliases": [a.lower() for a in parts[1:]]})
    return out


def hosts_audit(content: str, expected: Dict[str, str]) -> Dict:
    """Écart attendu/réel d'un /etc/hosts. `expected` : {nom court du
    nœud → IP de gestion}. Retour : {ok, missing, wrong, shortless,
    dup, stale} — missing/wrong/dup portent sur les nœuds du cluster,
    stale sur les entrées de la famille sans nœud correspondant.
    Fonction PURE (aucun I/O) : l'audit dry-run et la maquette de test
    l'appellent directement."""
    entries = _hosts_entries(content)
    by_alias: Dict[str, List[Dict]] = {}
    for e in entries:
        for a in e["aliases"]:
            by_alias.setdefault(a, []).append(e)
    known = {str(n).lower(): ip for n, ip in (expected or {}).items()}
    missing: List[Dict] = []
    wrong: List[Dict] = []
    shortless: List[Dict] = []
    dup: List[Dict] = []
    ok: List[str] = []
    for name, ip in sorted(known.items()):
        lines = by_alias.get(name, [])
        if not lines:
            # alias court absent : une ligne ne porte-t-elle que le FQDN ?
            fqdn_lines = [e for e in entries
                          if any(a.split(".")[0] == name
                                 for a in e["aliases"])]
            if fqdn_lines:
                good = [e for e in fqdn_lines if e["ip"] == ip]
                if good and len(fqdn_lines) == 1:
                    shortless.append({"name": name, "ip": ip,
                                      "found": fqdn_lines[0]["ip"],
                                      "idx": fqdn_lines[0]["idx"]})
                else:
                    wrong.append({"name": name, "ip": ip,
                                  "found": sorted({e["ip"]
                                                   for e in fqdn_lines}),
                                  "idx": fqdn_lines[-1]["idx"],
                                  "also_fqdn_only": True})
            else:
                missing.append({"name": name, "ip": ip})
            continue
        good = [e for e in lines if e["ip"] == ip]
        if good:
            ok.append(name)
            if len(lines) > 1:
                dup.append({"name": name, "ip": ip,
                            "kept_idx": good[-1]["idx"],
                            "stale_idx": [e["idx"] for e in lines
                                          if e["idx"] != good[-1]["idx"]]})
        else:
            wrong.append({"name": name, "ip": ip,
                          "found": sorted({e["ip"] for e in lines}),
                          "idx": lines[-1]["idx"]})
    # entrées OBSOLÈTES : famille des nœuds actuels, alias court en
    # « préfixe + numéro », mais aucun nœud actuel ne porte ce nom.
    prefs = hosts_family_prefixes(expected or {})
    stale: List[Dict] = []
    seen_lines: Set[int] = set()
    for e in entries:
        for a in e["aliases"]:
            short = a.split(".")[0]
            if short in known:
                break
            if any(re.fullmatch(re.escape(p) + r"\d+", short) for p in prefs):
                stale.append({"alias": short, "ip": e["ip"], "idx": e["idx"],
                              "raw": e["raw"]})
                seen_lines.add(e["idx"])
                break
    return {"ok": sorted(ok), "missing": missing, "wrong": wrong,
            "shortless": shortless, "dup": dup, "stale": stale}


def hosts_block_sort(lines: List[str],
                    expected: Dict[str, str]) -> List[str]:
    """Réordonne les lignes du /etc/hosts CORRIGÉ en BLOCS canoniques
    (v17) : les ajouts de nœuds manquants atterrissaient en FIN de
    fichier, APRÈS la section IPv6 — le fichier corrigé perdait sa
    structure d'origine. Ordre imposé à CHAQUE réécriture :
      1. localhost / bouclage (127.0.0.1, ::1) ;
      2. nœuds du cluster (ordre d'origine préservé, ajouts en fin de
         bloc, ajouts triés par nom car sans ordre d'origine) ;
      3. « le reste » (autres entrées : backup, autres clusters, VIP,
         commentaires neutres — ordre d'origine préservé) ;
      4. section IPv6 EN DERNIER si elle existe (bannière Debian
         « ...IPv6 capable hosts », #::1..., entrées IPv6 actives) ;
      5. tout à la fin, les lignes mises en commentaire PAR CE SCRIPT
         (retraits datés) : elles ne sont pas du contenu de
         résolution, un « cimetière » clairement séparé en fin de
         fichier est plus simple à relire puis purger.
    Les lignes vides d'origine sont remplacées par UNE ligne vide
    entre blocs. Aucun contenu n'est modifié : uniquement déplacé.
    Les fichiers déjà conformes ne sont PAS réécrits (hosts_sync
    n'écrit que sur anomalie) — ce tri ne s'applique donc qu'aux
    fichiers déjà en cours de correction."""
    known = {str(n).lower() for n in (expected or {})}
    fam = hosts_family_prefixes(expected or {})
    lb: List[str] = []       # 1. localhost / bouclage
    cl: List[str] = []       # 2. nœuds du cluster (+ retraits non marqués)
    rest: List[str] = []     # 3. le reste (entrées + commentaires neutres)
    v6: List[str] = []       # 4. section IPv6 (bannière + entrées, actives ou commentées)
    graveyard: List[str] = []  # 5. retraits produits par ce script

    def clusterish(ip: str, aliases: List[str]) -> bool:
        if any(a in known for a in aliases):
            return True
        return any(re.fullmatch(re.escape(p) + r"\d+", a.split(".")[0])
                   for p in fam for a in aliases)

    for l in lines or []:
        s = l.strip()
        if not s:
            continue                                    # séparateur régénéré
        if s.startswith("#"):
            if s.startswith("# [proxmox-rolling-update"):
                graveyard.append(l.rstrip())            # retrait daté du script
            elif re.search(r"(?i)ipv6|ip6-|::", s):
                v6.append(l.rstrip())                   # bannière + #::1...
            else:
                rest.append(l.rstrip())                 # commentaire neutre
            continue
        parts = s.split()
        ip, aliases = parts[0], [a.lower() for a in parts[1:]]
        if re.match(r"^(127\.|0\.0\.0\.0|::1\b)", ip):
            lb.append(l.rstrip())
        elif clusterish(ip, aliases):
            cl.append(l.rstrip())
        elif ":" in ip:
            v6.append(l.rstrip())
        else:
            rest.append(l.rstrip())
    blocks = [b for b in (lb, cl, rest, v6, graveyard) if b]
    return ("\n\n".join("\n".join(b) for b in blocks)).splitlines()


def hosts_fix(content: str, expected: Dict[str, str],
              fqdns: Optional[Dict[str, str]] = None
              ) -> Tuple[str, List[str]]:
    """Applique les corrections dictées par hosts_audit sur le CONTENU
    (fonction pure — l'écriture du fichier revient à l'appelant) :
    retour (nouveau_contenu, actions_lisibles). Les lignes retirées sont
    mises en commentaire daté, JAMAIS effacées."""
    fqdns = fqdns or {}
    lines = (content or "").splitlines()
    touched: Set[int] = set()
    actions: List[str] = []
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    marker = f"# [proxmox-rolling-update {stamp}]"

    def comment_out(i: int, why: str) -> None:
        lines[i] = f"{marker} {why} : {lines[i]}"
        touched.add(i)

    # 1) nœuds du cluster
    audit = hosts_audit(content, expected)
    for m in audit["missing"]:
        fqdn = (fqdns.get(m["name"]) or "").strip()
        entry = (f"{m['ip']}\t{fqdn}\t{m['name']}" if fqdn
                 else f"{m['ip']}\t{m['name']}")
        lines.append(entry)
        actions.append(f"MANQUANT → ligne ajoutée : {entry.replace(chr(9), '  ')}")
    for s in audit["shortless"]:
        i = s["idx"]
        if i in touched:
            continue
        lines[i] = f"{lines[i]} {s['name']}"
        touched.add(i)
        actions.append(f"ALIAS COURT ABSENT → « {s['name']} » ajouté à la ligne de {s['ip']}")
    for w in audit["wrong"]:
        i = w["idx"]
        if i not in touched:
            lines[i] = re.sub(r"^\S+", w["ip"], lines[i], count=1)
            touched.add(i)
            actions.append(
                f"INCOHÉRENT → « {w['name']} » : IP corrigée "
                f"({', '.join(w['found'])} → {w['ip']})")
    for d in audit["dup"]:
        for j in d["stale_idx"]:
            comment_out(j, f"doublon de « {d['name']} » ({d['ip']})")
            actions.append(f"DOUBLON → ligne de « {d['name']} » mise en commentaire (IP conservée : {d['ip']})")
    # 2) entrées obsolètes de la famille (hors lignes déjà corrigées)
    for s in audit["stale"]:
        if s["idx"] in touched:
            continue
        comment_out(s["idx"], f"« {s['alias']} » n'est pas/plus un nœud du cluster")
        actions.append(
            f"OBSOLÈTE → « {s['alias']} » ({s['ip']}) mis en commentaire : "
            "nœud absent du cluster, retirez la ligne définitivement "
            "si vous confirmez")
    # v17 : layout en blocs canoniques (localhost / cluster / reste /
    # IPv6 en dernier / retraits du script tout à la fin) — pur, sans
    # modification du contenu, uniquement l'ordre des lignes.
    lines = hosts_block_sort(lines, expected)
    return "\n".join(lines) + ("\n" if content.endswith("\n") else ""), actions


def hosts_write_files_identical(a: str, b: str) -> bool:
    """Compare deux contenus de /etc/hosts de façon STABLE, symétrique
    et indépendante du transport : toutes les commandes SSH de ce script
    tournent avec get_pty=True, et un PTY ajoute un '\\r' à chaque fin
    de ligne (translation ONLCR) — la relecture « cat » d'un fichier
    écrit en '\\n' revient donc systématiquement en '\\r\\n'. Une
    comparaison octet à octet échouait à TOUS les coups alors même que
    le fichier sur disque était PARFAIT (vécu le 18/11 : FATAL « la
    relecture diffère » sur p-c4-proxspv-10, correction sur disque
    correcte). On compare donc ligne par ligne, SANS les '\\r'/espaces
    de fin de ligne, en ignorant les lignes vides de queue (une
    absence de saut de ligne final n'est pas une corruption)."""
    def norm(s: str) -> List[str]:
        lines = [l.rstrip("\r \t") for l in (s or "").splitlines()]
        while lines and not lines[-1].strip():
            lines.pop()
        return lines
    return norm(a) == norm(b)


def hosts_write_files_diff_hint(back: str, new_content: str) -> str:
    """Premières lignes divergentes (normalisées) pour le message
    d'erreur — assez pour diagnostiquer sans noyer la log."""
    def norm(s: str) -> List[str]:
        lines = [l.rstrip("\r \t") for l in (s or "").splitlines()]
        while lines and not lines[-1].strip():
            lines.pop()
        return lines
    a, b = norm(back), norm(new_content)
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else "<absente>"
        y = b[i] if i < len(b) else "<absente>"
        if x != y:
            return (f"première divergence ligne {i + 1} : "
                    f"disque « {x[:80]} » / attendu « {y[:80]} »")
    return "aucune divergence normalisée (casse/blancs ?)"


def hosts_item_str(it: Dict, kind: str) -> str:
    """Ligne de rapport lisible pour une anomalie d'audit."""
    if kind == "missing":
        return f"MANQUANT : {it['name']} ({it['ip']})"
    if kind == "wrong":
        return (f"INCOHÉRENT : {it['name']} → pointe "
                f"{', '.join(it['found'])}, attendu {it['ip']}"
                + (" (alias court absent, ligne FQDN seulement)"
                   if it.get("also_fqdn_only") else ""))
    if kind == "shortless":
        return (f"INCOHÉRENT : {it['name']} — ligne FQDN sans alias court "
                f"(getent ne résout pas le nom court), IP {it['found']}")
    if kind == "dup":
        return (f"DOUBLON : « {it['name']} » sur "
                f"{1 + len(it['stale_idx'])} ligne(s)")
    if kind == "stale":
        return (f"EN TROP : « {it['alias']} » ({it['ip']}) — ressemble à un "
                "nœud de ce cluster mais n'en fait pas partie (retiré du "
                "cluster ?)")
    return str(it)


# ---------------------------------------------------------------------------
# SÉLECTEUR DE PLACEMENT (partagé réel/dry-run)
# ---------------------------------------------------------------------------
def plan_migrations(state: ClusterState, source: NodeInfo,
                    logger: logging.Logger,
                    exclude_ha: bool = False) -> List[Dict]:
    """Calcule les migrations des VMs de `source` vers les autres nœuds,
    de façon équitable (minimise la pression RAM+CPU des cibles),
    en exigeant que la RAM max déclarée de la VM tienne dans la marge."""
    targets = [n for n in state.nodes.values()
               if n.name != source.name and n.status == "online"
               and not n.in_maintenance]
    plans: List[Dict] = []
    if not targets:
        raise RuntimeError(f"Aucune cible disponible pour vider {source.name} !")

    # Résilience : compter les VMs déjà planifiées par cible pour privilégier
    # les nœuds encore vides. Objectif : aucun nœud (hors source) à 0 VM si
    # la RAM le permet — on évite de tout empiler sur les gros hyperviseurs.
    planned_counts: Dict[str, int] = {t.name: 0 for t in targets}
    # vmids planifiées par cible : pour l'anti-affinité « keep
    # separate », une VM du groupe séparé déjà PLANIFIÉE sur la cible
    # compte comme un occupant (l'état simulé est muté au fil de l'eau).
    planned_vmids: Dict[str, Set[int]] = {t.name: set() for t in targets}
    # Σ RAM max DÉCLARÉE (running) déjà planifiée sur chaque cible PENDANT
    # CE plan : les VMs planifiées ne sont pas encore dans tgt.vms (cet
    # état n'est muté qu'à l'application), mais elles compteront dans la
    # pression déclarée de la cible — l'anti-overcommit doit les voir.
    declared_planned: Dict[str, int] = {t.name: 0 for t in targets}

    # VMs les plus grosses d'abord (first-fit decreasing).
    # En exécution réelle (exclude_ha), les ressources HA sont exclues :
    # le CRM vient de les évacuer en mode maintenance — une migration
    # manuelle d'une ressource HA serait refusée (règles d'affinité).
    # En dry-run (exclude_ha=False) elles restent dans le plan pour
    # l'affichage, marquées [HA].
    if exclude_ha and source.vms:
        ha_here = [v for v in source.vms if v.vmid in state.ha_vmids]
        if ha_here:
            logger.warning(f"  Ignorées (ressources HA gérées par le CRM) : "
                          + ", ".join(str(v) for v in ha_here))
    for vm in [v for v in sorted(source.vms, key=lambda v: -v.maxmem)
               if not (exclude_ha and v.vmid in state.ha_vmids)]:
        placed = False
        # Compatibilité QEMU/machine (v13) : ne proposer que des cibles
        # dont le QEMU sait exécuter la machine RÉSOLUE de la VM. Les
        # VMs LXC n'ont pas de machine ; les invités arrêtés ne sont
        # pas migrés (ils restent sur place pendant le reboot), et la
        # sonde ne voit dans `ps` que les processus DÉMARÉS — le filtre
        # ne s'applique donc qu'aux candidates réelles de migration.
        # Sonde absente pour un nœud (échec SSH, version non parsée) ➔
        # pas de contrainte : on reste permissif, PVE garde son garde-fou.
        mver = _machine_version(state.vm_machine.get(vm.vmid))
        if mver is not None:
            compat = [t for t in targets
                      if _qemu_version(state.node_qemu.get(t.name)) is None
                      or _qemu_version(state.node_qemu.get(t.name)) >= mver]
            if not compat:
                # Aucune cible ne sait exécuter cette machine : donner
                # la remédiation AVANT d'échouer (l'upgrade du nœud
                # cible est la vraie solution ; en attendant, seule
                # une VM ARRÊTÉE peut rester sur un nœud plus ancien).
                versions = ", ".join(
                    f"{t.name}={state.node_qemu.get(t.name, '?')}"
                    for t in targets)
                raise RuntimeError(
                    f"Impossible de placer {vm} : sa machine "
                    f"'{state.vm_machine[vm.vmid]}' exige QEMU ≥ "
                    f"{mver[0]}.{mver[1]} et aucune cible disponible ne "
                    f"le supporte ({versions}). Remédiation : (1) "
                    f"arrêter la VM puis 'qm set {vm.vmid} --machine "
                    f"<famille>-<{mver[0]}.{mver[1]}>' (la machine "
                    f"n'est PAS changeable à chaud — au redémarrage "
                    f"elle redescend au niveau le plus ancien du "
                    f"cluster), ou (2) laisser cette VM ARRÊTÉE "
                    f"pendant ce run (un invité arrêté reste sur "
                    f"place, reboot inclus), ou (3) upgrader un nœud "
                    f"cible puis relancer le run.")
            targets_for_vm = compat
        else:
            targets_for_vm = targets
        # Affinité HA : strict=1 = CONTRAINTE DURE (aucun repli — le
        # CRM la respecterait de toute façon) ; strict=0 = PRÉFÉRENCE
        # (sémantique du CRM : repli autorisé si saturation, cf. wiki
        # Proxmox). Pas de règle = pas de contrainte.
        hard = state.ha_affinity_hard.get(vm.vmid)
        affinity = state.ha_affinity.get(vm.vmid)
        aff_no_target = False
        if hard is not None:
            allowed = [t for t in targets_for_vm if t.name in hard]
            if not allowed:
                raise RuntimeError(
                    f"Impossible de placer {vm} : sa règle d'affinité "
                    f"DURE (strict=1) n'autorise que "
                    f"{', '.join(sorted(hard))} et aucun de ces nœuds "
                    f"n'est une cible disponible (online, hors "
                    f"maintenance, QEMU compatible) pour vider "
                    f"{source.name}.")
        elif affinity is not None:
            allowed = [t for t in targets_for_vm if t.name in affinity]
            if not allowed:
                # Règle SOFT (strict=0) dont AUCUN nœud préféré n'est
                # une cible disponible — cas typique : règle mono-nœud
                # désignant précisément le nœud en cours d'évacuation
                # (ex. ha-group-C4 ➔ p-c4-ospdcctrl01 seul). Sémantique
                # du CRM : une préférence n'est PAS une contrainte —
                # on continue avec ZÉRO candidate dans la règle ; le
                # repli « hors règle » de la boucle ci-dessous opérera
                # (off_rule=True → réactivation HA différée, puis rapa-
                # triement par plan_off_rule_failback en fin de run).
                # Le cas DUR (strict=1) reste bloquant (raise ci-des-
                # sus) : le CRM refuserait lui aussi la relocation.
                aff_no_target = True
                logger.warning(
                    f"  {vm} : sa règle d'affinité "
                    f"({', '.join(sorted(affinity))}, strict=0) ne "
                    f"contient aucune cible disponible pour vider "
                    f"{source.name} (le nœud préféré est le nœud "
                    f"évacué) — REPLI hors règle, comme le ferait le "
                    f"CRM en maintenance.")
            # NB : pas de raise — une préférence vide ne bloque
            # JAMAIS l'évacuation, contrairement au strict=1.
        else:
            allowed = list(targets_for_vm)
        # Anti-affinité « keep separate » (resource-affinity negative) :
        # une cible qui héberge (ou hébergera — migrations déjà plani-
        # fiées) une VM du groupe séparé est écartée. Violation DURE
        # (strict=1) = JAMAIS ; violation soft = repli avec WARNING
        # seulement si aucune cible propre ne convient (le CRM ferait
        # de même en saturation).
        sep_hard = state.ha_separate_hard.get(vm.vmid, set())
        sep_soft = state.ha_separate.get(vm.vmid, set())
        sep_all = sep_hard | sep_soft
        if sep_all:
            def _sep_viol(t, group):
                occ = {v.vmid for v in t.vms} | planned_vmids[t.name]
                return bool(occ & group)
            hard_ok = [t for t in allowed if not _sep_viol(t, sep_hard)]
            clean = [t for t in hard_ok if not _sep_viol(t, sep_all)]
            if not hard_ok:
                raise RuntimeError(
                    f"Impossible de placer {vm} : toutes les cibles "
                    f"disponibles hébergeraient une VM d'une "
                    f"anti-affinité DURE (keep separate, strict=1 : "
                    f"{', '.join(sorted(str(x) for x in sep_hard))}).")
        else:
            clean = list(allowed)
            hard_ok = clean
        # préférence de groupe (resource-affinity positive) : cible
        # hébergeant déjà une VM du même groupe d'abord
        together = state.ha_together.get(vm.vmid, set())

        def _order(t):
            grp = 1
            if together:
                occ = {v.vmid for v in t.vms} | planned_vmids[t.name]
                grp = 0 if occ & together else 1
            return (grp, len(t.vms) + planned_counts[t.name],
                    -(t.ram_free_margin() - vm.maxmem))

        def _order_loose(t):
            # dernier recours overcommit : aggraver le MOINS possible —
            # cible dont la pression DÉCLARÉE (présente + planifiée dans
            # ce plan) est la plus basse d'abord.
            return ((declared_load(t) + declared_planned[t.name])
                    / max(t.maxmem, 1))

        def _place(cands, strict=True, off_rule=False, order=None):
            """Place `vm` sur la première candidate qui passe les barrières.
            strict=True : marge RAM RÉELLE (maxmem) + limite
            anti-overcommit mémoire (Σ RAM max déclarée des guests
            running, présents + déjà planifiés, ≤ capacité − marge) + CPU.
            strict=False : DERNIER RECOURS — seule la limite anti-overcommit
            est relâchée (documentée : clé 'overcommit' + WARNING) ; la
            marge RAM réelle et le seuil CPU restent exigés."""
            for tgt in sorted(cands, key=order or _order):
                if vm.maxmem > tgt.ram_free_margin():
                    continue            # marge RAM RÉELLE (maxmem)
                if strict and not declared_fits(
                        tgt, vm_load(vm) + declared_planned[tgt.name]):
                    continue            # limite anti-overcommit mémoire
                future_cpu = (tgt.cpu * tgt.maxcpu + vm.maxcpu) / tgt.maxcpu
                if future_cpu > (1 - CPU_SAFETY_MARGIN):
                    if strict:
                        logger.warning(
                            f"  {tgt.name}: placement de {vm} reporté "
                            f"(CPU projeté {future_cpu * 100:.0f}% > seuil)")
                    continue
                tgt.mem += vm_load(vm)   # pression : running uniquement
                tgt.cpu = future_cpu
                planned_counts[tgt.name] += 1
                planned_vmids[tgt.name].add(vm.vmid)
                declared_planned[tgt.name] += vm_load(vm)
                # Pression DÉCLARÉE cumulée après placement (présents
                # + planifiés dans CE plan) : même métrique que la
                # limite anti-overcommit et le segment « Σ déclarée »
                # des vues (le clone ne mute PAS t.vms ici, d'où le
                # declared_planned ; mem resterait réel+mutations).
                p = {"vm": vm, "from": source.name, "to": tgt.name,
                     "target_mem_after": declared_load(tgt)
                                         + declared_planned[tgt.name],
                     "target_maxmem": tgt.maxmem}
                if off_rule:
                    p["off_rule"] = True
                if not strict:
                    p["overcommit"] = True
                    logger.warning(
                        f"  → {vm} placée sur {tgt.name} en OVERCOMMIT "
                        f"mémoire : Σ RAM max DÉCLARÉE des guests running "
                        f"(présents + planifiés) = "
                        f"{gb(declared_load(tgt) + declared_planned[tgt.name])} "
                        f"> capacité − marge ({gb(tgt.maxmem - tgt.ram_margin_for(tgt.maxmem))}) "
                        f"— dernier recours : risque de swap/OOM si les "
                        f"guests consomment réellement leur maximum.")
                plans.append(p)
                return tgt
            return None

        # 1re passe : cibles PROPRES (sans voisin du groupe séparé) —
        # marge RAM réelle + limite anti-overcommit mémoire.
        tgt = _place(clean)
        placed = tgt is not None
        if not placed and clean != hard_ok:
            # toutes les cibles PROPRES ont échoué (RAM/CPU/overcommit) :
            # repli soft « keep separate » — le CRM ferait de même en
            # saturation.
            logger.warning(
                f"  {vm} : aucune cible propre pour l'anti-affinité "
                f"(keep separate, strict=0 : "
                f"{', '.join(sorted(str(x) for x in sep_all))}) ne "
                f"respecte la marge RAM / la limite anti-overcommit — "
                f"repli sur une cible hébergeant un voisin du groupe "
                f"séparé.")
            tgt = _place(hard_ok)
            placed = tgt is not None
            if placed:
                logger.warning(
                    f"  → {vm} placée sur {tgt.name} malgré le voisin "
                    f"du groupe séparé — le CRM peut la re-migrer "
                    f"après réactivation (attendu).")
        if not placed and hard is None and affinity is not None:
            # Règle SOFT (strict=0) : repli hors règle — exactement
            # ce que ferait le CRM (« si aucun des nœuds spécifiés
            # n'est disponible, la ressource peut aussi être déplacée
            # vers d'autres nœuds », wiki Proxmox). La réactivation
            # HA de cette ressource sera DIFFÉRÉE à la fin du run :
            # le CRM la re-migrerait immédiatement vers ses nœuds
            # préférés sinon (churn en pleine évacuation).
            if not aff_no_target:
                # (le cas « règle sans aucune cible disponible » est
                # déjà journalisé au calcul de `allowed` ci-dessus)
                logger.warning(
                    f"  {vm} : aucune cible de sa règle d'affinité "
                    f"({', '.join(sorted(affinity))}, strict=0) ne "
                    f"respecte la marge RAM / la limite anti-overcommit "
                    f"({margins_desc()}) — REPLI hors règle (préférence, "
                    f"pas contrainte : le CRM ferait de même).")
            # repli HORS règle : TOUTES les cibles (pas seulement
            # celles de la règle) — seule l'anti-affinité DURE reste
            # bloquante ici
            off_targets = [t for t in targets
                          if not ({v.vmid for v in t.vms}
                                  | planned_vmids[t.name]) & sep_hard]
            tgt = _place(off_targets, off_rule=True)
            placed = tgt is not None
            if placed:
                logger.warning(
                    f"  → {vm} repliée sur {tgt.name} "
                    f"(HORS règle) — réactivation HA différée "
                    f"à la fin du run.")
        if not placed:
            # DERNIER RECOURS : aucune cible (propre / voisins séparés /
            # hors règle) ne respecte la limite anti-overcommit mémoire.
            # Mieux vaut un plan qui aboutit avec un overcommit DOCUMENTÉ
            # (WARNING ici + récapitulatif dans le bilan) qu'un run
            # impossible : on relâche la limite anti-overcommit (la marge
            # RAM RÉELLE et le seuil CPU restent exigés) en visant les
            # cibles les moins sur-engagées pour aggraver le moins
            # possible. Une règle d'affinité DURE (strict=1) n'est JAMAIS
            # contournée ; l'anti-affinité « keep separate » DURE reste
            # bloquante dans tous les cas.
            if hard is not None:
                pool = hard_ok
            else:
                pool = [t for t in targets
                        if not ({v.vmid for v in t.vms}
                                | planned_vmids[t.name]) & sep_hard]
            logger.warning(
                f"  {vm} : AUCUNE cible ne respecte la limite "
                f"anti-overcommit mémoire — dernier recours : placement "
                f"avec OVERCOMMIT documenté (risque de swap/OOM si les "
                f"guests consomment réellement leur maximum).")
            tgt = _place(pool, strict=False,
                         off_rule=(hard is None and affinity is not None),
                         order=_order_loose)
            placed = tgt is not None
        if not placed:
            if hard is not None:
                raise RuntimeError(
                    f"Impossible de placer {vm} (RAM max {gb(vm.maxmem)}) : "
                    f"aucune cible de sa règle d'affinité DURE "
                    f"({', '.join(sorted(hard))}, strict=1) ne respecte la "
                    f"marge RAM ni la limite anti-overcommit mémoire "
                    f"({margins_desc()}).")
            raise RuntimeError(
                f"Impossible de placer {vm} (RAM max {gb(vm.maxmem)}) : "
                f"aucune cible ne respecte la marge RAM ni la limite "
                f"anti-overcommit mémoire ({margins_desc()}).")

    return plans


def hors_rule_vmids(state: ClusterState) -> Set[int]:
    """Ressources HA dont le nœud COURANT de l'état (simulé ou réel)
    n'est PAS autorisé par leur règle 'node-affinity' (soft OU dure) :
    typiquement déplacées pendant l'Étape 1 pendant le sommeil des
    règles (le placement était LIBRE — c'est le but), ou repliées
    hors règle à la réactivation HA (saturation strict=0). Ce sont
    elles que le CRM re-localisera au dégel final (pour une DURE :
    certain ; pour une soft : probable). Les VMs sans HA sont exclues :
    le CRM ne les gère pas, aucune churn possible."""
    out: Set[int] = set()
    for vmid, aff in state.ha_affinity.items():
        if vmid not in state.ha_vmids:
            continue
        for n in state.nodes.values():
            if any(v.vmid == vmid for v in n.vms):
                if n.name not in aff:
                    out.add(vmid)
                break
    return out


def plan_off_rule_failback(state: ClusterState, logger: logging.Logger,
                           vmids: Set[int],
                           second_pass: bool = False) -> List[Dict]:
    """Avant le rééquilibrage final : rapatrie vers leurs nœuds de règle
    TOUTE ressource HA qui se trouve encore HORS règle à ce stade :
    - repli strict=0 pendant l'Étape 1 (saturation au moment de
      l'évacuation — l'ensemble passé en argument, suivi par le run),
    - ET toute ressource déplacée pendant que les règles étaient en
      sommeil (l'Étape 1 vide les contraintes : une VM mono-nœud est
      forcément déplacée hors règle quand SON nœud est évacué) —
      détecté par hors_rule_vmids(), règle soft OU dure, VM running
      (le CRM la re-migrerait au dégel) comme stopped (migration hors
      ligne : elle sera déjà conforme à sa prochaine mise route —
      onboot=1 au boot du nœud compris).
    Objectif : un dégel final COHÉRENT — sans cela, le CRM
    re-migrerait la ressource hors-règle juste après le dégel (« nach
    kurzer Zeit », forum Proxmox), cassant en post-run l'équilibre que
    le rééquilibrage vient d'atteindre. Le rapatriement est planifié ICI
    (état simulé muté, mêmes sémantiques que plan_rebalance) et exécuté
    PENDANT la fenêtre de gel CRM, AVANT le rééquilibrage proprement
    dit — le rééquilibrage optimise donc AUTOUR du placement conforme.
    Si aucun nœud de la règle ne respecte la marge RAM/CPU : la
    ressource reste sur son hôte actuel (WARNING) — en 1re passe
    (second_pass=False), le WARNING annonce la SECONDE passe
    post-rééquilibrage (toujours rejouée dans la fenêtre de gel) ;
    en seconde passe (second_pass=True), seule issue restante, il
    annonce l'action du CRM au dégel — certaine pour une règle DURE
    (strict=1), probable pour une soft (comportement attendu, pas
    une anomalie)."""
    vmids = set(vmids) | hors_rule_vmids(state)
    plans: List[Dict] = []
    for vmid in sorted(vmids):
        vm = None
        src = None
        for n in state.nodes.values():
            for v in n.vms:
                if v.vmid == vmid:
                    vm, src = v, n
                    break
            if vm is not None:
                break
        if vm is None:
            continue                 # plus dans l'état (edge) : rien à faire
        affinity = state.ha_affinity.get(vmid)
        if not affinity:
            continue
        if src.name in affinity:
            # déjà sur un nœud de sa règle (edge/reprise) : rien à faire
            continue
        hard_rule = vmid in state.ha_affinity_hard
        kind = "DURE (strict=1)" if hard_rule else "soft (strict=0)"
        sep_hard = state.ha_separate_hard.get(vmid, set())
        sep_soft = state.ha_separate.get(vmid, set())
        together = state.ha_together.get(vmid, set())
        cands = []
        for n in state.nodes.values():
            if (n.name in affinity and n.status == "online"
                    and not n.in_maintenance
                    and vm.maxmem <= n.ram_free_margin()
                    and declared_fits(n, vm_load(vm))):
                future_cpu = (n.cpu * n.maxcpu + vm.maxcpu) / n.maxcpu
                if future_cpu > (1 - CPU_SAFETY_MARGIN):
                    continue
                # anti-affinité « keep separate » : un nœud hébergeant
                # déjà une VM du groupe séparé n'est PAS un candidat —
                # pas de repli ici : le but est un dégel final COHÉRENT,
                # recréer une cohabitation ferait exactement le churn
                # CRM que le rapatriement doit éviter.
                if {v.vmid for v in n.vms} & (sep_hard | sep_soft):
                    continue
                cands.append(n)
        if not cands:
            if second_pass:
                logger.warning(
                    f"  {vm} : rapatriement impossible sur sa règle "
                    f"({', '.join(sorted(affinity))}, {kind}) même "
                    f"après le rééquilibrage — aucun nœud de la règle "
                    f"ne respecte la marge RAM/CPU, la limite "
                    f"anti-overcommit mémoire ou l'anti-affinité "
                    f"keep-separate : elle reste sur "
                    f"{src.name} (hôte actuel) ; le CRM "
                    + ("la RELOCALISERA au dégel (règle DURE violée)"
                       if hard_rule else
                       "pourra la re-migrer après le dégel (préférence)")
                    + " (comportement attendu, pas une anomalie).")
            else:
                # 1re passe : la SECONDE passe post-rééquilibrage est
                # TOUJOURS rejouée ensuite (même fenêtre de gel) — ne
                # pas annoncer une relocalisation CRM comme certaine,
                # le rééquilibrage peut libérer le nœud de règle
                # saturé (cas réel RHOSPDC : DUREs 101/103).
                logger.warning(
                    f"  {vm} : rapatriement impossible sur sa règle "
                    f"({', '.join(sorted(affinity))}, {kind}) à la 1re "
                    f"passe — aucun nœud de la règle ne respecte la "
                    f"marge RAM/CPU, la limite anti-overcommit mémoire "
                    f"ou l'anti-affinité keep-separate à ce stade : "
                    f"elle reste sur {src.name} (hôte actuel) ; "
                    f"SECONDE PASSE de rapatriement prévue après le "
                    f"rééquilibrage — si elle échoue aussi, le CRM "
                    + ("la RELOCALISERA au dégel (règle DURE violée)"
                       if hard_rule else
                       "pourra la re-migrer après le dégel (préférence)")
                    + " (comportement attendu, pas une anomalie).")
            continue
        # cible : nœud de la règle avec le PLUS de marge RAM ; préférence
        # de groupe (positive) : nœud hébergeant déjà une VM du même
        # groupe d'abord ; départage alphabétique (reproductibilité)
        cands.sort(key=lambda n: (
            0 if (together and {v.vmid for v in n.vms} & together) else 1,
            -n.ram_free_margin(), n.name))
        tgt = cands[0]
        # mutation de l'état simulé — mêmes sémantiques que plan_rebalance
        src.vms.remove(vm)
        tgt.vms.append(vm)
        vm.node = tgt.name
        ld = vm_load(vm)
        src.mem -= ld
        tgt.mem += ld
        # tgt.vms a été re-appendé ci-dessus : declared_load(tgt) est
        # déjà la pression déclarée APRÈS ce rapatriement.
        plans.append({"vm": vm, "from": src.name, "to": tgt.name,
                      "target_mem_after": declared_load(tgt),
                      "target_maxmem": tgt.maxmem,
                      "off_rule_failback": True})
        extra = ""
        if vm.status != "running":
            extra = (" ; VM stopped : migration HORS LIGNE (métadonnées "
                     "seules), elle sera déjà sur un nœud conforme à sa "
                     "prochaine mise en route")
        pass_note = (" — 2e passe post-rééquilibrage"
                     if second_pass else "")
        logger.info(f"  {vm} : rapatriement {src.name} ➔ {tgt.name} "
                    f"(nœud de sa règle {kind}{pass_note}{extra} — marge RAM "
                    f"restante après placement : "
                    f"{gb(tgt.ram_free_margin())}) : "
                    f"le dégel final n'aura rien à corriger ✔")
    return plans


def plan_rebalance(state: ClusterState, logger: logging.Logger) -> List[Dict]:
    """Étape 4 : rééquilibre équitable sur l'ensemble du cluster.
    Déplace les VMs tant que l'écart de pression RAM dépasse
    REBALANCE_THRESHOLD. La phase 2 n'évalue PAS seulement le couple
    (nœud le plus chargé ➔ nœud le plus vide) : quand des règles
    d'affinité HA confinent les VMs sur un sous-ensemble de nœuds, la
    cible la plus vide est souvent hors règle et ce couple est bloqué
    alors qu'un mouvement intra-règle améliorerait l'écart global —
    on évalue donc TOUS les couples (source ➔ cible) valides et on
    retient le mouvement qui minimise l'écart de pression RAM GLOBAL.

    Garanties de terminaison :
    - l'état simulé est réellement muté (la VM quitte la liste .vms de son
      nœud pour rejoindre la cible) => une VM déjà déplacée ne peut pas être
      re-déplacée depuis son nœud d'origine ;
    - l'ensemble 'moved' interdit tout ping-pong (déplacer 2 fois une VM) ;
    - la phase 2 s'arrête dès qu'AUCUN mouvement ne réduit l'écart de
      pression RAM GLOBAL : migrer ne servirait qu'à déplacer de la charge
      sans gagner en équilibre (migrations live inutiles évitées) ;
    - MAX_MOVES borne le nombre total de migrations en dernier recours.
    """
    REBALANCE_THRESHOLD = None      # AUTO : fixé après calcul de l'optimum
    plans: List[Dict] = []
    moved = set()                # vmids déjà déplacés (anti ping-pong)

    # Une VM HA réactivée PEUT être déplacée ici (migration live supportée
    # par le CRM), MAIS uniquement vers un nœud autorisé par sa règle
    # d'affinité si elle en a une — sinon le CRM la re-migrerait (churn).
    def _placement_ok(vm, tgt) -> bool:
        if vm.vmid not in state.ha_vmids:
            return True
        allowed = state.ha_affinity.get(vm.vmid)
        if allowed and tgt.name not in allowed:
            return False        # node-affinity (soft = contrainte ici)
        # anti-affinité « keep separate » : JAMAIS deux VMs du même
        # groupe séparé sur un même nœud pendant le rééquilibrage —
        # sinon le CRM re-migrerait juste après le dégel (churn).
        sep = (state.ha_separate.get(vm.vmid, set())
               | state.ha_separate_hard.get(vm.vmid, set()))
        if sep and {v.vmid for v in tgt.vms} & sep:
            return False
        return True

    # --- affichage étape par étape : vue arborescente COMPLÈTE du cluster
    # (mêmes lignes que partout ailleurs) après CHAQUE migration simulée,
    # avec la VM déplacée marquée ◄ MIGRÉE sur sa cible.
    step = 0
    last_gap = None       # écart de pression global après l'étape précédente

    def _log_step(src, sb, sa, tgt, tb, ta, vm):
        nonlocal step, last_gap
        step += 1
        gap_after = _gap(_online())
        gb_txt = (f" | écart global : {last_gap:.0%} ➔ {gap_after:.0%}"
                  if last_gap is not None
                  else f" | écart global : {gap_after:.0%}")
        print_occupancy_table(
            logger, state,
            f"RÉÉQUILIBRAGE — ÉTAPE {step} : VM {vm.vmid} ({vm.name}) : "
            f"{src.name} ➔ {tgt.name} "
            f"(pression {src.name}: {sb:.0%} ➔ {sa:.0%} | "
            f"{tgt.name}: {tb:.0%} ➔ {ta:.0%}){gb_txt}",
            plans=[{"vm": vm, "from": src.name, "to": tgt.name}])
        last_gap = gap_after

    print_occupancy_table(logger, state, "RÉÉQUILIBRAGE — ÉTAT DE DÉPART")

    def _online():
        return [n for n in state.nodes.values()
                if n.status == "online" and not n.in_maintenance]

    def _gap(nodes):
        ps = [n.mem / n.maxmem for n in nodes]
        return max(ps) - min(ps)

    # NB RÉSILIENCE : seule une VM RUNNING compte — une VM stopped n'apporte
    # ni charge ni reprise sur panne ; un nœud qui n'héberge que des VMs
    # éteintes est traité comme vide.
    def _running(node) -> List:
        return [v for v in node.vms if v.status == "running"]

    # --- écart de pression global actuel vs OPTIMUM THÉORIQUE approché :
    # recherche locale (descente steepest + redémarrages aléatoires seedés,
    # reproductibles) sur toutes les VMs running librement réaffectables
    # (règles d'affinité respectées). Indique le meilleur écart atteignable,
    # pour situer le résultat du rééquilibrage.
    def _theoretical_gap() -> float:
        on = _online()
        if len(on) < 2:
            return 0.0
        items = []                      # (charge, nœuds autorisés, hôte actuel)
        for n in on:
            for v in n.vms:
                if v.status != "running":
                    continue
                allowed = {x.name for x in on}
                if v.vmid in state.ha_vmids:
                    a = state.ha_affinity.get(v.vmid)
                    if a:
                        allowed &= a
                items.append((vm_load(v), allowed, n.name))
        if not items:
            return 0.0
        names = [x.name for x in on]
        maxs = {x.name: x.maxmem for x in on}
        import random
        rnd = random.Random(0)          # graine fixe : reproductible

        def gap_of(assign):
            mem = dict.fromkeys(names, 0)
            for (ld, _a, _h), j in zip(items, assign):
                mem[names[j]] += ld
            ps = [mem[nm] / max(maxs[nm], 1) for nm in names]
            return max(ps) - min(ps)

        def descend(start):
            a = list(start)
            g = gap_of(a)
            while True:
                bestg, besta = g, a
                for i in range(len(items)):
                    for j in range(len(names)):
                        if j == a[i] or names[j] not in items[i][1]:
                            continue
                        b = list(a)
                        b[i] = j
                        gb = gap_of(b)
                        if gb < bestg:
                            bestg, besta = gb, b
                if bestg >= g:
                    return g
                a, g = besta, bestg

        cur = [names.index(h) for (_ld, _a, h) in items]
        best = descend(cur)
        for _ in range(25):
            r = [rnd.randrange(len(names)) for _ in items]
            for i, (_ld, allowed, h) in enumerate(items):
                if names[r[i]] not in allowed:
                    r[i] = names.index(h)
            best = min(best, descend(r))
        return best

    last_gap = _gap(_online())
    theo = _theoretical_gap()
    state.theoretical_gap = theo
    # AUTO UNIQUE : viser l'optimum théorique (+1 point de tolérance).
    REBALANCE_THRESHOLD = min(1.0, theo + 0.01)
    thr_desc = "AUTO : optimum théorique + 1 point"
    logger.info(f"[rebalance] Écart de pression RAM global : {last_gap:.0%} "
                f"— optimum théorique approché : {theo:.0%} "
                f"(cible : {REBALANCE_THRESHOLD:.0%} — {thr_desc})")

    # --- Phase 1 : RÉSILIENCE — aucun nœud online sans VM RUNNING, si on
    # peut l'éviter. On remplit chaque nœud vide avec une VM running prise
    # sur un nœud qui en a AU MOINS 2 (jamais au prix d'en priver un autre).
    # On essaie CHAQUE nœud vide (pas seulement le premier) : une règle
    # d'affinité HA peut interdire le premier nœud vide mais pas les autres.
    # Parmi les coups possibles, on choisit celui qui minimise l'écart final.
    while True:
        online = _online()
        if len(online) < 2:
            break
        empty = sorted((n for n in online if len(_running(n)) == 0),
                       key=lambda n: n.name)
        donors = [n for n in online if len(_running(n)) >= 2]
        if not empty or not donors:
            break
        best = None             # (écart_après, cible, source, vm)
        for tgt in empty:
            for src in donors:
                for vm in _running(src):
                    if vm.vmid in moved or not _placement_ok(vm, tgt) \
                            or vm.maxmem > tgt.ram_free_margin() \
                            or not declared_fits(tgt, vm_load(vm)):
                        continue
                    ld = vm_load(vm)
                    src_p = (src.mem - ld) / src.maxmem
                    tgt_p = (tgt.mem + ld) / tgt.maxmem
                    others = [n.mem / n.maxmem for n in online
                              if n is not src and n is not tgt]
                    gap_after = max([src_p, tgt_p] + others) - min([src_p, tgt_p] + others)
                    if best is None or gap_after < best[0]:
                        best = (gap_after, tgt, src, vm)
        if best is None:
            logger.warning("Nœud(s) restant sans VM running : "
                           + ", ".join(n.name for n in empty)
                           + " — aucune VM running déplaçable ne respecte la "
                             "marge RAM (souvent bloqué par une règle "
                             "d'affinité HA).")
            break
        _, tgt, src, vm = best
        # pressions AVANT la mutation (pour l'affichage étape par étape)
        sb = src.mem / max(src.maxmem, 1)
        tb = tgt.mem / max(tgt.maxmem, 1)
        src.vms.remove(vm)
        tgt.vms.append(vm)
        vm.node = tgt.name
        ld = vm_load(vm)
        src.mem -= ld
        tgt.mem += ld
        moved.add(vm.vmid)
        # tgt.vms re-appendé : declared_load(tgt) = pression déclarée
        # APRÈS ce déplacement (mem resterait réel+mutations).
        plans.append({"vm": vm, "from": src.name, "to": tgt.name,
                      "target_mem_after": declared_load(tgt),
                      "target_maxmem": tgt.maxmem,
                      "impact_pct": (src.name, sb, src.mem / max(src.maxmem, 1),
                                     tgt.name, tb, tgt.mem / max(tgt.maxmem, 1))})
        _log_step(src, sb, src.mem / max(src.maxmem, 1),
                  tgt, tb, tgt.mem / max(tgt.maxmem, 1), vm)
        logger.debug(f"[rebalance/resilience] {vm.name} : {src.name} ➔ {tgt.name} "
                     f"(remplissage du nœud vide)")

    # --- Phase 2 : équilibrage des pressions RAM (meilleur mouvement GLOBAL) -
    # On ne se limite PAS au couple (nœud le plus chargé ➔ nœud le plus
    # vide) : quand des règles d'affinité HA confinent les VMs sur un
    # sous-ensemble de nœuds (ex. PRA : tout le HA sur 3 nœuds sur 9), la
    # cible la plus vide est hors règle et le couple est bloqué, alors
    # qu'un mouvement intra-règle réduisait l'écart global (ex. une VM
    # 16G b03 ➔ c03). On évalue donc TOUS les couples (source ➔ cible)
    # valides et on retient le mouvement qui minimise l'écart de pression
    # RAM GLOBAL après coup.
    while True:
        online = _online()
        if len(online) < 2:
            break
        pressures = {n.name: n.mem / max(n.maxmem, 1) for n in online}
        gap_before = max(pressures.values()) - min(pressures.values())
        if gap_before <= REBALANCE_THRESHOLD:
            break                                   # cluster équilibré : fin
        # choix du mouvement qui MINIMISE l'écart de pression RAM GLOBAL
        # après coup (plus petite VM en cas d'égalité) ; sources triées de
        # la plus chargée à la moins chargée (on vide d'abord les pics) ;
        # si AUCUN mouvement n'améliore, on s'arrête : migrer ne ferait
        # que déplacer de la charge sans équilibrer davantage
        # (migrations live inutiles).
        chosen = None           # (gap_after, fix, source, cible, vm)
        for src in sorted(online, key=lambda n: -pressures[n.name]):
            # RÉSILIENCE : ne jamais déplacer la DERNIÈRE VM RUNNING d'un
            # nœud — sinon la phase 2 vide un nœud que la phase 1 venait
            # de remplir.
            if len(_running(src)) <= 1:
                continue
            src_ids = {v.vmid for v in src.vms}
            for vm in sorted((v for v in src.vms if v.vmid not in moved),
                             key=lambda v: v.maxmem):
                ld = vm_load(vm)
                # DÉPARTAGE à égalité d'écart : privilégier le mouvement
                # qui SÉPARE des voisins d'une règle « keep separate »
                # co-localisés (repli soft de l'évacuation) — sinon le
                # CRM re-migrerait la VM juste après le dégel (churn),
                # précisément ce que le plan veut éviter.
                sep = (state.ha_separate.get(vm.vmid, set())
                       | state.ha_separate_hard.get(vm.vmid, set()))
                fixes = bool((src_ids - {vm.vmid}) & sep)
                for tgt in online:
                    if tgt is src:
                        continue
                    if not _placement_ok(vm, tgt):
                        continue    # HA : règle d'affinité interdit cette cible
                    if vm.maxmem > tgt.ram_free_margin():
                        continue    # ne tient pas dans la marge de la cible
                    if not declared_fits(tgt, ld):
                        continue    # cible sur-engagée en RAM déclarée
                    nb = (src.mem - ld) / max(src.maxmem, 1)
                    ne = (tgt.mem + ld) / max(tgt.maxmem, 1)
                    others = [pressures[n.name] for n in online
                              if n is not src and n is not tgt]
                    ga = max([nb, ne] + others) - min([nb, ne] + others)
                    if chosen is None or ga < chosen[0] - 1e-9 \
                            or (abs(ga - chosen[0]) <= 1e-9
                                and fixes and not chosen[1]):
                        chosen = (ga, fixes, src, tgt, vm)
        if chosen is None:
            logger.warning(f"Rééquilibrage bloqué : plus aucun mouvement "
                           f"valide (source ➔ cible) n'est possible "
                           f"(écart de pression résiduel "
                           f"{gap_before:.0%}). Écart souvent inévitable "
                           f"quand les VMs sont grosses devant la RAM des "
                           f"nœuds, ou bloquées par une règle d'affinité "
                           f"HA.")
            break
        best_gap_after, _fix, busiest, emptiest, chosen_vm = chosen
        if best_gap_after >= gap_before:
            logger.info(f"[rebalance] Arrêt : aucun mouvement n'améliore "
                        f"l'écart de pression global ({gap_before:.0%}, "
                        f"au mieux {best_gap_after:.0%} après migration de "
                        f"{chosen_vm.name}) — migrer ne ferait que déplacer "
                        f"de la charge sans mieux équilibrer le cluster.")
            break
        if gap_before - best_gap_after < 0.01:
            logger.info(f"[rebalance] Arrêt : le meilleur mouvement ne gagne "
                        f"que {gap_before - best_gap_after:.0%} d'écart "
                        f"({gap_before:.0%} ➔ {best_gap_after:.0%}) — trop "
                        f"peu pour justifier une migration live.")
            break
        # --- mutation RÉELLE de l'état simulé : la VM change de nœud ---
        p_busy = busiest.mem / max(busiest.maxmem, 1)
        p_empty = emptiest.mem / max(emptiest.maxmem, 1)
        busiest.vms.remove(chosen_vm)
        emptiest.vms.append(chosen_vm)
        chosen_vm.node = emptiest.name
        busiest.mem -= vm_load(chosen_vm)
        emptiest.mem += vm_load(chosen_vm)
        moved.add(chosen_vm.vmid)
        # emptiest.vms re-appendé : declared_load = pression déclarée
        # APRÈS le déplacement (cf. 2c).
        plans.append({"vm": chosen_vm, "from": busiest.name, "to": emptiest.name,
                      "target_mem_after": declared_load(emptiest),
                      "target_maxmem": emptiest.maxmem,
                      "impact_pct": (busiest.name, p_busy,
                                     busiest.mem / max(busiest.maxmem, 1),
                                     emptiest.name, p_empty,
                                     emptiest.mem / max(emptiest.maxmem, 1))})
        _log_step(busiest, p_busy, busiest.mem / max(busiest.maxmem, 1),
                  emptiest, p_empty, emptiest.mem / max(emptiest.maxmem, 1),
                  chosen_vm)
        logger.debug(f"[rebalance] {chosen_vm.name} : {busiest.name} ➔ "
                      f"{emptiest.name} (pression {p_busy:.0%} ➔ "
                      f"{p_empty:.0%})")
    return plans


# ---------------------------------------------------------------------------
# CLIENT PROXMOX (réel) — Option C : proxmoxer API + backend ssh
# ---------------------------------------------------------------------------
def _fmt(out) -> str:
    return out.decode() if isinstance(out, bytes) else str(out)


class ProxmoxClient:
    """API REST (token) pour le pilotage cluster + SSH (clé) pour
    ha-manager / apt / uname. Chaque méthode lève RuntimeError si échec."""

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._ssh_pkey = None            # clé privée chargée à la demande (passphrase)
        # Connexions SSH PERSISTANTES par nœud (un seul handshake par
        # nœud et par run, réutilisé pour toutes les commandes ; recréée
        # si morte — y compris après le reboot du nœud).
        self._ssh_cli: Dict[str, object] = {}
        # proxmoxer >= 3.x expose 'ProxmoxAPI' ; les versions antérieures
        # utilisaient l'alias 'Proxmox'. On gère les deux pour compatibilité.
        try:
            from proxmoxer import ProxmoxAPI as _PxmApiClass
        except ImportError:
            from proxmoxer import Proxmox as _PxmApiClass
        self._Proxmox = _PxmApiClass
        # Départ : le nœud graine (ou la liste figée si PVE_API_HOSTS est fourni)
        self.api_hosts = list(API_HOSTS) if API_HOSTS else [API_HOST]
        self.api_host_idx = 0
        self.node_addr: Dict[str, str] = {}   # nom Proxmox -> IP de gestion
        self._reboot_baseline: Dict[str, Optional[int]] = {}  # uptime avant reboot
        # Cluster sans Ceph (détection mémoïsée) : gates Ceph ignorées
        self._no_ceph = False          # True dès qu'on a prouvé l'absence
        self._no_ceph_logged = False   # log informatif émis UNE fois
        # Remédiation MON_CLOCK_SKEW autorisée ? En dry-run le script
        # n'exécute RIEN sur les nœuds : l'Updater positionne ce
        # drapeau à False, et la remédiation se borne alors à EXPLIQUER
        # ce que le run réel ferait (aucun restart chrony, aucun
        # makestep, aucun restart de mon).
        self.can_remediate = True
        # Bilan dry-run : détection des guests avec disque sur stockage
        # NON partagé, mémoïsée par (vmtype, vmid) -> True/False/None.
        self._vm_local_disks: Dict[Tuple[str, int], Optional[bool]] = {}
        self._vm_onboot: Dict[Tuple[str, int], Optional[bool]] = {}
        # Storages PARTAGÉS par nœud, mémoïsés (partagé = tout sauf local).
        # NB v21 : cette initialisation manquait depuis l'introduction de
        # la mémoïsation — shared_storages() levait AttributeError au
        # PREMIER appel (vécu 19/11 : FATAL 'ProxmoxClient' object has no
        # attribute '_shared_storages_cache' en Phase 1 sur la VM 405 ;
        # en dry-run l'exception était avalée et tous les guests passaient
        # en « disques locaux : indéterminé », dégradation silencieuse).
        self._shared_storages_cache: Dict[str, Optional[Set[str]]] = {}
        self._connect_api()
        # Découverte dynamique de tous les nœuds du cluster
        if not API_HOSTS:
            self._discover_hosts()

    # ---------- Découverte du cluster ----------
    def _resolve_seed_ip(self, host: str) -> Optional[str]:
        """Résout l'IP du nœud graine (IP directe, ou DNS depuis le worker)."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def _resolve_node_ip(self, name: str, seed_ip: Optional[str]) -> Optional[str]:
        """Résout l'IP de gestion d'un nœud :
        1) via l'API (GET /nodes/{name}/network) : on préfère l'IP sur le même
           sous-réseau /24 que le nœud graine,
        2) via DNS depuis le worker,
        3) via SSH sur le nœud graine (getent hosts <name>)."""
        # 1) API : interfaces réseau du nœud
        try:
            nets = self.api.nodes(name).network.get()
            same_subnet, first_ip = None, None
            for iface in nets:
                cidr = iface.get("cidr") or iface.get("address") or ""
                if "/" not in cidr:
                    continue
                ip = cidr.split("/")[0]
                if ip.startswith("127."):
                    continue
                if first_ip is None:
                    first_ip = ip
                if seed_ip and ip.rsplit(".", 1)[0] == seed_ip.rsplit(".", 1)[0]:
                    same_subnet = ip
                    break
            if same_subnet:
                self.log.debug(f"{name} résolu via API réseau : {same_subnet}")
                return same_subnet
            if first_ip:
                self.log.debug(f"{name} résolu via API réseau : {first_ip}")
                return first_ip
        except Exception as e:
            self.log.debug(f"API network illisible pour {name} : {e}")
        # 2) DNS depuis le worker
        try:
            ip = socket.gethostbyname(name)
            self.log.debug(f"{name} résolu via DNS worker : {ip}")
            return ip
        except socket.gaierror:
            pass
        # 3) SSH sur le nœud graine : le nœud Proxmox sait résoudre ses pairs
        try:
            out = self._ssh(self.api_hosts[self.api_host_idx], f"getent hosts {name}")
            ip = out.split()[0]
            self.log.debug(f"{name} résolu via SSH graine : {ip}")
            return ip
        except Exception as e:
            self.log.debug(f"Résolution SSH de {name} impossible : {e}")
        return None

    def _find_node_owning_ip(self, nodes: List[str], ip: str) -> Optional[str]:
        """Identifie le nœud qui possède l'IP donnée (cas d'une VIP de graine) :
        1) l'IP apparaît dans la config réseau d'un nœud (GET /nodes/{n}/network),
        2) reverse DNS (PTR) de l'IP : le nom retourné contient le nom Proxmox."""
        for name in nodes:
            try:
                nets = self.api.nodes(name).network.get()
                for iface in nets:
                    cidr = iface.get("cidr") or ""
                    if "/" in cidr and cidr.split("/")[0] == ip:
                        return name
            except Exception:
                continue
        try:
            ptr = socket.gethostbyaddr(ip)[0]
            for name in nodes:
                if name in ptr or ptr.split(".")[0] == name:
                    return name
        except (socket.herror, socket.gaierror):
            pass
        return None

    def _discover_hosts(self):
        """Interroge le cluster (GET /nodes) et construit la liste d'hôts API
        SANS DOUBLON : chaque nœud est identifié par son IP de gestion, et le
        nœud graine (souvent fourni en IP, sans nom) n'est pas ajouté une
        deuxième fois sous son nom Proxmox."""
        try:
            nodes = [n["node"] for n in self.api.nodes.get()]
        except Exception as e:
            self.log.warning(f"Découverte des nœuds impossible ({e}) — "
                             f"l'hôte graine {API_HOST} sera utilisé seul. "
                             f"Le failover API ne pourra pas fonctionner !")
            return
        if not nodes:
            self.log.warning("Aucun nœud renvoyé par l'API — hôte graine conservé seul.")
            return
        current = self.api_hosts[self.api_host_idx]          # ex. IP, FQDN ou VIP
        current_ip = self._resolve_seed_ip(current) or current
        # La graine n'est qu'un POINT D'ENTRÉE : la liste des hôtes API est
        # construite UNIQUEMENT à partir des nœuds découverts (résolus en IP
        # de gestion). La graine n'y figure jamais — le nœud qu'elle désigne
        # y est déjà par sa propre IP, et si c'est une VIP elle n'y a pas
        # sa place (basculer vers une VIP ne change pas de serveur).
        addrs: Dict[str, str] = {}
        hosts: List[str] = []
        seed_name = None                                     # nom Proxmox du graine
        for name in sorted(nodes):
            ip = self._resolve_node_ip(name, current_ip) or name
            addrs[name] = ip
            if ip not in hosts:                              # dédoublonnage par IP
                hosts.append(ip)
            if ip == current_ip and seed_name is None:
                seed_name = name
        self.api_hosts = hosts
        self.node_addr = addrs
        if seed_name is None:
            # La graine n'est pas l'IP de gestion d'un nœud : probable VIP.
            # Log informatif uniquement — la VIP n'est pas conservée.
            owner = self._find_node_owning_ip(nodes, current_ip)
            if owner:
                self.log.info(f"Graine '{current}' : VIP du nœud '{owner}' — "
                               f"point d'entrée uniquement, non incluse dans les hôtes API.")
            else:
                self.log.info(f"Graine '{current}' ({current_ip}) : point d'entrée "
                               f"seulement (pas une IP de nœud) — non incluse "
                               f"dans les hôtes API.")
        else:
            self.log.info(f"Nœud graine identifié : '{seed_name}' ({current})")
        self.log.info(f"Hôtes API ({len(hosts)}) : {', '.join(hosts)}")

    # ---------- Failover API ----------
    def _connect_api(self):
        host = self.api_hosts[self.api_host_idx]
        self.log.info(f"Connexion API à {host}")
        self.api = self._Proxmox(host, user=API_USER, token_name=API_TOKEN_NAME,
                                 token_value=API_TOKEN_VALUE, verify_ssl=VERIFY_SSL)

    def _rotate_api_host(self, avoid: Optional[str] = None):
        """Bascule vers le nœud API suivant (utile si l'hôte courant reboote).
        `avoid` : hôte (nom ou IP) à SAUTER — typiquement le nœud en cours
        de reboot, qui reste dans la liste mais est injoignable."""
        if len(self.api_hosts) < 2:
            return False
        for _ in range(len(self.api_hosts)):
            self.api_host_idx = (self.api_host_idx + 1) % len(self.api_hosts)
            if self.api_hosts[self.api_host_idx] != avoid:
                break
        self.log.warning(f"Bascule de l'hôte API vers {self.api_hosts[self.api_host_idx]}")
        self._connect_api()
        return True

    def _ensure_api_host_not(self, node: str):
        """Si l'hôte API courant est le nœud sur le point d'être arrêté,
        on bascule AVANT sur un autre nœud. La comparaison tolère à la fois
        le nom Proxmox et l'IP (les hôtes API sont stockés en IP)."""
        current = self.api_hosts[self.api_host_idx]
        node_ip = self.node_addr.get(node, node)
        if current in (node, node_ip) and len(self.api_hosts) > 1:
            self.log.warning(f"L'hôte API ({current}) est le nœud à rebooter — bascule préventive.")
            self._rotate_api_host()

    def with_api(self, fn, retries: int = 1, quiet: bool = False):
        """Exécute fn(prox) en gérant le failover entre hôtes API.
        fn reçoit l'objet proxmoxer et doit effectuer UN appel API.
        NB : seules les erreurs de CONNEXION/host justifient une bascule :
        - erreur cliente (400) : déterministe partout → échec immédiat ;
        - « guest agent is not running » : l'agent de la VM est absent
          dans l'OS — déterministe (appel proxifié vers l'hébergeur) ;
        - erreur PROXY (« 595 … proxy handshake … Connection refused ») :
          l'HÔTE API a répondu, mais il ne joint pas le port 8006 du
          NŒUD CIBLE (ex. nœud en cours de reboot). Basculer ne sert à
          rien : tous les hôtes échoueraient à l'identique → échec
          immédiat, à traiter par l'appelant (poll d'attente).
        - mode quiet : aucun log de bascule (polls d'attente pendant un
          reboot, où l'échec est le résultat ATTENDU).
        NB 2 : une erreur « connection aborted » répétée sur TOUS les
        hôtes n'est pas une panne réseau : c'est la REQUÊTE qui fait
        planter le worker pveproxy (ex. bug Perl de relocate) — on
        borne donc strictement le nombre de tentatives."""
        last_exc = None
        attempts = 0
        max_attempts = max(1, retries) * len(self.api_hosts) + 1
        for _ in range(max_attempts):
            attempts += 1
            try:
                return fn(self.api)
            except Exception as e:
                last_exc = e
                msg = str(e)
                if "400" in msg or "Parameter verification" in msg:
                    # requête invalide : le bug est dans l'appel, pas l'hôte
                    self.log.error(f"Requête API refusée ({msg}) — "
                                   f"pas une panne d'hôte, aucune bascule.")
                    raise
                if "binary not installed" in msg \
                        or "pveceph configuration not initialized" in msg:
                    # Ceph NON INSTALLÉ sur ce cluster (ex. PES) : l'erreur
                    # 500 est DÉTERMINISTE et identique sur tous les hôtes.
                    # Basculer ne sert à rien et déclenche un carrousel
                    # inutile + un faux message ERREUR à chaque nœud.
                    self.log.debug(f"Endpoint Ceph indisponible ({msg}) — "
                                   f"cluster probablement sans Ceph, "
                                   f"aucune bascule d'hôte.")
                    raise
                if "guest agent is not running" in msg:
                    # guest agent configuré mais ABSENT/inactif DANS l'OS
                    # de la VM (ex. service qemu-guest-agent arrêté) :
                    # erreur 500 DÉTERMINISTE — l'appel agent.ping est
                    # proxifié vers le nœud qui héberge la VM, tous les
                    # hôtes API échoueraient à l'identique. Sans ce cas,
                    # CHAQUE VM sans agent déclenche un carrousel complet
                    # des hôtes API (~80 s sur un cluster de 10 nœuds) —
                    # sur un gros cluster, le diagnostic pré-migration
                    # devient interminable. L'appelant (vm_alive) gère
                    # déjà cet échec avec un simple WARNING.
                    self.log.debug(f"Guest agent injoignable ({msg}) — "
                                   f"erreur déterministe, aucune "
                                   f"bascule d'hôte.")
                    raise
                if "does not exist" in msg or "No such object" in msg:
                    # objet ABSENT (ex. fichier de conf d'une VM qui n'est
                    # pas sur ce nœud) : erreur DÉTERMINISTE, identique sur
                    # tous les hôtes — la bascule est inutile (et noisie).
                    self.log.debug(f"Objet introuvable ({msg}) — erreur "
                                   f"déterministe, aucune bascule d'hôte.")
                    raise
                if "is not available on node" in msg:
                    # storage (ou autre objet) ABSENT de la CIBLE de la
                    # requête (vécu 19/11 : 500 « storage 'shm1…21local'
                    # is not available on node 'p-shm1-proxspv-18' » :
                    # disques LOCAUX d'une VM stopped, le planner avait
                    # proposé une cible qui ne porte pas le storage du
                    # disque). Erreur DÉTERMINISTE : la requête est
                    # validée cluster-wide (pmxcfs), tous les hôtes
                    # échoueraient À L'IDENTIQUE — sans ce cas, chaque
                    # tentative déclenchait un carrousel complet des
                    # hôtes API (vécu : 2 carrousels de 13 hôtes ≈ 54 s
                    # de bruit, plus le faux message pveproxy).
                    self.log.error(
                        f"Storage/objet indisponible sur la CIBLE ({msg}) "
                        f"— requête refusée cluster-wide : erreur "
                        f"déterministe, aucune bascule d'hôte.")
                    raise
                if "proxy handshake" in msg or " 595" in msg \
                        or "595 Errors during connection" in msg:
                    # appel PROXIFIÉ vers le nœud cible : c'est la CIBLE
                    # qui est injoignable (reboot attendu), pas l'hôte API.
                    if not quiet:
                        self.log.error(
                            f"Appel proxifié échoué ({msg}) — le nœud CIBLE "
                            f"de la requête est injoignable, ce n'est pas "
                            f"l'hôte API qui est en panne.")
                    raise
                # UN retry sur le MÊME hôte avant de basculer : un worker
                # pveproxy qui se coupe/reprend (restart de service juste
                # après une réactivation HA) donne des « Connection
                # aborted » transitoires IDENTIQUES sur tous les hôtes —
                # la bascule ne fait que du bruit de carrousel.
                time.sleep(2)
                try:
                    return fn(self.api)
                except Exception as e2:
                    last_exc = e2
                    if "400" in str(e2) or "Parameter verification" in str(e2):
                        self.log.error(f"Requête API refusée ({e2}) — "
                                       f"pas une panne d'hôte, aucune "
                                       f"bascule.")
                        raise
                if not quiet:
                    self.log.warning(f"Appel API échoué ({e}) — "
                                     f"tentative de bascule d'hôte…")
                if not self._rotate_api_host():
                    time.sleep(5)
        if attempts >= max_attempts and not quiet:
            self.log.error("La connexion a échoué sur tous les hôtes API : "
                           "la requête elle-même fait probablement planter "
                           "pveproxy (pas une panne de cluster).")
        raise RuntimeError(f"Impossible d'exécuter l'appel API après bascules : {last_exc}")

    # ---------- SSH helper (paramiko direct : fiable pour commandes brutes) ----------
    def _get_ssh_pkey(self) -> "paramiko.PKey":
        """Charge la clé privée UNE seule fois.
        Ordre de tentatives : 1) sans passphrase (clé non protégée) ou avec
        PVE_SSH_PASSPHRASE si défini, 2) si la clé est protégée et sans
        passphrase connue : saisie interactive (une seule fois).
        NB : paramiko >= 4 a supprimé DSSKey (DSA obsolète) — on ne référence
        que les types modernes, présents dans toutes les versions."""
        if self._ssh_pkey is not None:
            return self._ssh_pkey
        import getpass
        import paramiko
        key_classes = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]

        def _try_load(passphrase):
            for kc in key_classes:
                try:
                    pkey = kc.from_private_key_file(SSH_PRIVATE_KEY,
                                                    password=passphrase)
                    self.log.debug(f"Clé SSH chargée ({kc.__name__})")
                    return pkey
                except paramiko.PasswordRequiredException:
                    raise            # clé protégée : passphrase obligatoire
                except (paramiko.SSHException, OSError):
                    continue         # ce n'est pas ce type de clé : suivant
            return None

        passphrase = SSH_KEY_PASSPHRASE or None
        pkey = None
        try:
            pkey = _try_load(passphrase)
        except paramiko.PasswordRequiredException:
            if passphrase is not None:
                # une passphrase était configurée mais ne déverrouille pas
                # la clé : la valeur du fichier env ne correspond pas
                raise RuntimeError(
                    "La passphrase PVE_SSH_PASSPHRASE ne permet pas de "
                    f"déverrouiller la clé {SSH_PRIVATE_KEY} — vérifiez sa valeur.")
            if not sys.stdin.isatty():
                raise RuntimeError(
                    "La clé SSH est protégée par une passphrase mais le script "
                    "tourne sans terminal. Utilisez une clé dédiée SANS passphrase "
                    "(restreinte dans authorized_keys), ou définissez "
                    "PVE_SSH_PASSPHRASE via le fichier d'environnement.")
            passphrase = getpass.getpass(
                f"Passphrase de la clé SSH {SSH_PRIVATE_KEY} : ")
            self.log.warning(f"Clé protégée détectée et PVE_SSH_PASSPHRASE "
                             f"absent/vides — saisie interactive. Pour un run "
                             f"non supervisé, définissez PVE_SSH_PASSPHRASE "
                             f"dans le fichier d'environnement.")
            pkey = _try_load(passphrase)
        if pkey is None:
            raise RuntimeError(f"Impossible de charger la clé SSH {SSH_PRIVATE_KEY} "
                               "(type non supporté ou passphrase incorrecte).")
        self._ssh_pkey = pkey
        return self._ssh_pkey

    def hosts_read(self, node: str) -> str:
        """Contenu brut de /etc/hosts du nœud (lecture pure)."""
        return self._ssh(node, "cat /etc/hosts")

    def hosts_fqdn(self, node: str) -> Optional[str]:
        """FQDN du nœud (« hostname -f »), None si injoignable/sans
        domaine — best-effort, jamais bloquant."""
        try:
            out = self._ssh(node, "hostname -f 2>/dev/null").strip()
        except Exception:
            return None
        if not out:
            return None
        fq = out.split()[0]
        return fq if "." in fq else None

    def hosts_write(self, node: str, new_content: str) -> str:
        """Écrit /etc/hosts du nœud : sauvegarde datée PUIS écriture
        atomique de contenu encodé en base64 (zéro interprétation par
        le shell distante — aucun échappement à casser). Retourne le
        chemin de la sauvegarde. Lève RuntimeError au moindre échec.
        NB : la relecture de vérification passe par le PTY SSH (get_pty)
        qui renvoie CHAQUE fin de ligne en « \\r\\n » — la comparaison
        est donc NORMALISÉE (hosts_write_files_identical, v16) : un
        '\\r' de transport n'est PAS une divergence, un vrai contenu
        différent l'est toujours (ligne à ligne)."""
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        bak = f"/etc/hosts.proxmox-rolling-update.bak-{ts}"
        b64 = base64.b64encode(new_content.encode("utf-8")).decode("ascii")
        cmd = (f"cp -a /etc/hosts {bak} && "
               f"echo '{b64}' | base64 -d > /etc/hosts && "
               f"chmod --reference={bak} /etc/hosts")
        self._ssh(node, cmd)
        # relecture immédiate : ce qui est SUR LE DISQUE doit être ce
        # que l'on a voulu écrire, sinon la correction est réputée ÉCHUE.
        back = self.hosts_read(node)
        if not hosts_write_files_identical(back, new_content):
            raise RuntimeError(
                f"{node}: /etc/hosts réécrit mais la relecture diffère "
                f"({hosts_write_files_diff_hint(back, new_content)} ; "
                f"réseau ? système de fichiers plein ?) — VÉRIFIEZ le "
                f"fichier AVANT toute action : s'il est correct, "
                f"poursuivez (la sauvegarde {bak} reste disponible), "
                f"s'il est cassé restaurez-la.")
        return bak

    def _ssh(self, node: str, cmd: str, stream: bool = False,
             retries: Optional[int] = None) -> str:
        """Enveloppe de résilience : si la connexion SSH est perdue
        (micro-coupure réseau pendant un apt, nœud momentanément
        injoignable…), on attend, on RECONNECTE et on RE-JOUE la commande.
        Toutes les commandes passées ici sont idempotentes ou résilientes :
        - apt-get update / full-upgrade : re-exécuter est le chemin de
          reprise officiel (dpkg reconfigure les paquets interrompus) ;
          de plus, si l'ancien apt tourne ENCORE sur le nœud (coupure
          réseau alors que le process distant a survécu), l'option
          DPkg::Lock::Timeout fait attendre le nouveau apt jusqu'à la
          fin du premier — jamais de conflit de lock dpkg ;
        - ha-manager maintenance on/off : idempotent ;
        - uname / test / getent : lectures pures.
        retries=None → PVE_SSH_RETRIES (défaut 3) => jusqu'à 4 tentatives
        (attentes 15 s puis 30 s puis 45 s : traverse un ban fail2ban
        temporaire ; la connexion persistante limite de toute façon
        drastiquement le nombre de handshakes)."""
        if retries is None:
            retries = SSH_RETRIES
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            if attempt:
                wait = min(60, 15 * attempt)
                self.log.warning(
                    f"Perte de connexion SSH avec {node} — nouvelle tentative "
                    f"{attempt + 1}/{retries + 1} dans {wait}s…")
                time.sleep(wait)
            try:
                return self._ssh_once(node, cmd, stream)
            except SshTransportLost as e:
                last_exc = e
        raise RuntimeError(
            f"{node} est resté injoignable en SSH après {retries + 1} "
            f"tentatives ({last_exc}) — si le nœud rejette les connexions "
            f"en rafale, vérifiez fail2ban/sshguard ou la limite "
            f"MaxStartups de sshd.")

    def _ssh_drop(self, node: str) -> None:
        """Ferme et oublie la connexion persistante du nœud (si présente)."""
        cli = self._ssh_cli.pop(node, None)
        if cli is not None:
            try:
                cli.close()
            except Exception:
                pass

    def _ssh_once(self, node: str, cmd: str, stream: bool = False) -> str:
        import paramiko
        pkey = self._get_ssh_pkey()
        # Utiliser l'IP résolue lors de la découverte (le nom DNS peut ne pas
        # être résolvable depuis le worker, mais l'IP de gestion est connue).
        addr = self.node_addr.get(node, node)
        # Connexion PERSISTANTE : réutilisée si vivante, sinon recréée
        # (nœud rebooté, micro-coupure prolongée…).
        cli = self._ssh_cli.get(node)
        if cli is not None:
            try:
                tr = cli.get_transport()
                if tr is None or not tr.is_active():
                    cli = None
            except Exception:
                cli = None
            if cli is None:
                self._ssh_drop(node)
        if cli is None:
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                cli.connect(addr, port=SSH_PORT, username=SSH_USER,
                            pkey=pkey, look_for_keys=False, allow_agent=True,
                            timeout=30, banner_timeout=30, auth_timeout=30)
            except Exception as e:
                # échec d'ÉTABLISSEMENT de connexion : injoignable →
                # retentable par l'enveloppe _ssh (coupure transitoire)
                self._ssh_drop(node)
                raise SshTransportLost(f"connexion SSH à {addr} impossible ({e})")
            # Keepalive TCP : sans lui, une micro-coupure réseau prolongée
            # n'est détectée par personne et readline() bloque pour toujours.
            cli.get_transport().set_keepalive(15)
            self._ssh_cli[node] = cli
        try:
            stdin, stdout, stderr = cli.exec_command(cmd, get_pty=True)
            stdin.close()
            buf = ""
            if stream:
                # affiche la sortie au fur et à mesure (apt, etc.)
                # Version ROBUSTE : polling du canal au lieu d'un readline()
                # bloquant. readline() ne rend JAMAIS la main si le transport
                # SSH meurt au milieu d'un apt (micro-coupure réseau, reboot
                # du nœud…) — le run se fige sans erreur ni message. Ici, on
                # détecte : (1) la fin du canal (exit status), (2) la mort
                # du transport (keepalive sans réponse) → exception claire.
                chan = stdout.channel
                transport = cli.get_transport()
                pending = ""
                while True:
                    while chan.recv_ready():
                        pending += chan.recv(4096).decode("utf-8", "replace")
                        while "\n" in pending:
                            line, pending = pending.split("\n", 1)
                            if line.strip():
                                self.log.info(f"    │ {line.rstrip()}")
                            buf += line + "\n"
                    if chan.exit_status_ready() and not chan.recv_ready():
                        # drain final puis sortie
                        while chan.recv_ready():
                            pending += chan.recv(4096).decode("utf-8", "replace")
                        break
                    if not transport.is_active():
                        tail = "\n".join(buf.strip().splitlines()[-5:])
                        raise SshTransportLost(
                            f"connexion perdue pendant '{cmd}' sur {node} "
                            f"(micro-coupure réseau ou nœud injoignable). "
                            f"Dernières lignes reçues : {tail}")
                    time.sleep(0.2)
                if pending.strip():
                    self.log.info(f"    │ {pending.rstrip()}")
                    buf += pending
                rc = chan.recv_exit_status()
            else:
                buf = stdout.read().decode()
                err = stderr.read().decode().strip()
                rc = stdout.channel.recv_exit_status()
                # get_pty=True fusionne stderr dans stdout : le vrai message
                # d'erreur (ha-manager, etc.) est donc dans buf, pas dans err.
                detail = err or "\n".join(buf.strip().splitlines()[-5:])
                if err and rc != 0:
                    self.log.debug(f"ssh stderr ({node}): {err}")
            if rc != 0:
                raise RuntimeError(f"SSH '{cmd}' sur {node} a retourné {rc}"
                                   + (f" : {detail.strip()}" if detail.strip() else ""))
            return buf
        except SshTransportLost:
            # connexion morte : invalider le cache avant de retenter
            self._ssh_drop(node)
            raise

    # ---------- API helpers ----------
    def _diagnose_nodes(self, nostats: List[str],
                        offline: List[Tuple[str, str]]) -> List[str]:
        """Sondes COMPLÉMENTAIRES (lectures pures : GET + systemctl, donc
        sans effet même en dry-run) quand l'inventaire est incomplet —
        distinguer les causes au lieu de deviner :
        - token sans privilèges : depuis PVE 8, un token API créé avec
          --privsep 1 (le DÉFAUT) n'hérite PAS des privilèges de son
          utilisateur, même root — il faut lui donner ses PROPRES ACL ;
        - pvestatd arrêté sur le nœud (stats jamais écrites) ;
        - nœud marqué offline à tort (corosync) alors qu'il répond ;
        - SSH injoignable (résolution du nom, clé, passphrase).
        On interroge l'API EN DIRECT (self.api, sans with_api) : les
        sondes ne déclenchent ni retry ni bascule d'hôte — chaque échec
        est un RÉSULTAT, pas une erreur."""
        findings: List[str] = []
        try:
            self.api.version.get()
            findings.append("authentification du token : OK — le problème "
                            "est de PRIVILÈGES ou de services, pas "
                            "d'identité")
        except Exception as e:
            findings.append(f"sonde GET /version : {str(e)[:120]}")
        for node in sorted(set(nostats) | {n for n, _ in offline}):
            # 1) GET /nodes/<n>/status exige Sys.Audit sur ce nœud :
            #    discriminateur entre « token sans droits » et « autre »
            try:
                st = self.api.nodes(node).status.get()
                mem = st.get("memory", {}) if isinstance(st, dict) else {}
                findings.append(
                    f"{node} : GET /nodes/{node}/status RÉPOND (RAM "
                    f"totale {gb(mem.get('total', 0))}) — le token A le "
                    f"privilège Sys.Audit : l'omission des stats dans "
                    f"/cluster/resources n'est PAS un problème de droits")
            except Exception as e:
                estr = str(e)
                elow = estr.lower()
                if "403" in estr or "forbidden" in elow \
                        or "permission denied" in elow:
                    findings.append(
                        f"{node} : GET /nodes/{node}/status → 403 : "
                        f"CONFIRMÉ, le token n'a pas le privilège "
                        f"Sys.Audit sur ce nœud — un token créé avec "
                        f"--privsep 1 (le DÉFAUT) n'hérite PAS des "
                        f"privilèges de son utilisateur, même root : lui "
                        f"donner ses propres ACL (pveum acl modify / "
                        f"-user '<user>!<token>' -role Administrator ; "
                        f"état vérifiable via pveum user token list)")
                else:
                    findings.append(
                        f"{node} : GET /nodes/{node}/status injoignable "
                        f"({estr[:100]}) — nœud probablement arrêté ou "
                        f"corosync désynchronisé (pvecm status)")
            # 2) SSH : état des services qui produisent les stats
            try:
                out = self._ssh(
                    node, 'hostname; for s in pvestatd pvedaemon pmxcfs '
                          'corosync; '
                          'do echo "$s=$(systemctl is-active $s)"; done',
                    retries=0)
                svcs = " ; ".join(l for l in out.strip().splitlines()
                                  if "=" in l)
                findings.append(f"{node} : SSH OK — {svcs}")
            except Exception as e:
                findings.append(f"{node} : SSH injoignable "
                                f"({str(e)[:100]}) — vérifier résolution "
                                f"du nom, clé, passphrase, PVE_SSH_USER")
        return findings

    def fetch_state(self) -> ClusterState:
        state = ClusterState()
        resources = self.with_api(lambda p: p.cluster.resources.get())
        # NB : l'API ne garantit AUCUN ordre ; en pratique les guests arrivent
        # souvent AVANT les nœuds. Deux passes obligatoires : créer tous les
        # nœuds d'abord, puis rattacher les VMs/CT.
        offline: List[str] = []
        nostats: List[str] = []
        for res in resources:
            if res["type"] == "node":
                if not all(k in res for k in ("maxmem", "mem", "maxcpu", "cpu")):
                    # entrée SANS statistiques — deux causes possibles :
                    # - nœud réellement hors-ligne/inconnu (offline) :
                    #   /cluster/resources ne renvoie que
                    #   id/node/type/status ;
                    # - nœud ONLINE mais token API sans le privilège
                    #   Sys.Audit sur /nodes/<nœud> : l'appel RÉUSSIT et
                    #   cpu/mem/maxmem/uptime sont simplement OMIS.
                    # Un rolling update exige un inventaire complet :
                    # échec EXPLICITE (pas un KeyError 'maxmem' cryptique)
                    # qui DISTINGUE les deux causes et liste tout d'un coup.
                    if res.get("status") == "online":
                        nostats.append(res["node"])
                    else:
                        offline.append((res["node"],
                                        res.get("status", "?")))
                    continue
                ni = NodeInfo(
                    name=res["node"], maxmem=res["maxmem"], mem=res["mem"],
                    maxcpu=res["maxcpu"], cpu=res["cpu"], status=res["status"])
                # moyennes RRD 1h : charge réelle du nœud (CPU + RAM)
                try:
                    avg = self.node_rrd_avg(res["node"])
                    if avg["cpu"]:
                        ni.cpu_avg = avg["cpu"]
                    if avg["mem"]:
                        ni.mem_avg = avg["mem"]
                except Exception:
                    pass    # RRD indisponible : on garde l'instantané
                state.nodes[res["node"]] = ni
        diag: List[str] = []
        if offline or nostats:
            # tests complémentaires AVANT l'arrêt : chaque sonde est une
            # lecture pure (GET + systemctl) — le résultat complète le
            # message d'erreur pour ne pas repartir à l'aveugle.
            diag = self._diagnose_nodes(nostats, offline)
            for d in diag:
                self.log.warning(f"[DIAG] {d}")
        if offline:
            raise RuntimeError(
                "nœud(s) hors-ligne/inconnu(s) dans /cluster/resources : "
                + ", ".join(f"{n} ({s})" for n, s in sorted(offline))
                + " — inventaire incomplet, rolling update refusé : "
                  "tous les nœuds doivent être online (vérifier pvecm "
                  "status / ha-manager status ; si le nœud est retiré "
                  "définitivement : pvecm delnode avant de relancer)."
                + (" Diagnostic : " + " ; ".join(diag) if diag else ""))
        if nostats:
            raise RuntimeError(
                "nœud(s) online SANS statistiques dans /cluster/resources : "
                + ", ".join(sorted(nostats))
                + " — cpu/mem/maxmem omis par l'API : cause typique, le "
                  "token API n'a pas le privilège Sys.Audit sur "
                  "/nodes/<nœud> (l'appel réussit quand même) — un token "
                  "créé avec --privsep 1 (le DÉFAUT depuis PVE 8) n'hérite "
                  "PAS des privilèges de son utilisateur, même root : "
                  "donner ses propres ACL au token (pveum acl modify / "
                  "-user '<user>!<token>' -role Administrator) ou "
                  "répliquer l'ACL du token d'un cluster qui fonctionne "
                  "(le run exige aussi migrations/HA/reboot) ; cause plus "
                  "rare : pvestatd arrêté sur le(s) nœud(s)."
                + (" Diagnostic : " + " ; ".join(diag) if diag else ""))
        for res in resources:
            if res["type"] not in ("qemu", "lxc"):
                continue
            node = state.nodes.get(res["node"])
            if node is None:
                # nœud inconnu : ne devrait jamais arriver après la 1re passe,
                # on log au lieu de jeter silencieusement
                self.log.warning(f"Guest {res['type']}/{res['vmid']} sur nœud "
                                  f"inconnu '{res['node']}' — ignoré.")
                continue
            vm = VmInfo(vmid=res["vmid"], name=res.get("name", str(res["vmid"])),
                        node=res["node"],
                        maxmem=res.get("maxmem", 0), mem=res.get("mem", 0),
                        maxcpu=res.get("cpu", 0.0) / max(res.get("maxcpu", 1), 1),
                        cores=res.get("maxcpu", 0),
                        status=res["status"], vmtype=res["type"])
            node.vms.append(vm)
            # moyennes 1h (RRD) : CPU comparable à l'UI Proxmox + RAM
            # réellement consommée en moyenne (l'instantané et la RAM max
            # déclarée ne disent pas si la VM utilise vraiment sa RAM).
            if vm.status == "running":
                try:
                    avg = self.guest_rrd_avg(res["node"], vm.vmid, vm.vmtype)
                    if avg["cpu"]:
                        vm.cpu_avg = avg["cpu"]
                    if avg["mem"]:
                        vm.mem_avg = avg["mem"]
                except Exception:
                    pass    # RRD indisponible : on garde l'instantané
        # vmid gérés par le HA (VMs 'vm:' + CONTENEURS 'ct:') : ils seront
        # détachés ('ignored') puis migrés par le script, le CRM ne les
        # gère plus pendant ce temps.
        try:
            sids = self.ha_sids()
            state.ha_vmids = set(sids.keys())
            if sids:
                self.log.info("Ressources HA sur ce cluster : "
                              + ", ".join(sorted(sids.values())))
        except Exception as e:
            self.log.warning(f"Ressources HA illisibles ({e}).")
        # Règles d'affinité 'node-affinity' : strict=1 = CONTRAINTE
        # (aucun repli) ; strict=0 = PRÉFÉRENCE (repli hors règle si
        # saturation — sémantique du CRM lui-même). Règle absente =
        # pas de contrainte.
        try:
            for r in self.ha_rules():
                if (r.get("type") != "node-affinity" or r.get("disable")):
                    continue
                allowed = {n.strip() for n in str(r.get("nodes", "")
                                                  ).split(",") if n.strip()}
                if not allowed:
                    continue
                # affinity=negative : les ressources doivent ÉVITER ces
                # nœuds → cibles autorisées = tous les nœuds SAUF ceux-là
                # (sémantique du CRM). Les nœuds sont déjà connus à ce
                # stade (fetch_state les charge en premier).
                if str(r.get("affinity", "positive")).lower() == "negative":
                    allowed = set(state.nodes.keys()) - allowed
                    if not allowed:
                        continue
                try:
                    strict_rule = bool(int(r.get("strict", 0) or 0))
                except (TypeError, ValueError):
                    strict_rule = False
                for res in str(r.get("resources", "")).split(","):
                    res = res.strip()
                    if not res or ":" not in res:
                        continue
                    try:
                        vmid = int(res.split(":", 1)[1])
                    except ValueError:
                        continue
                    state.ha_affinity.setdefault(vmid, set()).update(allowed)
                    if strict_rule:
                        if vmid in state.ha_affinity_hard:
                            state.ha_affinity_hard[vmid] &= allowed
                        else:
                            state.ha_affinity_hard[vmid] = set(allowed)
            # Règles 'resource-affinity' : affinités ENTRE RESSOURCES —
            # positive = à garder ENSEMBLE (préférence : le CRM regroupe
            # au mieux) ; negative = « keep separate » : à garder sur des
            # nœuds DIFFÉRENTS (strict=1 = contrainte DURE, sinon
            # préférence avec repli WARNING — même sémantique que
            # node-affinity). Pas de champ « nodes » sur ces règles.
            for r in self.ha_rules():
                if (r.get("type") != "resource-affinity"
                        or r.get("disable")):
                    continue
                r_vms: List[int] = []
                for res in str(r.get("resources", "")).split(","):
                    res = res.strip()
                    if not res or ":" not in res:
                        continue
                    try:
                        r_vms.append(int(res.split(":", 1)[1]))
                    except ValueError:
                        continue
                if len(r_vms) < 2:
                    continue
                try:
                    r_strict = bool(int(r.get("strict", 0) or 0))
                except (TypeError, ValueError):
                    r_strict = False
                r_neg = (str(r.get("affinity", "positive")).lower()
                         == "negative")
                if r_neg:
                    # identité de la règle (id, strict, membres) pour le
                    # bilan de fin de dry-run (fenêtres de non-respect)
                    state.ha_rules_info.append({
                        "id": str(r.get("rule") or r.get("id") or "?"),
                        "strict": r_strict,
                        "members": sorted(set(r_vms))})
                for i, a in enumerate(r_vms):
                    others = set(r_vms[:i]) | set(r_vms[i + 1:])
                    if r_neg:
                        state.ha_separate.setdefault(
                            a, set()).update(others)
                        if r_strict:
                            state.ha_separate_hard.setdefault(
                                a, set()).update(others)
                    else:
                        state.ha_together.setdefault(
                            a, set()).update(others)
            if state.ha_separate:
                self.log.info(
                    "Anti-affinités HA (resource-affinity negative — "
                    "« keep separate », à garder SÉPARÉES) : "
                    + "; ".join(
                        f"{v} ≠ {','.join(sorted(str(o) for o in others))}"
                        + ("" if v in state.ha_separate_hard else " (soft)")
                        for v, others in sorted(state.ha_separate.items())))
            if state.ha_together:
                self.log.info(
                    "Affinités de groupe HA (resource-affinity positive — "
                    "à garder ENSEMBLE, préférence) : "
                    + "; ".join(
                        f"{v} = {','.join(sorted(str(o) for o in others))}"
                        for v, others in sorted(state.ha_together.items())))
            if state.ha_affinity:
                self.log.info(
                    "Affinités HA (strict=1 : contrainte ; strict=0 : "
                    "préférence avec repli hors règle si saturation) : "
                    + "; ".join(
                        f"{v}: {','.join(sorted(n))}"
                        + ("" if v in state.ha_affinity_hard else " (soft)")
                        for v, n in sorted(state.ha_affinity.items())))
        except Exception as e:
            self.log.warning(f"Règles d'affinité HA illisibles ({e}) — "
                             f"placement HA sans contrainte d'affinité.")
        try:
            self.qemu_compat_scan(state)
        except Exception as e:
            self.log.debug(f"Sonde QEMU/machine non exécutée : {e}")
        return state

    def qemu_compat_scan(self, state: ClusterState) -> None:
        """Sonde de compatibilité QEMU/machine (v13) : pour chaque nœud
        online, UNE session SSH lit (1) la version du binaire QEMU et
        (2) via `ps`, la machine TELLE QUE LE PROCESS L'EXÉCUTE —
        l'alias « pc »/« q35 » de la config y est déjà RÉSOLU en
        « pc-i440fx-X.Y+pveN » par le QEMU du nœud qui a démarré la
        VM (c'est la seule façon fiable de connaître la version de
        machine réellement exigée : `qm listmachines` n'existe pas).
        Remplit state.node_qemu (nœud ➔ « 10.1.2 ») et state.vm_machine
        (vmid ➔ « pc-i440fx-11.1+pve0 ») ; les invités arrêtés ne sont
        pas migrés et n'apparaissent pas dans `ps`, ils ne sont donc
        pas contraints. Toute erreur (SSH, binaire absent, sortie non
        parsée) laisse l'entrée ABSENTE : absence = PAS de contrainte
        (on reste permissif ; le garde-fou natif de PVE s'applique de
        toute façon au moment de la migration)."""
        for node in [n for n in state.nodes.values() if n.status == "online"]:
            try:
                # NB : sur PVE le binaire QEMU est lancé via le symlink
                # /usr/bin/kvm — le comm du process n'est DONC PAS
                # fiable pour `ps -C` ; on filtre sur les args COMPLETS
                # (`ps -eww -o args=`), en excluant le grep lui-même.
                out = self._ssh(
                    node.name,
                    "qemu-system-x86_64 --version 2>/dev/null | head -1; "
                    "echo '---'; "
                    "ps -eww -o args= 2>/dev/null "
                    "| grep -E 'qemu-system-x86_64|/usr/bin/kvm ' "
                    "| grep -v 'grep '")
            except Exception as e:
                self.log.debug(f"Sonde QEMU indisponible sur {node.name} "
                               f"({e}) — nœud traité sans contrainte.")
                continue
            head, _, ps_out = out.partition("---")
            m = re.search(r"version\s+(\d+(?:\.\d+)+)", head)
            if m:
                state.node_qemu[node.name] = m.group(1)
            for line in ps_out.splitlines():
                mid = re.search(r"-id\s+(\d+)", line)
                mmac = re.search(r"-machine[ =]([^\s,]+)", line)
                if mid and mmac:
                    state.vm_machine[int(mid.group(1))] = mmac.group(1)

    def node_names(self) -> List[str]:
        # NB : GET /nodes expose le nom du nœud sous la clé "node"
        return [n["node"] for n in self.with_api(lambda p: p.nodes.get())]

    def node_rrd_avg(self, node: str) -> Dict[str, float]:
        """Moyennes CPU (0..1) et RAM (octets) d'un NŒUD sur la dernière
        heure (GET /nodes/{n}/rrddata, timeframe=hour, cf=AVERAGE) — même
        logique que guest_rrd_avg : l'instantané de /cluster/resources
        ne dit rien de la charge réelle du nœud. Échec silencieux."""
        rows = self.with_api(
            lambda p: p.nodes(node).rrddata.get(timeframe="hour",
                                                cf="AVERAGE"),
            quiet=True) or []
        cpu = [r.get("cpu") for r in rows
               if isinstance(r, dict) and r.get("cpu") is not None]
        mem = [r.get("mem") for r in rows
               if isinstance(r, dict) and r.get("mem") is not None]
        return {"cpu": sum(cpu) / len(cpu) if cpu else 0.0,
                "mem": int(sum(mem) / len(mem)) if mem else 0}

    def guest_rrd_avg(self, node: str, vmid: int,
                      vmtype: str = "qemu") -> Dict[str, float]:
        """Moyennes CPU (0..1) et RAM (octets) d'un guest sur la dernière
        heure, via les RRD de PVE (GET /nodes/{n}/{qemu|lxc}/{id}/rrddata,
        timeframe=hour, cf=AVERAGE). C'est la donnée comparable à ce que
        montre l'UI Proxmox — le champ 'cpu' de /cluster/resources n'est
        qu'un échantillon INSTANTANÉ pris au moment de l'appel (d'où les
        écarts constatés). Échec silencieux : l'appelant garde l'instantané.
        """
        ep = (lambda p: p.nodes(node).qemu(vmid).rrddata.get(
                  timeframe="hour", cf="AVERAGE")) if vmtype == "qemu" \
            else (lambda p: p.nodes(node).lxc(vmid).rrddata.get(
                      timeframe="hour", cf="AVERAGE"))
        rows = self.with_api(ep, quiet=True) or []
        cpu = [r.get("cpu") for r in rows
               if isinstance(r, dict) and r.get("cpu") is not None]
        mem = [r.get("mem") for r in rows
               if isinstance(r, dict) and r.get("mem") is not None]
        return {"cpu": sum(cpu) / len(cpu) if cpu else 0.0,
                "mem": int(sum(mem) / len(mem)) if mem else 0}

    def node_versions(self) -> Dict[str, str]:
        """Version PVE par nœud (pveversion), pour vérifier l'homogénéité."""
        out: Dict[str, str] = {}
        for name in self.node_names():
            try:
                v = self.with_api(lambda p, n=name: p.nodes(n).version.get())
                out[name] = str(v.get("version", "?"))
            except Exception as e:
                out[name] = f"inaccessible ({e})"
        return out

    def _ha_maintenance(self, node: str, new_cmd: str, old_cmd: str):
        """Commande de maintenance HA, compatible PVE 8 et PVE 9 :
        - PVE 9  : ha-manager crm-command node-maintenance enable/disable <node>
        - PVE <=8 : ha-manager node-maintenance on/off <node>
        On tente la syntaxe PVE 9 puis on retombe sur l'ancienne.
        NB : le repli ne se déclenche QUE sur un refus de SYNTAXE (message
        d'usage / commande inconnue). Une erreur transitoire (SSH coupé,
        démon HA en cours d'arrêt pendant un reboot) doit être RETENTÉE
        dans la même syntaxe, pas remplacée par une commande obsolète."""
        cmd9 = (f"ha-manager crm-command node-maintenance "
                f"{new_cmd} {node}")
        try:
            self._ssh(node, cmd9)
        except RuntimeError as e:
            msg = str(e).lower()
            if ("usage" in msg or "unknown command" in msg
                    or "unrecognized" in msg or "unknown subcommand" in msg):
                self.log.debug("Syntaxe PVE 9 refusée — repli sur la "
                               "syntaxe PVE 8")
                self._ssh(node, f"ha-manager node-maintenance "
                               f"{old_cmd} {node}")
            else:
                # erreur transitoire : retenter TEL QUEL (_ssh ne rejoue
                # que les pertes de transport SSH, pas les rc != 0)
                self.log.warning(f"Commande maintenance HA en échec "
                                 f"transitoire sur {node} ({e}) — nouvel "
                                 f"essai dans 15s…")
                time.sleep(15)
                self._ssh(node, cmd9)

    def ha_sids(self) -> Dict[int, str]:
        """Tous les guests gérés par le cluster HA : vmid → sid complet.
        Une VM QEMU a le sid 'vm:<id>', un CONTENEUR LXC a 'ct:<id>' —
        il faut parser les DEUX, sinon un CT en HA ne serait pas détaché
        (le script le migrerait manuellement pendant que le CRM le
        gère encore)."""
        lst = self.with_api(lambda p: p.cluster.ha.resources.get())
        out: Dict[int, str] = {}
        for r in lst:
            sid = str(r.get("sid", ""))
            for prefix in ("vm:", "ct:"):
                if sid.startswith(prefix):
                    try:
                        out[int(sid.split(":")[1])] = sid
                    except (IndexError, ValueError):
                        pass
                    break
        return out

    def ha_vmids(self):
        """Ensemble des vmid gérés par le cluster HA — VMs QEMU ('vm:')
        et CONTENEURS LXC ('ct:')."""
        return set(self.ha_sids().keys())

    def wait_ha_settled(self, timeout: Optional[int] = None,
                        stable_window: int = 60):
        """Attend que le CRM HA n'ait plus AUCUNE tâche en cours sur les
        ressources (états transitoires : migrate, relocate, recover,
        fence, freeze, lost). En fin de run, garantir un cluster stable
        avant le rapport final.
        timeout=None → HA_SETTLE_TIMEOUT lu À L'APPEL (le défaut d'un
        argument serait figé à sa valeur d'import, avant la relecture
        du --env-file par main()).

        BUDGET ADAPTÉ v22 (vécu 19/11 13:14 : le failback CRM de la VM
        500, live migration RAM-dépendante de ~9 min, a consommé tout
        le budget FIXE de 600 s + presque la fenêtre de confirmation de
        60 s → FATAL « cluster instable » 15 s AVANT la réussite, à
        tort : le CRM TRAVAILLAIT légitimement). Le budget d'une
        « manche » n'est plus un nombre fixe :
        - plancher : PVE_HA_SETTLE_TIMEOUT (défaut 600 s), découplé
          de PVE_MIGRATE_TIMEOUT qui reste le plancher du timeout
          d'UNE tâche de migration ;
        - si des tâches migrate/relocate sont en cours, le budget monte
          à la durée ESTIMÉE de la plus longue (même modèle de débit
          que nos propres migrations, _migrate_timeout_for, plafonné)
          + la fenêtre de confirmation + 60 s de marge de décision CRM ;
        - à CHAQUE changement du set de tâches, la manche repart à
          zéro avec un budget recalculé : le CRM peut ENCHAINER des
          migrations légitimes (failback de plusieurs VMs, gros
          rééquilibrage RAM-dépendant) sans être tué par un budget
          global — c'est le travail normal d'un cluster multi-VMs ;
        - les états recover/fence/freeze/lost ne réarment PAS le
          budget : ce ne sont pas des transferts, c'est déjà le signe
          d'un souci de santé → ils restent soumis au plancher ;
        - garde-fou DUR : la durée TOTALE toutes manches confondues
          est plafonnée à PVE_HA_SETTLE_MAX_TOTAL (défaut 4 h), au-delà
          seulement le FATAL « cluster instable » est justifié.

        NB : un instantané unique ne suffit PAS. À la sortie du mode
        maintenance, le CRM met plusieurs secondes (voire dizaines) à
        DÉCIDER un relocate (ex. rapatriement d'une VM évacuée vers son
        nœud d'origine). Un point isolé « rien en cours » peut donc
        précéder de peu une migration. On exige donc que l'état soit
        stable PENDANT stable_window secondes consécutives : toute
        tâche qui démarre dans la fenêtre réarme le compteur."""
        if timeout is None:
            timeout = HA_SETTLE_TIMEOUT
        transient = ("migrate", "relocate", "recover", "fence", "freeze", "lost")
        transfer = ("migrate", "relocate")
        t_all = time.time()
        round_t0 = t_all
        round_budget: float = timeout
        prev_sig: Optional[frozenset] = None
        ram_memo: Dict[str, Optional[int]] = {}
        stable_since: Optional[float] = None
        last_beat = 0

        def _ram_of(sid: str) -> Optional[int]:
            """RAM max déclarée du guest derrière une sid 'vm:500' :
            GET /cluster/resources (lecture pure), mémoïsée par sid.
            None si illisible -> estimation conservatrice dédiée.
            NB : le préfixe HA ('vm:500') ne correspond PAS au type
            des ressources ('qemu/500') : vm->qemu, ct->lxc."""
            if sid in ram_memo:
                return ram_memo[sid]
            ram: Optional[int] = None
            try:
                parts = str(sid).split(":", 1)
                if len(parts) == 2:
                    kind = {"vm": "qemu", "ct": "lxc"}.get(parts[0],
                                                          parts[0])
                    rid = f"{kind}/{parts[1]}"
                else:
                    rid = None
                for r in self.with_api(lambda p: p.cluster.resources.get()):
                    if rid is not None and r.get("id") == rid:
                        try:
                            ram = int(r.get("maxmem", 0) or 0) or None
                        except (TypeError, ValueError):
                            ram = None
                        break
            except Exception:
                ram = None
            ram_memo[sid] = ram
            return ram

        while True:
            now = time.time()
            if now - t_all > HA_SETTLE_MAX_TOTAL:
                raise RuntimeError(
                    f"Le CRM HA a toujours des tâches en cours après "
                    f"{int(now - t_all)}s (plafond total "
                    f"{HA_SETTLE_MAX_TOTAL}s) — cluster instable")
            items = self.with_api(lambda p: p.cluster.ha.status.current.get())
            busy = [i for i in items if i.get("type") == "service"
                    and any(t in str(i.get("state", "")) for t in transient)]
            sig = frozenset(f"{i.get('sid')}|{i.get('state')}" for i in busy)
            if sig != prev_sig:
                # NOUVELLE MANCHE : apparition/disparition/changement
                # d'état d'au moins une tâche CRM -> budget recalculé.
                prev_sig = sig
                round_t0 = now
                stable_since = None
                est = 0
                why: List[str] = []
                for i in busy:
                    st = str(i.get("state", ""))
                    if not any(t in st for t in transfer):
                        continue    # recover/fence/... : pas un transfert
                    ram = _ram_of(str(i.get("sid")))
                    e = (_migrate_timeout_for(ram)
                         if ram else HA_SETTLE_UNKNOWN_RAM_EST)
                    est = max(est, e)
                    why.append(
                        f"{i.get('sid')} ("
                        + (f"{ram // (1024 ** 3)} GiB, ~{e}s" if ram
                           else f"RAM illisible, ~{e}s") + ")")
                round_budget = timeout
                if est:
                    # + fenêtre de confirmation + marge de décision CRM
                    round_budget = max(timeout, est + 2 * stable_window + 60)
                if busy:
                    self.log.info(
                        "  CRM HA : manche de tâches — budget "
                        + (f"{int(round_budget)}s"
                           + (f" (migrate/relocate : {', '.join(why)})"
                              if why else ""))
                        + f", plafond total {HA_SETTLE_MAX_TOTAL//60} min")
            if not busy:
                if stable_since is None:
                    stable_since = now
                    self.log.info(
                        f"CRM HA : aucune tâche en cours — confirmation "
                        f"pendant {stable_window}s…")
                elif now - stable_since >= stable_window:
                    self.log.info(f"CRM HA : cluster stable depuis "
                                  f"{stable_window}s ✔")
                    return
            else:
                stable_since = None
                if now - round_t0 > round_budget:
                    raise RuntimeError(
                        f"Le CRM HA a toujours des tâches en cours après "
                        f"{int(now - round_t0)}s (budget de manche "
                        f"{int(round_budget)}s) — cluster instable")
                self.log.info("  CRM HA : tâches en cours — "
                              + ", ".join(f"{i.get('sid')} ({i.get('state')})"
                                          for i in busy))
            # battement de cœur pendant la fenêtre de stabilité :
            # un point toutes les 15s prouve que le script tourne toujours
            elapsed = int(time.time() - t_all)
            if elapsed - last_beat >= 15 and stable_since is not None:
                last_beat = elapsed
                self.log.info("  … CRM HA : stabilité confirmée "
                              f"depuis {int(time.time() - stable_since)}s "
                              f"/ {stable_window}s")
            time.sleep(5)

    def ceph_status(self) -> Optional[Dict]:
        """Santé globale Ceph via GET /cluster/ceph/status.
        Retourne None si le cluster n'a pas de Ceph (501/erreur).
        L'absence de Ceph est MÉMOÏSÉE : après la première preuve
        (ex. 500 « binary not installed: ceph-mon », « pveceph
        configuration not initialized »), plus AUCUN appel Ceph
        n'est tenté pour le reste du run."""
        if self._no_ceph:
            return None
        try:
            return self.with_api(lambda p: p.cluster.ceph.status.get())
        except Exception as e:
            msg = str(e)
            if "binary not installed" in msg \
                    or "pveceph configuration not initialized" in msg \
                    or "501" in msg:
                self._no_ceph = True
            return None    # pas de Ceph sur ce cluster : contrôle sans objet

    def ceph_diagnose(self, st: Optional[Dict]) -> None:
        """Diagnostic Ceph quand la santé n'est pas HEALTH_OK : affiche
        les checks détaillés (MON_DOWN, OSD_DOWN, PG_DEGRADED, ...) du
        status déjà récupéré — le détail est DANS le payload
        /cluster/ceph/status, aucune requête SSH/API supplémentaire.
        Ne fait RIEN si st est None (pas de Ceph) ou HEALTH_OK."""
        if st is None:
            return
        h = (st.get("health") or {})
        if h.get("status", "?") == "HEALTH_OK":
            return
        status = h.get("status", "?")
        self.log.warning(f"[Ceph] Diagnostic ({status}) :")
        checks = h.get("checks") or {}
        if not checks:
            self.log.warning("    aucun détail dans le status — "
                             "consultez « ceph -s » / « ceph health "
                             "detail » sur un nœud.")
            return
        for code, c in sorted(checks.items()):
            sev = c.get("severity", "?")
            msg = _check_summary_text(c.get("summary")).strip()
            self.log.warning(f"    {code} [{sev}] : {msg}")
            for d in (c.get("detail") or [])[:3]:
                dm = ((d.get("message") or "").strip()
                      .replace("\n", " "))
                if dm:
                    self.log.warning(f"        {dm[:200]}")

    # Tolérance des avis de sécurité cephx : depuis le hotfix
    # CVE-2025-30156 (Ceph Squid 19.2.6 / Tentacle 20.2.4, 19/08/2026),
    # six checks AUTH_INSECURE_* signalent les clés CephX encore en
    # « aes » (AES-128-CBC, IV fixe, sans HMAC — bypass d'authentica-
    # tion possible). Deux sont en sévérité ERR (AUTH_INSECURE_SERVICE_
    # KEY_TYPE, AUTH_INSECURE_SERVICE_TICKETS) → le cluster passe en
    # HEALTH_ERR alors que stockage et disponibilité sont sains : ces
    # checks ne bloquent NI les IO NI les daemons (avis cryptogra-
    # phique, pas une panne). La remédiation définitive est la rotation
    # des clés vers « aes256k » (procédure Ceph/Proxmox). La tolérance
    # ci-dessous est un pis-aller EXPLICITE, opt-in via
    # PVE_CEPH_ALLOW_AUTH_INSECURE=1, qui filtre UNIQUEMENT ces codes :
    # toute autre dégradation (PG, OSD, MON…) reste bloquante.
    CEPH_AUTH_INSECURE_PREFIX = "AUTH_INSECURE_"

    @staticmethod
    def _ceph_allow_auth_insecure() -> bool:
        return str(_env("PVE_CEPH_ALLOW_AUTH_INSECURE", "0")) == "1"

    def ceph_effective_health(
            self, st: Optional[Dict]) -> Tuple[str, Tuple[str, ...]]:
        """(santé effective, codes ignorés) : recompte la santé Ceph
        après filtrage des checks AUTH_INSECURE_* si (et seulement si)
        PVE_CEPH_ALLOW_AUTH_INSECURE=1. Les codes filtrés sont renvoyés
        pour journalisation ; tout check restant (dégradation RÉELLE du
        stockage) compte normalement. Santé brute si l'option est
        absente ou qu'aucun code ne correspond."""
        if st is None:
            return "?", ()
        h = (st.get("health") or {})
        health = h.get("status", "?")
        checks = h.get("checks") or {}
        ignored = tuple(sorted(
            c for c in checks
            if c.startswith(self.CEPH_AUTH_INSECURE_PREFIX)))
        if not ignored or not self._ceph_allow_auth_insecure():
            return health, ()
        remaining = [c for c in checks.items() if c[0] not in ignored]
        sevs = [str((c or {}).get("severity", "")) for _, c in remaining]
        if any("ERR" in sev for sev in sevs):
            return "HEALTH_ERR", ignored
        if any("WARN" in sev for sev in sevs):
            return "HEALTH_WARN", ignored
        return "HEALTH_OK", ignored

    def ceph_log_auth_insecure(self, ignored: Tuple[str, ...]) -> None:
        """Journalise en une ligne la tolérance des avis AUTH_INSECURE_*
        (message partagé par toutes les gates Ceph)."""
        self.log.warning(
            f"[Ceph] PVE_CEPH_ALLOW_AUTH_INSECURE=1 : {len(ignored)} "
            f"check(s) de sécurité cephx toléré(s) "
            f"({', '.join(ignored)}) — avis cryptographique "
            f"(CVE-2025-30156, clés « aes »), sans impact IO/daemons. "
            f"Remédiation définitive : migrer les clés vers « aes256k ».")

    # Flags de maintenance Ceph pour reboot PLANIFIÉ : sans eux, un
    # reboot qui traîne (> ~5-10 min) fait marquer les OSDs 'out' par
    # les mons → backfill massif vers les autres nœuds, puis rebalance-
    # ment en retour quand le nœud revient (double churn). Avec eux, le
    # cluster NE reconstruit RIEN pendant la fenêtre : les OSDs
    # redescendent 'down' sans être 'out', et le cluster repasse
    # HEALTH_OK dès qu'ils remontent. NB : 'noup'/'nodown' sont
    # volontairement EXCLUS (ils masquent les pannes réelles).
    CEPH_MAINT_FLAGS = ("noout", "norecover", "norebalance",
                        "nobackfill", "noscrub", "nodeep-scrub")

    def ceph_flags_current(self, node: str) -> Optional[Dict[str, bool]]:
        """Flags Ceph actuellement positionnés ({flag: True}), lus via
        « ceph osd dump --format=json » sur le nœud. None = pas de
        Ceph / commande indisponible. Lecture pure : dry-run OK."""
        if self._no_ceph:
            return None
        try:
            out = self._ssh(node, "ceph osd dump --format=json")
            dump = json.loads(out)
            fl = dump.get("flags") or ""
            return {f.strip(): True for f in fl.split(",")
                    if f.strip() and f.strip() != "hash-"}
        except Exception:
            return None

    def ceph_mon_ensure(self, node: str) -> None:
        """2f-bis-0 (AUTO-RÉPARATION, à considérer comme TEMPORAIRE) :
        s'assure que le mon Ceph de CE nœud est actif après le reboot.
        Symptôme observé (PVE 9 / Ceph Tentacle) : ceph-mon@<nœud> échoue
        au boot — probablement démarré avant que le réseau / les pairs /
        l'horloge soient prêts, et le service n'a PAS de Restart= — puis
        ne remonte pas seul, alors qu'un restart MANUEL une fois le nœud
        stabilisé fonctionne. Sans ce rattrapage, la 2f-bis échouerait à
        chaque reboot de ce nœud pour un mon qui démarre en 10 secondes.
        Retour d'expérience (run du 29/10) : sur le nœud au mon malade,
        « systemctl list-units » a renvoyé une liste VIDE juste après le
        reboot (état transitoire de systemd) → AUCUN check, AUCUN
        restart, mon laissé down. La détection passe donc AUSSI par
        /var/lib/ceph/mon/ (source de vérité des mons hébergés par ce
        nœud), et TOUTE anomalie est loggée : plus aucune sortie
        silencieuse. Le journal systemd est loggé AVANT la relance —
        preuves pour le correctif durable (override systemd :
        After=network-online/chronyd + Restart=on-failure)."""
        try:
            out = self._ssh(
                node,
                "ls /var/lib/ceph/mon/ 2>/dev/null | sed 's/^ceph-//'; "
                "systemctl list-units --all --no-legend --no-pager "
                "'ceph-mon@*.service' | awk '{print $1}'")
        except Exception as e:
            self.log.warning(f"[Ceph] mons de {node} non listables "
                             f"({e}) — pas de rattrapage tenté.")
            return
        ids: List[str] = []
        units: List[str] = []
        for l in out.splitlines():
            l = l.strip()
            if not l:
                continue
            if l.startswith("ceph-mon@"):
                if l not in units:
                    units.append(l)
            else:
                ids.append(l)
        # unités à considérer : celles vues par systemd, sinon
        # ceph-mon@<id>.service déduit des répertoires de mons du nœud
        todo = units or [f"ceph-mon@{i}.service" for i in ids]
        if not todo:
            self.log.info(f"  {node} n'héberge pas de mon Ceph — pas de "
                          f"rattrapage nécessaire.")
            return
        for unit in todo:
            try:
                state = self._ssh(
                    node, f"systemctl is-active {unit}").strip()
            except Exception as e:
                self.log.warning(f"  {unit} : état illisible ({e}) — "
                                 f"pas de rattrapage, la 2f-bis "
                                 f"tranchera.")
                continue
            if state == "active":
                self.log.info(f"  {unit} : actif ✔")
                continue
            # INACTIF : preuves d'abord (journal), relance ensuite
            self.log.warning(f"  {unit} : {state} après le reboot — "
                             f"journal récent :")
            try:
                jrn = self._ssh(
                    node, f"journalctl -u {unit} -b --no-pager | tail -15")
                for l in jrn.splitlines():
                    if l.strip():
                        self.log.warning(f"    {l.strip()[:200]}")
            except Exception as e:
                self.log.warning(f"    journal illisible ({e})")
            # ÉTAT « ENABLED » : une instance DISABLED ne démarre
            # JAMAIS au boot — vécu 29/10 : journal vide (« No
            # entries », pas même une tentative), mon hors quorum à
            # chaque reboot, alors qu'un start manuel (UI PVE)
            # fonctionne… parce qu'il ne fait QUE démarrer, sans
            # activer. On corrige durablement, avec log explicite.
            try:
                en = self._ssh(
                    node,
                    f"systemctl is-enabled {unit} 2>/dev/null").strip()
            except Exception:
                en = "?"
            if en in ("disabled", "masked"):
                try:
                    self._ssh(
                        node,
                        ("systemctl unmask" if en == "masked"
                         else "systemctl enable") + f" {unit}")
                    self.log.warning(
                        f"  {unit} : {en} → RÉACTIVÉE (correctif "
                        f"durable : l'instance sera lancée au "
                        f"prochain boot).")
                except Exception as e:
                    self.log.error(
                        f"  {unit} : impossible de réactiver ({e}) — "
                        f"le mon ne remontera PAS au prochain boot, "
                        f"à corriger manuellement.")
            try:
                self._ssh(node, f"systemctl restart {unit}")
            except Exception as e:
                self.log.error(f"  {unit} : restart IMPOSSIBLE ({e}) — "
                               f"la 2f-bis tranchera.")
                continue
            for _ in range(7):            # actif attendu sous ~30s
                time.sleep(5)
                try:
                    st_ = self._ssh(
                        node, f"systemctl is-active {unit}").strip()
                except Exception:
                    continue
                if st_ == "active":
                    self.log.info(f"  {unit} : actif après restart ✔")
                    break
            else:
                self.log.error(f"  {unit} TOUJOURS inactif après "
                               f"restart — voir la 2f-bis qui suivra.")

    # --- REMÉDIATION MON_CLOCK_SKEW (« clock skew » après reboot) ------
    @staticmethod
    def ceph_clock_skews(st: Optional[Dict]) -> List[Tuple[str, str]]:
        """(mon, message) des checks MON_CLOCK_SKEW du status Ceph. La
        ligne du health NOMME le coupable (« mon.p-proxc02 clock skew
        0.156993s > max 0.05s ») : sur PVE, le mon porte le NOM du nœud
        qui l'héberge (pveceph crée les mons nommés d'après les nœuds) —
        c'est donc le nœud dont l'horloge est décalée. La recherche
        couvre le résumé ET les lignes de détail (le nom peut n'apparaî-
        tre que dans l'une des deux selon la version de Ceph), et les
        mons sont dédupliqués. Lecture pure."""
        out: List[Tuple[str, str]] = []
        checks = ((st or {}).get("health") or {}).get("checks") or {}
        for code, c in sorted(checks.items()):
            if code != "MON_CLOCK_SKEW":
                continue
            msgs = [_check_summary_text(c.get("summary"))]
            msgs += [d.get("message") or ""
                     for d in (c.get("detail") or [])]
            for m in msgs:
                mm = re.search(r"mon\.([A-Za-z0-9][\w.-]*)", m or "")
                if not mm:
                    continue
                mon = mm.group(1).rstrip(".,;:")
                if mon and all(mon != x[0] for x in out):
                    out.append((mon, (m or "").strip()))
        return out

    def _clock_fix_node(self, node: str) -> bool:
        """Remédie l'horloge du nœud coupable d'un clock skew. Retourne
        True si l'horloge est PROUVÉE juste à la fin (chrony synchronisé
        et offset sous le seuil). État lu en UNE seule commande SSH :
        « systemctl is-active chrony ; chronyc tracking ». Décisions :
          - chrony INACTIF → restart du service (l'horloge dérive
            sans lui) ;
          - actif mais NON synchronisé → restart du service (au boot,
            chrony peut partir avant le réseau et rester bloqué sur
            des sources mortes : un restart après stabilisation du
            nœud refait la résolution) ;
          - synchronisé mais offset > CLOCK_SKEW_MAX_S → « chronyc
            makestep » (saute l'heure MAINTENANT : le rattrapage
            progressif de chrony laisse le warning vivre des minutes) ;
          - déjà juste → RIEN (reliquat : les mons ré-évalueront seuls,
            ~30s)."""
        try:
            out = self._ssh(
                node,
                "systemctl is-active chrony 2>/dev/null; echo ---; "
                "chronyc tracking 2>/dev/null")
        except Exception as e:
            self.log.warning(f"[Ceph] {node} : état chrony illisible "
                             f"({e}) — remédiation horloge impossible.")
            return False
        parts = out.split("---")
        active = parts[0].strip().lower() == "active"
        tracking = parts[1] if len(parts) > 1 else ""
        sync = ("Leap status" in tracking
                and "Not synchronised" not in tracking)
        mm = re.search(r"System time\s*:\s*([0-9.]+)\s*seconds",
                       tracking)
        offset = abs(float(mm.group(1))) if mm else None
        if not active:
            self.log.warning(f"[Ceph] {node} : chrony INACTIF → "
                             f"restart du service.")
            action = "systemctl restart chrony"
        elif not sync:
            self.log.warning(f"[Ceph] {node} : chrony actif mais NON "
                             f"synchronisé (sources NTP mortes ?) → "
                             f"restart du service.")
            action = "systemctl restart chrony"
        elif offset is not None and offset > CLOCK_SKEW_MAX_S:
            self.log.warning(f"[Ceph] {node} : synchronisé mais offset "
                             f"{offset:.3f}s > {CLOCK_SKEW_MAX_S}s → "
                             f"chronyc makestep (saut d'heure "
                             f"immédiat).")
            action = "chronyc makestep"
        else:
            self.log.info(f"[Ceph] {node} : horloge déjà juste "
                          f"(synchronisée, offset "
                          f"{f'{offset:.3f}s' if offset is not None else '?'}"
                          f") — pas d'action, le warning partira à la "
                          f"prochaine ré-évaluation des mons (~30s).")
            return True
        try:
            self._ssh(node, action)
        except Exception as e:
            self.log.error(f"[Ceph] {node} : « {action} » IMPOSSIBLE "
                           f"({e}).")
            return False
        if action == "chronyc makestep":
            # le pas est immédiat : une re-lecture suffit
            time.sleep(2)
        # attendre la resynchronisation (restart) / vérifier le pas
        t0 = time.time()
        while time.time() - t0 < CLOCK_CHRONY_TIMEOUT_S:
            try:
                out = self._ssh(
                    node,
                    "systemctl is-active chrony 2>/dev/null; "
                    "echo ---; chronyc tracking 2>/dev/null")
            except Exception:
                time.sleep(5)
                continue
            parts = out.split("---")
            if parts[0].strip().lower() != "active":
                time.sleep(5)
                continue
            tracking = parts[1] if len(parts) > 1 else ""
            if "Leap status" not in tracking \
                    or "Not synchronised" in tracking:
                time.sleep(5)
                continue
            mm = re.search(r"System time\s*:\s*([0-9.]+)\s*seconds",
                           tracking)
            off = abs(float(mm.group(1))) if mm else None
            if off is None or off <= CLOCK_SKEW_MAX_S:
                self.log.info(f"[Ceph] {node} : chrony synchronisé "
                              f"(offset "
                              f"{f'{off:.3f}s' if off is not None else '?'}"
                              f") ✔")
                return True
            time.sleep(5)
        self.log.error(f"[Ceph] {node} : chrony toujours pas "
                       f"resynchronisé après {CLOCK_CHRONY_TIMEOUT_S}s "
                       f"— vérifiez « chronyc sources » (NTP joignable "
                       f"?), le pare-feu UDP/123 et la connectivité du "
                       f"nœud.")
        return False

    def _clock_wait_clear(self, timeout_s: int, context: str) -> bool:
        """Attend que les mons ré-évaluent l'horloge (intervalle
        mon_timecheck_skew_interval, ~30 s) et que MON_CLOCK_SKEW
        disparaisse du status. Un skew dont l'horloge devient juste
        part TOUT SEUL — aucun restart de mon nécessaire."""
        t0 = time.time()
        next_beat = 0
        while time.time() - t0 < timeout_s:
            elapsed = int(time.time() - t0)
            if elapsed >= next_beat:
                next_beat = elapsed + 30
                self.log.info(f"[Ceph] {context} : attente de la "
                              f"ré-évaluation des mons "
                              f"({elapsed}s/{timeout_s}s)…")
            time.sleep(5)
            try:
                if not self.ceph_clock_skews(self.ceph_status()):
                    return True
            except Exception:
                continue
        return False

    def _clock_mon_restart(self, mon: str, st: Optional[Dict],
                           context: str) -> bool:
        """DERNIER RECOURS : restart du mon signalé skewé alors que
        l'horloge de son nœud est PROUVÉE juste — c'est le mon qui
        garde un relevé décalé (mon mal réveillé après le reboot,
        latence de heartbeat). UN SEUL mon à la fois, et UNIQUEMENT si
        le quorum conserve la majorité STRICTE : sans majorité, TOUT
        le cluster fige ses IO — refusé sur un cluster à 2 mons (le
        restart en laisserait 1/2). Gate : retour du mon au quorum
        sous CLOCK_MON_REJOIN_TIMEOUT_S."""
        mons = ((st or {}).get("monmap") or {}).get("mons") or []
        rank = next((m.get("rank") for m in mons
                     if m.get("name") == mon), None)
        quorum = (st or {}).get("quorum") or []
        nq, nmon = len(quorum), len(mons)
        majority = nmon // 2 + 1
        if rank is None or rank not in quorum:
            self.log.warning(f"[Ceph] mon.{mon} hors quorum/inconnu — "
                             f"pas de restart (ce n'est pas un skew, "
                             f"c'est un mon down : la gate santé "
                             f"tranchera).")
            return False
        remaining = nq - 1
        if nmon < 3 or remaining < majority:
            self.log.warning(
                f"[Ceph] restart de mon.{mon} REFUSÉ : il ne "
                f"resterait que {remaining}/{nmon} en quorum "
                f"(< majorité {majority}) — sans majorité stricte, "
                f"tout le cluster figerait ses IO. Correctif manuel "
                f"requis une fois le run terminé.")
            return False
        self.log.warning(
            f"[Ceph] {context} : skew persistant malgré une horloge "
            f"prouvée juste → DERNIER RECOURS : restart "
            f"ceph-mon@{mon} (quorum {nq}/{nmon}, reste "
            f"{remaining} ≥ majorité {majority}, IO continues).")
        try:
            self._ssh(mon, f"systemctl restart ceph-mon@{mon}.service")
        except Exception as e:
            self.log.error(f"[Ceph] restart ceph-mon@{mon} IMPOSSIBLE "
                           f"({e}).")
            return False
        # gate : retour du mon au quorum
        t0 = time.time()
        while time.time() - t0 < CLOCK_MON_REJOIN_TIMEOUT_S:
            time.sleep(5)
            try:
                s2 = self.ceph_status() or {}
            except Exception:
                continue
            mons2 = ((s2.get("monmap") or {}).get("mons") or [])
            rank2 = next((m.get("rank") for m in mons2
                          if m.get("name") == mon), rank)
            if rank2 in (s2.get("quorum") or []):
                self.log.info(f"[Ceph] mon.{mon} DE RETOUR au quorum ✔")
                return True
        self.log.error(f"[Ceph] mon.{mon} pas revenu au quorum sous "
                       f"{CLOCK_MON_REJOIN_TIMEOUT_S}s — la gate santé "
                       f"tranchera (arrêt propre du run).")
        return False

    def ceph_clock_skew_fix(self, st: Optional[Dict], context: str) -> bool:
        """Remédie un MON_CLOCK_SKEW détecté dans le status Ceph :
        1) horloge du/des nœud(s) coupable(s) — restart chrony ou
           makestep (rien si l'horloge est déjà juste) ;
        2) attente de la ré-évaluation par les mons (~30 s) — un skew
           à horloge juste part SEUL ;
        3) DERNIER RECOURS : restart du mon si (et seulement si)
           l'horloge est prouvée juste ET que le quorum garde la
           majorité stricte (PVE_CEPH_CLOCK_MON_RESTART=0 pour
           l'interdire). Retourne True si plus AUCUN MON_CLOCK_SKEW ne
        subsiste. En dry-run (can_remediate=False) : n'exécute RIEN,
        se borne à expliquer ce que le run réel fera."""
        skews = self.ceph_clock_skews(st)
        if not skews:
            return True
        for mon, msg in skews:
            self.log.warning(f"[Ceph] MON_CLOCK_SKEW ({context}) : {msg}")
        if not self.can_remediate:
            self.log.warning(
                f"[Ceph] Dry-run : RIEN n'est exécuté. Le run réel "
                f"remédierait automatiquement : restart chrony (ou "
                f"chronyc makestep) sur le(s) nœud(s) signalé(s) "
                f"({', '.join(sorted(m for m, _ in skews))}), attente "
                f"de ré-évaluation des mons, puis restart du mon en "
                f"DERNIER RECOURS si le quorum garde la majorité "
                f"stricte (refusé à 2 mons).")
            return False
        known = set(self.node_names())
        for mon, _msg in skews:
            if mon not in known:
                self.log.warning(
                    f"[Ceph] mon.{mon} ne correspond à aucun nœud du "
                    f"cluster — horloge non remédiable par le script : "
                    f"vérifiez manuellement sa synchro NTP "
                    f"(« chronyc sources ») sur l'hôte qui le porte.")
                continue
            self._clock_fix_node(mon)
        # ré-évaluation : un skew à horloge juste part SEUL
        if self._clock_wait_clear(CLOCK_REEVAL_TIMEOUT_S, context):
            return True
        still = self.ceph_clock_skews(self.ceph_status())
        if not still:
            return True
        if str(_env("PVE_CEPH_CLOCK_MON_RESTART", "1")) != "0":
            st2 = self.ceph_status()
            for mon, _msg in still:
                self._clock_mon_restart(mon, st2, context)
            # dernière ré-évaluation après rejointure du mon
            return self._clock_wait_clear(CLOCK_REEVAL_TIMEOUT_S, context)
        self.log.warning(f"[Ceph] PVE_CEPH_CLOCK_MON_RESTART=0 : "
                         f"restart du mon DÉSACTIVÉ — skew persistant "
                         f"laissé en l'état (la gate santé décidera).")
        return not self.ceph_clock_skews(self.ceph_status())

    def ceph_maintenance_on(self, node: str) -> Dict[str, bool]:
        """Reboot planifié : pose les flags de maintenance Ceph. Retourne
        UNIQUEMENT les flags que LE RUN a posés (les flags déjà posés
        par l'administrateur ne sont pas touchés et ne seront pas
        retirés). Un échec n'est PAS fatal : sans flags le reboot reste
        correct, il y a juste un risque de churn Ceph si le reboot
        traîne. Ne rien faire si le cluster n'a pas de Ceph."""
        cur = self.ceph_flags_current(node)
        if cur is None:
            return {}
        changed: Dict[str, bool] = {}
        for f in self.CEPH_MAINT_FLAGS:
            if f in cur:
                self.log.info(f"[Ceph] flag {f} déjà posé (admin) — "
                              f"conservé tel quel.")
                continue
            try:
                self._ssh(node, f"ceph osd set {f}")
                changed[f] = True
            except Exception as e:
                self.log.warning(f"[Ceph] flag {f} non posé ({e}) — le "
                                 f"reboot continue sans lui (risque de "
                                 f"churn Ceph si le reboot traîne).")
        if changed:
            self.log.info(f"[Ceph] Maintenance Ceph : flags posés pour "
                          f"le reboot ({', '.join(sorted(changed))}) — le "
                          f"cluster ne reconstruit RIEN pendant la "
                          f"fenêtre.")
        return changed

    def ceph_maintenance_off(self, changed: Dict[str, bool],
                             nodes: List[str]) -> None:
        """Fin de fenêtre : retire UNIQUEMENT les flags posés par le run
        (ceux de l'administrateur restent). Les flags sont globaux au
        cluster : on essaie chaque nœud fourni jusqu'à ce qu'un SSH
        réponde (le nœud traité peut être injoignable : reboot bloqué,
        nœud mort). Le retrait est une opération SÛRE : le cluster
        reprend son mode nominal, y compris si l'upgrade n'a pas abouti
        — c'est justement le but (que Ceph reconstruise ce qu'il doit).
        Retourne la liste des flags EFFECTIVEMENT retirés (les autres
        restent suivis par le fichier d'état)."""
        if not changed:
            return
        removed: List[str] = []
        reachable = False
        for n in nodes:
            try:
                self._ssh(n, "ceph osd dump >/dev/null 2>&1")
                reachable = True
                for f in sorted(changed):
                    try:
                        self._ssh(n, f"ceph osd unset {f}")
                        removed.append(f)
                    except Exception as e:
                        self.log.warning(f"[Ceph] flag {f} non retiré "
                                         f"({e}) — il restera suivi par "
                                         f"le fichier d'état.")
                break
            except Exception:
                continue          # nœud injoignable : essayer le suivant
        if removed:
            self.log.info(f"[Ceph] Maintenance Ceph : flags retirés "
                          f"({', '.join(removed)}) — le cluster reprend "
                          f"son fonctionnement nominal.")
        if not reachable:
            self.log.error(f"[Ceph] IMPOSSIBLE de contacter Ceph : "
                           f"flags {', '.join(sorted(changed))} NON "
                           f"retirés — retrait manuel requis : "
                           f"« ceph osd unset <flag> ».")
        return removed

    def check_ceph_ready(self, node: str, action: str,
                         timeout: int = CEPH_TIMEOUT):
        # Timeout configurable : sur un gros cluster, le recovery/backfill
        # entre deux nœuds peut dépasser le défaut de 900s — la gate reste
        # alors SÛRE (refus) mais interrompt le run. Allonger le délai via
        # PVE_CEPH_READY_TIMEOUT (secondes) sans toucher à l'exigence
        # HEALTH_OK, qui est LA protection anti-dégradation cumulée.
        timeout = int(_env("PVE_CEPH_READY_TIMEOUT", str(timeout)) or timeout)
        """HYPERCONVERGENCE : ne JAMAIS évacuer/rebooter un nœud pendant que
        Ceph reconstruit (recovery, backfill, rebalance). Rebooter un
        second nœud alors que les répliques se répliquent peut faire
        perdre à la fois plusieurs copies d'un même PG — c'est LA
        catastrophe à éviter. Bloque tant que ce n'est pas HEALTH_OK
        (HEALTH_WARN toléré si PVE_CEPH_ALLOW_WARN=1, à vos risques ;
        checks de sécurité cephx AUTH_INSECURE_* tolérés si
        PVE_CEPH_ALLOW_AUTH_INSECURE=1 — avis CVE-2025-30156, sans
        impact stockage/disponibilité).
        Vérifie aussi que tous les OSDs du nœud sont 'up'.
        Un check MON_CLOCK_SKEW (« mon.X clock skew … > max 0.05s »,
        typique au retour d'un nœud après reboot/upgrade noyau) est
        remédié AUTOMATIQUEMENT (restart chrony / chronyc makestep,
        puis restart du mon en DERNIER RECOURS si le quorum garde la
        majorité stricte) ; en dry-run rien n'est exécuté, il est
        toléré avec une explication (le run réel le corrigerait)."""
        st = self.ceph_status()
        if st is None:
            # cluster sans Ceph : message informatif UNE fois, puis silence
            if self._no_ceph and not self._no_ceph_logged:
                self._no_ceph_logged = True
                self.log.info("Cluster sans Ceph — les contrôles Ceph "
                              "(santé + OSD) sont ignorés pour tout le run.")
            return
        allow_warn = str(_env("PVE_CEPH_ALLOW_WARN", "0")) == "1"
        health, ignored = self.ceph_effective_health(st)
        if ignored:
            self.ceph_log_auth_insecure(ignored)
        t0 = time.time()
        diag_done = False       # diagnostic détaillé affiché UNE fois
        skew_attempted = False   # remédiation MON_CLOCK_SKEW tentée UNE fois
        while health not in ("HEALTH_OK",):
            if not diag_done:
                self.ceph_diagnose(st)
                diag_done = True
            if health == "HEALTH_WARN" and allow_warn:
                self.log.warning("Ceph en HEALTH_WARN — toléré "
                                 "(PVE_CEPH_ALLOW_WARN=1)")
                break
            # MON_CLOCK_SKEW : warning d'HORLOGE, bénin pour le
            # stockage, typique d'un nœud qui revient d'un reboot —
            # remédiation automatique au lieu de laisser la gate
            # échouer sur un problème que chrony corrige en quelques
            # secondes. Le cluster peut aussi être resté skewé d'un
            # reboot antérieur (hors run) : la gate le corrige alors
            # AVANT de démarrer l'évacuation.
            if "MON_CLOCK_SKEW" in ((st.get("health") or {})
                                    .get("checks") or {}) \
                    and not skew_attempted:
                skew_attempted = True
                if self.ceph_clock_skew_fix(
                        st, f"avant {action} de {node}"):
                    st = self.ceph_status() or {}
                    health, _ignored = self.ceph_effective_health(st)
                    continue
                if not self.can_remediate:
                    # dry-run : le run réel remédierait et repasserait
                    # cette gate — toléré avec explication explicite.
                    self.log.warning(
                        "Ceph en HEALTH_WARN (MON_CLOCK_SKEW) — TOLÉRÉ "
                        "pour ce dry-run : rien n'est exécuté, mais le "
                        "run réel remédierait automatiquement (restart "
                        "chrony / makestep, puis restart du mon en "
                        "dernier recours) et repasserait cette gate.")
                    break
            if time.time() - t0 > timeout:
                checks = (st.get("health") or {}).get("checks") or {}
                ai_only = bool(checks) and all(
                    c.startswith(self.CEPH_AUTH_INSECURE_PREFIX)
                    for c in checks)
                hint = (" NB : cet état provient uniquement de checks "
                        "de sécurité cephx AUTH_INSECURE_* (Ceph ≥ "
                        "19.2.6, CVE-2025-30156 — clés « aes », sans "
                        "impact IO/daemons) : PVE_CEPH_ALLOW_AUTH_"
                        "INSECURE=1 les tolère ; remédiation définitive "
                        "= migration des clés vers « aes256k »."
                        if ai_only else "")
                if set(checks) == {"MON_CLOCK_SKEW"}:
                    hint = (" NB : il ne reste qu'un MON_CLOCK_SKEW — "
                            "la remédiation automatique (restart "
                            "chrony / makestep, restart du mon en "
                            "dernier recours) n'a pas suffi : l'horloge "
                            "du nœud signalé ne se resynchronise pas "
                            "(« chronyc sources » : NTP joignable ? "
                            "pare-feu UDP/123 ?).")
                raise RuntimeError(
                    f"Ceph est en {health} depuis plus de {timeout}s — "
                    f"{action} de {node} REFUSÉ : un nœud ne doit pas "
                    f"tomber pendant une reconstruction. Corrigez Ceph "
                    f"(ou attendez la fin du recovery/backfill) et "
                    f"relancez.{hint}")
            self.log.warning(f"Ceph {health} avant « {action} » de {node} "
                             f"— reconstruction en cours, attente "
                             f"(recheck toutes les 15s)…")
            time.sleep(15)
            st = self.ceph_status() or {}
            health, _ignored = self.ceph_effective_health(st)
        # les OSDs du nœud doivent être 'up' : sinon les évacuer = ?
        # NB : le champ 'state' varie selon PVE/Ceph ("exists,up", liste
        # ["exists","up"], "active", "exists,down"…). Tolérant : un OSD
        # est refusé uniquement s'il est EXPLICITEMENT down/missing ;
        # un état inconnu n'interrompt pas le run (log debug).
        # Ce contrôle est un DIAGNOSTIC optionnel : si l'endpoint n'est
        # pas disponible (501, version PVE différente…), on dégrade en
        # warning — jamais en erreur fatale, la gate santé a déjà passé.
        class OsdDown(RuntimeError):
            pass
        try:
            try:
                # PVE 8/9 : GET /nodes/{node}/ceph/osd (singulier)
                osds = self.with_api(
                    lambda p: p.nodes(node).ceph.osd.get()) or []
            except RuntimeError:
                # repli ancien schéma /ceph/osds (PVE ≤ 7) ; s'il
                # échoue aussi, dégradation silencieuse ci-dessous.
                osds = self.with_api(
                    lambda p: p.nodes(node).ceph.osds.get(),
                    retries=0, quiet=True) or []
            down = []
            # Normalisation : selon la version PVE, proxmoxer peut renvoyer
            # la charge brute en str (JSON non décodé), une liste de dicts,
            # ou un dict unique. On tolère tout ce qui est décodable.
            if isinstance(osds, str):
                try:
                    osds = json.loads(osds)
                except ValueError:
                    osds = []
            if isinstance(osds, dict):
                osds = [osds]
            if not isinstance(osds, list):
                osds = []
            if not osds:
                # liste vide = aucun OSD sur ce nœud (légitime : tous
                # les nœuds n'hébergent pas d'OSD en hyperconvergence
                # partielle). Rien à vérifier, gate santé déjà passée.
                self.log.info(f"Aucun OSD sur {node} — rien à vérifier.")
                return
            if not all(isinstance(o, dict) for o in osds):
                self.log.warning(f"OSDs de {node} non vérifiables "
                                 f"(réponse inattendue) — contrôle OSD "
                                 f"sauté (santé Ceph déjà validée).")
                return
            for o in osds:
                raw = o.get("state", o.get("status", ""))
                states = (raw if isinstance(raw, list)
                          else str(raw).replace(",", " ").split())
                if any(s in ("down", "missing", "created") for s in states):
                    down.append(o.get("id", "?"))
            if down:
                raise OsdDown(
                    f"OSD(s) {down} de {node} sont down — "
                    f"{action} REFUSÉ (données du nœud non répliquées).")
        except OsdDown:
            raise
        except Exception as e:
            self.log.warning(f"OSDs de {node} non vérifiables ({e}) — "
                             f"contrôle OSD sauté (santé Ceph déjà validée).")
        self.log.info(f"Ceph HEALTH_OK, OSDs de {node} opérationnels ✔")

    def wait_ha_evacuated(self, node: str, ha_vmids: Set[int],
                          timeout: Optional[int] = None):
        """Attend que le CRM ait évacué TOUTES les ressources HA du nœud,
        en deux conditions :
        1. plus aucune entrée /cluster/ha/resources ne pointe sur le nœud ;
        2. plus aucun guest HA ne se trouve PHYSIQUEMENT sur le nœud —
           l'entrée ressource change dès que la migration est DÉCLENCHÉE,
           mais la VM (live-)migre encore : migrer un guest dont la
           migration HA est en cours échoue ou se fait refuser.
        timeout=None → MIGRATE_TIMEOUT lu À L'APPEL (cf. wait_ha_settled).
        NB : le choix des cibles revient au CRM (règles d'affinité) ; une
        migration manuelle vers une cible arbitraire serait rejetée avec
        « not allowed on target node »."""
        if timeout is None:
            timeout = MIGRATE_TIMEOUT
        t0 = time.time()
        while time.time() - t0 < timeout:
            lst = self.with_api(lambda p: p.cluster.ha.resources.get())
            on_node = [r for r in lst if r.get("node") == node]
            guests = {}
            for res in self.with_api(lambda p: p.cluster.resources.get()):
                if res.get("type") in ("qemu", "lxc"):
                    guests[res["vmid"]] = res.get("node")
            still_here = sorted(v for v in ha_vmids if guests.get(v) == node)
            if not on_node and not still_here:
                self.log.info(f"  CRM : ressources HA parties de {node} "
                              f"et VMs effectivement migrées ✔")
                return
            msg = []
            if on_node:
                msg.append(", ".join(str(r.get("sid")) for r in on_node)
                           + " (ressource)")
            if still_here:
                msg.append(", ".join(f"vm:{v} (guest encore sur {node})"
                                     for v in still_here))
            self.log.info(f"  CRM : évacuation HA en cours — {' ; '.join(msg)}…")
            time.sleep(10)
        raise RuntimeError(f"Le CRM n'a pas terminé l'évacuation HA de "
                           f"{node} après {timeout}s")

    def ha_rules(self) -> List[Dict]:
        """Règles HA (affinités) pour affichage : PVE ≥ 9 remplace les
        groupes par des règles de niveau/priorité de nœuds. Échec
        silencieux sur PVE 8 (endpoint absent)."""
        try:
            return self.with_api(lambda p: p.cluster.ha.rules.get())
        except Exception:
            return []

    def ha_rule_update(self, rid: str, **params) -> None:
        """PUT /cluster/ha/rules/{rid} : met à jour une règle d'affinité.
        NB CRITIQUE (schéma PVE 9, vérifié sur un run réel 9.1/9.2) : le
        PUT exige TOUJOURS le paramètre « type » (le schéma est
        type-dépendant : sans lui, tout autre champ de sous-schéma est
        refusé « property is not defined in schema ») ; selon la version
        de PVE, le champ « disable » peut ne PAS être exposé par l'API
        (alors que ha-manager le connaît) → toujours passer `type`, et
        prévoir les modes de repli « resources » / « delete »."""
        self.with_api(lambda p: p.cluster.ha.rules(rid).put(**params))

    def ha_rule_delete(self, rid: str) -> None:
        """DELETE /cluster/ha/rules/{rid} : dernier recours pour mettre
        une règle « en sommeil » sur un PVE dont l'API refuse à la fois
        « disable » et « resources » vides — la définition d'origine est
        dans le snapshot, la règle est recréée à l'identique en fin
        d'Étape 1 (ou à la reprise d'un run interrompu)."""
        self.with_api(lambda p: p.cluster.ha.rules(rid).delete())

    def ha_rule_get(self, rid: str) -> Optional[Dict]:
        """Re-lit l'état COURANT d'une règle HA côté cluster (GET
        /cluster/ha/rules, filtrage local par rid) : retourne la règle,
        None si elle est absente. À la différence de ha_rules() —
        silencieux sur échec — cette méthode LÈVE en cas d'erreur
        transport : elle sert à VÉRIFIER qu'un PUT a bien eu son EFFET,
        car un PUT accepté (HTTP 200) peut rester SANS EFFET côté HA
        Manager (cas PVE 9 : « disable=0 » ne réactive PAS une règle
        désactivée — correctif officiel pve-manager : SUPPRIMER la
        propriété « disable »)."""
        for r in self.with_api(lambda p: p.cluster.ha.rules.get()):
            if str(r.get("rid") or r.get("rule") or r.get("id")
                   or "") == rid:
                return r
        return None

    def ha_rule_create(self, **params) -> None:
        """POST /cluster/ha/rules : recrée une règle supprimée par un
        run interrompu (définition d'origine du snapshot). NB : le
        paramètre d'identifiant du schéma PVE 9 est « rule » ( PAS
        « rid » : un POST avec « rid » est refusé 400 — « property is
        not defined in schema » + « rule is missing »)."""
        self.with_api(lambda p: p.cluster.ha.rules.post(**params))

    # ---------- gestion HA « pilotée par le script » (PVE < 9.2 : pas de
    # CRS dynamic, le CRM ne tient pas compte de la charge lors d'une
    # évacuation → risque d'empilement de VMs sur un même nœud) ------
    def ha_resources_detail(self) -> List[Dict]:
        """Toutes les ressources HA avec leur config complète
        (sid, state, group, comment…)."""
        return self.with_api(lambda p: p.cluster.ha.resources.get())

    def ha_resource_snapshot(self, sid: str) -> Dict[str, str]:
        """État d'origine (state + comment) d'une ressource HA — le
        « point zéro » à restaurer quelle que soit la façon dont le run
        se termine."""
        detail = next((r for r in self.ha_resources_detail()
                       if r.get("sid") == sid), {})
        return {"state": detail.get("state", "started") or "started",
                "comment": detail.get("comment", "") or ""}

    def ha_set_resource(self, sid: str, state: str,
                        comment: Optional[str] = None) -> None:
        """PUT /cluster/ha/resources/{sid} : change l'état d'une
        ressource HA ('ignored' / 'started' / …) et, au mieux, son
        champ comment (label de traçabilité). Le champ comment
        n'existe que sur les PVE récents : en cas de refus on RETENTE
        sans le comment — l'état reste l'essentiel, le label est un
        confort."""
        params: Dict[str, str] = {"state": state}
        if comment is not None:
            params["comment"] = comment
        try:
            self.with_api(lambda p: p.cluster.ha.resources(sid).put(**params))
        except Exception as e:
            if "comment" in params:
                self.log.warning(f"Ressource {sid} : champ « comment » "
                                 f"refusé ({e}) — reprise sans le label.")
                del params["comment"]
                self.with_api(
                    lambda p: p.cluster.ha.resources(sid).put(**params))
            else:
                raise

    def vm_alive(self, node: str, vmid: int, vmtype: str = "qemu",
                  expect: str = "running") -> bool:
        """Diagnostic post-migration : la VM a-t-elle réellement survécu au
        déplacement ? `expect` = l'état AVANT la migration :
        - VM running : guest agent présent → agent/ping (l'OS répond) ;
          sinon qmpstatus 'running' + processus qemu actif ;
        - VM stopped : la migration est HORS LIGNE (config déplacée) :
          constater 'stopped' est le résultat ATTENDU ✔ ;
        - divergence (running → stopped) : échec réel.
        Retourne False uniquement si l'état constaté est anormal."""
        try:
            kind = "CT" if vmtype == "lxc" else "VM"
            st = self.with_api(
                lambda p: getattr(p.nodes(node), vmtype)(vmid)
                .status.current.get())
            qmp = str(st.get("qmpstatus", st.get("status", "")))
            if qmp == "stopped":
                if expect == "stopped":
                    self.log.info(f"  {kind} {vmid} sur {node} : "
                                  f"stopped (état attendu) ✔ — migration "
                                  f"hors ligne de la configuration")
                    return True
                self.log.error(f"{kind} {vmid} sur {node} : elle "
                               f"TOURNAIT avant la migration et est "
                               f"maintenant 'stopped' — la migration "
                               f"l'a tuée.")
                return False
            if qmp != "running":
                self.log.error(f"{kind} {vmid} sur {node} : "
                               f"statut '{qmp}' (attendu '{expect}') — "
                               f"état anormal.")
                return False
            if st.get("agent"):
                try:
                    self.with_api(
                        lambda p: getattr(p.nodes(node), vmtype)(vmid)
                        .agent.ping.post())
                    self.log.info(f"  {kind} {vmid} : guest agent "
                                   f"répond — OS vivant ✔")
                except Exception as e:
                    self.log.warning(f"  {kind} {vmid} sur {node} : guest "
                                     f"actif mais agent injoignable ({e}) "
                                     f"— OS en cours de boot, figé, ou "
                                     f"agent désactivé dans l'OS.")
            else:
                if vmtype == "lxc":
                    self.log.info(f"  CT {vmid} sur {node} : conteneur "
                                  f"actif (pas de guest agent LXC — OS "
                                  f"non vérifiable).")
                else:
                    self.log.info(f"  VM {vmid} sur {node} : processus "
                                  f"qemu actif (pas de guest agent — OS "
                                  f"non vérifiable).")
            return True
        except Exception as e:
            self.log.error(f"{kind} {vmid} sur {node} : statut "
                           f"illisible ({e}).")
            return False

    def vm_status(self, node: str, vmid: int, vmtype: str = "qemu"
                  ) -> Optional[Dict]:
        """État d'un guest VU DE CE NŒUD, ou None si le guest n'y est PAS
        (config absente sur ce nœud : l'API répond en erreur — c'est le
        signe que le guest réside ailleurs). Diagnostic de LOCALISATION
        après un échec de migration (reprise v18)."""
        try:
            return self.with_api(
                lambda p: getattr(p.nodes(node), vmtype)(vmid)
                .status.current.get())
        except Exception:
            return None

    def vm_start(self, node: str, vmid: int, vmtype: str = "qemu",
                 timeout: Optional[int] = None):
        """Démarre un guest sur un nœud (tâche asynchrone attendue).
        Reprise v18 : une VM arrêtée par une course QEMU au « resume »
        de la migration doit repartir AU PLUS VITE — ses disques et sa
        config sont DÉJÀ sur le nœud cible."""
        if timeout is None:
            # lu À L'APPEL (pas de défaut capturé à l'import : une valeur
            # PVE_START_TIMEOUT du --env-file doit rester effective).
            timeout = START_TIMEOUT
        self.log.info(f"  Démarrage du "
                      f"{'CT' if vmtype == 'lxc' else 'VM'} {vmid} sur "
                      f"{node} (timeout {timeout}s)…")
        task = self.with_api(
            lambda p: getattr(p.nodes(node), vmtype)(vmid)
            .status.start.post())
        self._wait_task(node, task, timeout=timeout)

    def ha_maintenance_on(self, node: str):
        self.log.info(f"Activation du mode maintenance HA sur {node}")
        self._ha_maintenance(node, "enable", "on")

    def ha_maintenance_off(self, node: str):
        self.log.info(f"Sortie du mode maintenance HA sur {node}")
        self._ha_maintenance(node, "disable", "off")

    def shared_storages(self, node: str) -> Optional[Set[str]]:
        """Storages PARTAGÉS visibles depuis CE nœud (Ceph, SAN, NFS…) :
        GET /nodes/{node}/storage, champ « shared ». La config des
        storages est synchronisée cluster-wide (storage.cfg) : la liste
        d'UN nœud couvre tous les storages utilisables par ses guests.
        NB : /cluster/storage N'EXISTE PAS dans l'API PVE (501 Not
        Implemented — vécu : cycle complet de bascule d'hôte à chaque
        guest sur Cluster-C4). Mémoïsé par nœud ; None si échec (les
        guests suivants n'en refont PAS la tentative)."""
        if node in self._shared_storages_cache:
            return self._shared_storages_cache[node]
        res: Optional[Set[str]] = None
        try:
            res = {s.get("storage", "")
                   for s in self.with_api(
                       lambda p: p.nodes(node).storage.get())
                   if str(s.get("shared", "0")) in ("1", "true")}
        except Exception:
            res = None
        self._shared_storages_cache[node] = res
        return res

    def vm_on_local_storage(self, node: str, vmid: int,
                            vmtype: str) -> Optional[bool]:
        """True si le guest a au moins un disque sur un stockage NON
        partagé (« stockage LOCAL ») : sa migration copiera ses disques
        (with-local-disks), ce que l'estimation de durée du bilan
        dry-run ne modélise PAS. False = tout sur stockage partagé.
        None = indéterminé (config ou storages illisibles). Mémoïsé
        par (vmtype, vmid) : l'appel n'a lieu qu'à la PREMIÈRE
        migration simulée du guest, quand il est encore sur son
        nœud RÉEL (l'état interne est déjà simulé ensuite)."""
        key = (vmtype, vmid)
        if key in self._vm_local_disks:
            return self._vm_local_disks[key]
        shared = self.shared_storages(node)
        if shared is None:
            # storages illisibles sur ce nœud (échec mémoïsé) : inutile
            # de lire la config du guest — indéterminé, sans autre appel
            self._vm_local_disks[key] = None
            return None
        res: Optional[bool] = None
        try:
            cfg = (self.with_api(
                       lambda p: p.nodes(node).lxc(vmid).config.get())
                   if vmtype == "lxc" else
                   self.with_api(
                       lambda p: p.nodes(node).qemu(vmid).config.get()))
            stors = set()
            for k, v in (cfg or {}).items():
                if not isinstance(v, str):
                    continue
                # clés disques : ide0, sata0, scsi0, virtio0, efidisk0,
                # tpmstate0, unused0 (qemu) ; rootfs, mp0, unused0 (lxc)
                if not re.match(r"^(rootfs|(unused|mp|ide|sata|scsi|"
                                r"virtio|efidisk|tpmstate)\d+)$", k):
                    continue
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+):", v)
                if m:
                    stors.add(m.group(1))
            res = bool(stors) and not stors <= shared
        except Exception:
            res = None
        self._vm_local_disks[key] = res
        return res

    def vm_onboot(self, node: str, vmid: int, vmtype: str) -> Optional[bool]:
        """Option « start at boot » (onboot) d'un guest : True si onboot=1,
        False si 0 ou ABSENT (défaut PVE : pas de démarrage auto), None si
        la config est illisible. Pourquoi ça compte : tant qu'un guest
        est géré par le HA (ressource NON 'ignored'), onboot est SANS
        effet (seul l'état demandé à la ressource compte) ; mais dès
        que la ressource est détachée ('ignored'), le HA ne le gère
        plus et 'pve-guests' applique onboot au boot du nœud. Laisser
        sur place une VM stopped avec onboot=1 pendant un upgrade la
        ferait DÉMARRER au retour du nœud, puis ÉTEINDRE par le CRM à
        la réactivation de sa ressource dans l'état d'origine
        ('stopped' = état demandé, le CRM l'impose). Mémoïsé par
        (vmtype, vmid)."""
        key = (vmtype, vmid)
        if key in self._vm_onboot:
            return self._vm_onboot[key]
        res: Optional[bool] = None
        try:
            cfg = (self.with_api(
                       lambda p: p.nodes(node).lxc(vmid).config.get())
                   if vmtype == "lxc" else
                   self.with_api(
                       lambda p: p.nodes(node).qemu(vmid).config.get()))
            val = (cfg or {}).get("onboot", "0")
            res = str(val).strip() == "1"
        except Exception:
            res = None
        self._vm_onboot[key] = res
        return res

    def vm_set_onboot(self, node: str, vmid: int, vmtype: str,
                      value: bool) -> None:
        """Positionne l'option « onboot » (start at boot) d'un guest
        (garde-fou v20). Relecture AVANT écriture + PUT avec le DIGEST
        de la config lue : une modif concurrentine fait ÉCHOUER le PUT
        au lieu d'être écrasée silencieusement. Utilisé pour suspendre
        TEMPORAIREMENT l'auto-démarrage d'une VM stopped+onboot=1 dont
        les disques LOCAUX l'ancrent à son nœud (migration impossible :
        storage non partagé inexistant ailleurs — la laisser démar-
        rerait au boot du nœud au retour d'upgrade, puis une ressource
        HA 'stopped' l'éteindrait). La valeur d'origine est restaurée
        dans le finally du nœud ET tracée dans le fichier d'état
        (reprise après interruption)."""
        cfg = (self.with_api(
                   lambda p: p.nodes(node).lxc(vmid).config.get())
               if vmtype == "lxc" else
               self.with_api(
                   lambda p: p.nodes(node).qemu(vmid).config.get()))
        params: Dict[str, object] = {"onboot": 1 if value else 0}
        digest = (cfg or {}).get("digest")
        if digest:
            params["digest"] = digest
        if vmtype == "lxc":
            self.with_api(lambda p: p.nodes(node).lxc(vmid)
                          .config.put(**params))
        else:
            self.with_api(lambda p: p.nodes(node).qemu(vmid)
                          .config.put(**params))

    def migrate_vm(self, node: str, vmid: int, target: str, vmtype: str,
                   timeout: Optional[int] = None):
        """Migration d'un guest. QEMU : live migration (zéro downtime).
        LXC : PAS de live migration possible — on utilise le mode 'restart'
        (arrêt, transfert, redémarrage sur la cible : downtime de quelques
        secondes/minutes selon le stockage).
        timeout : timeout EFFECTIF d'attente de la tâche (live QEMU :
        adapté à la taille de la VM par _migrate_timeout_for ; sinon
        PVE_MIGRATE_TIMEOUT)."""
        if vmtype == "lxc":
            self.log.info(f"Migration du CT {vmid} : {node} ➔ {target} "
                          f"(mode restart : ARRET/REDÉMARRAGE, downtime court)")
            task = self.with_api(lambda p: p.nodes(node).lxc(vmid).migrate.post(
                target=target, restart=1))
            self._wait_task(node, task)
        else:
            t = timeout or MIGRATE_TIMEOUT
            self.log.info(f"Live migration de la VM {vmid} : {node} ➔ {target} "
                          f"(timeout {t}s)")
            kwargs = {"target": target, "online": 1}
            if WITH_LOCAL_DISKS:
                # disques locaux inclus dans la migration (storage non partagé)
                kwargs["with-local-disks"] = 1
            task = self.with_api(lambda p: p.nodes(node).qemu(vmid).migrate.post(**kwargs))
            self._wait_task(node, task, timeout=t)

    def _wait_task(self, node: str, upid: str,
                   timeout: Optional[int] = None):
        """Attend la fin d'une tâche Proxmox. timeout=None → MIGRATE_TIMEOUT
        lu AU MOMENT DE L'APPEL (le paramètre par défaut d'une fonction est
        évalué à l'import : une valeur PVE_MIGRATE_TIMEOUT posée dans le
        --env-file doit rester effective après la relecture de main())."""
        if timeout is None:
            timeout = MIGRATE_TIMEOUT
        t0 = time.time()
        last_beat = 0
        while time.time() - t0 < timeout:
            elapsed = int(time.time() - t0)
            if elapsed - last_beat >= 30:
                last_beat = elapsed
                self.log.info(f"  … tâche {upid} en cours sur {node} "
                              f"— {elapsed}s écoulées")
            try:
                st = self.with_api(lambda p: p.nodes(node).tasks(upid).status.get())
            except RuntimeError:
                time.sleep(5)
                continue
            if st.get("status") == "stopped":
                exitstatus = st.get("exitstatus")
                if exitstatus in ("OK", None):
                    return
                # PVE rend « WARNINGS: n » pour une tâche RÉUSSIE mais
                # NON SILENCIEUSE (ex. job de backup avec 1 avertis-
                # sement, migration avec remarque) : seul un exitstatus
                # « ERROR… » est un échec (règle Proxmox,
                # PVE::Tools::upid_status_is_error). Interrompre tout
                # le run pour un simple avertissement casait l'upgrade
                # en pleine évacuation pour rien — on LOGUE les
                # avertissements puis on continue normalement.
                if re.fullmatch(r"WARNINGS: \d+", str(exitstatus)):
                    self.log.warning(
                        f"  Tâche {upid} terminée avec {exitstatus} — "
                        f"considérée RÉUSSIE (règle Proxmox : seul "
                        f"« ERROR » est un échec). Détail :")
                    try:
                        rows = self.with_api(
                            lambda p: p.nodes(node).tasks(upid).log.get())
                        warns: List[str] = []
                        for row in (rows if isinstance(rows, list) else []):
                            line = (row.get("t", "")
                                    if isinstance(row, dict) else str(row))
                            if ("WARNING" in line.upper()
                                    and not line.strip().upper().startswith(
                                        "TASK WARNINGS")):
                                warns.append(line.strip())
                        for w in warns[:3]:
                            self.log.warning(f"    ⚠ {w}")
                        if len(warns) > 3:
                            self.log.warning(
                                f"    … +{len(warns) - 3} autres "
                                f"avertissements (log complet : "
                                f"pvesh get /nodes/{node}/tasks/"
                                f"{upid}/log)")
                    except Exception as e:
                        self.log.debug(f"    (log de tâche illisible : {e})")
                    return
                raise RuntimeError(f"Tâche {upid} échouée : {exitstatus}")
            time.sleep(5)
        # Timeout : l'attente est purement CLIENTE — la tâche peut TOUJOURS
        # tourner côté Proxmox. Pour une live migration, la laisser finir
        # en pleine remise en état HA est une course dangereuse (le CRM
        # reprend la main sur une VM en cours de déplacement). On ANNULE
        # donc proprement la tâche côté Proxmox : une qmigrate annulée
        # laisse la VM SUR SON NŒUD SOURCE, sans perte ni interruption —
        # état cohérent pour la sortie de maintenance et le CRM. L'annula-
        # tion est BEST-EFFORT (tâche déjà finie, API injoignable…) : elle
        # ne masque JAMAIS le timeout d'origine.
        try:
            self.with_api(lambda p: p.nodes(node).tasks(upid).cancel.post())
            self.log.warning(f"  … tâche {upid} : annulation demandée côté "
                             f"Proxmox après timeout — la VM (le cas échéant) "
                             f"reste sur son nœud source, sans interruption")
        except Exception:
            self.log.warning(f"  … tâche {upid} : annulation impossible "
                             f"(déjà terminée ou API injoignable) — VÉRIFIER "
                             f"son issue côté Proxmox avant tout relancement")
        raise RuntimeError(
            f"Timeout ({timeout}s) sur la tâche {upid}")

    def apt_update(self, node: str):
        self.log.info(f"{node}: apt update (rafraîchissement des listes)…")
        # AUTO-RÉPARATION : un apt interrompu (kill, Ctrl-C, coupure)
        # laisse dpkg en « half-configured » — apt refuserait ensuite de
        # démarrer (« E: dpkg was interrupted, you must manually run
        # 'dpkg --configure -a' »). On détecte l'état avec « dpkg
        # --audit » et on TERMINE la configuration AVANT toute
        # simulation/upgrade. Les verrous dpkg sont libérés à la mort
        # des processus : rien à débloquer ici.
        try:
            audit = self._ssh(node, "dpkg --audit 2>/dev/null")
            if audit.strip():
                self.log.warning(
                    f"{node}: dpkg INCOMPLET détecté (apt d'un run "
                    f"précédent interrompu ?) — fin de la configuration "
                    f"en cours (dpkg --configure -a)…")
                self._ssh(node,
                          "DEBIAN_FRONTEND=noninteractive "
                          "dpkg --configure -a", stream=True)
        except Exception as e:
            self.log.warning(f"{node}: audit dpkg impossible ({e}) — "
                             f"poursuite.")
        self._ssh(node, "apt-get update -q")

    def apt_upgrade_pending(self, node: str) -> Tuple[int, bool, int, int, bool]:
        """Évalue (sans rien installer) les mises à jour en attente :
        - simulation apt-get (mode -s, aucune action),
        - retour : (nb de paquets à mettre à jour, noyau concerné ?,
                    octets à télécharger, octets d'espace disque
                    supplémentaire requis (négatif si libéré),
                    paquet PVE concerné ? (pve-*/proxmox-*)).
        Le noyau dans la liste => reboot attendu après le full-upgrade.
        Un paquet pve-*/proxmox-* dans la liste => changement de version
        PVE (pve-manager, pve-qemu-kvm, proxmox-kernel…) : significatif
        pour --skip-minor-updates, qui n'ignore JAMAIS ces nœuds."""
        out = self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                              "apt-get -s full-upgrade -q")
        m = re.search(r"(\d+) upgraded", out)
        n = int(m.group(1)) if m else 0
        kernel = bool(re.search(r"^Inst (proxmox-kernel|linux-image)",
                                out, re.M))
        pve_up = bool(re.search(r"^Inst (pve-|proxmox-)", out, re.M))

        def _to_bytes(val: str, unit: str) -> int:
            mul = {"B": 1, "kB": 10**3, "MB": 10**6, "GB": 10**9}.get(unit, 1)
            try:
                return int(float(val.replace(",", "")) * mul)
            except ValueError:
                return 0
        dl = 0
        m = re.search(r"Need to get ([\d.,]+) ?(B|kB|MB|GB) ", out)
        if m:
            dl = _to_bytes(m.group(1), m.group(2))
        inst = 0
        # "After this operation, X MB of additional disk space will be
        # used" (positif) ou "... X MB of disk space will be freed"
        # (négatif : apt libère de la place).
        m = re.search(r"After this operation, ([\d.,]+) ?(B|kB|MB|GB) "
                      r"of (?:additional disk space will be used"
                      r"|disk space will be freed)", out)
        if m:
            inst = _to_bytes(m.group(1), m.group(2))
            if "freed" in out[m.start():m.end()]:
                inst = -inst
        return n, kernel, dl, inst, pve_up

    def disk_free(self, node: str) -> Dict[str, Tuple[int, int]]:
        """Diagnostic espace disque : {montage: (octets libres, octets
        total)} pour /, /var et /boot/efi. Un montage absent est ignoré
        (ex. /boot/efi en BIOS, /var non séparé de /). NB : quand /var
        est sur le même système de fichiers que /, df renvoie les mêmes
        chiffres pour les deux montages. Lecture pure : dry-run OK."""
        out = self._ssh(node, "df -B1 / /var /boot/efi 2>/dev/null || true")
        res: Dict[str, Tuple[int, int]] = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[5].startswith("Mounted"):
                continue
            try:
                total, avail = int(parts[1]), int(parts[3])
            except ValueError:
                continue
            res[parts[5]] = (avail, total)
        return res

    def apt_upgrade(self, node: str):
        self.log.info(f"{node}: apt full-upgrade (streaming)…")
        self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                       "NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 "
                       "apt-get full-upgrade -y -q "
                       "-o DPkg::Lock::Timeout=600 "
                       "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confnew",
                  stream=True)

    def reboot_required(self, node: str) -> bool:
        """Vrai si /var/run/reboot-required existe OU si le noyau courant
        diffère du dernier installé."""
        try:
            self._ssh(node, "test -e /var/run/reboot-required")
            return True
        except RuntimeError:
            pass
        out = self._ssh(node, "uname -r")
        cur = out.strip()
        latest = self._ssh(node,
                           "ls /boot/vmlinuz-* | sed 's|/boot/vmlinuz-||' | sort -V | tail -1").strip()
        self.log.info(f"{node}: noyau courant={cur}, dernier installé={latest}")
        return cur != latest

    def reboot_node(self, node: str):
        # Basculer l'hôte API AVANT le reboot si c'est le nœud concerné
        self._ensure_api_host_not(node)
        # UPTIME DE RÉFÉRENCE capturé AVANT la commande reboot : la preuve
        # du reboot effectif sera une DIMINUTION stricte de l'uptime. Un
        # simple « uptime < seuil » ne suffit pas : un nœud fraîchement
        # booté (cluster rebooté peu avant le run) a déjà un petit uptime
        # et serait déclaré « de retour » avant même de redescendre.
        try:
            st = self.with_api(lambda p: p.nodes(node).status.get(), quiet=True)
            self._reboot_baseline[node] = int(st.get("uptime", 0))
        except Exception:
            self._reboot_baseline[node] = None
        self.log.info(f"{node}: redémarrage demandé")
        self.with_api(lambda p: p.nodes(node).status.post(command="reboot"))

    def wait_node_back(self, node: str, timeout: int = REBOOT_TIMEOUT):
        """Attend le RETOUR RÉEL du nœud après reboot. La preuve d'un reboot
        effectif est une DIMINUTION STRICTE de l'uptime par rapport à la
        valeur de référence capturée juste avant la commande reboot :
        - juste après la commande reboot, l'API répond encore 10-30s
          (arrêt en cours) et l'uptime CONTINUE de croître ;
        - après le reboot, l'uptime repart de ~0 : up < référence prouve
          le reboot, même si le nœud avait déjà un petit uptime avant
          (cas d'un cluster rebooté peu avant le run)."""
        self.log.info(f"{node}: attente du retour après reboot "
                      f"(uptime réinitialisé, max {timeout}s)…")
        # L'hôte API est déjà un AUTRE nœud (basculé avant le reboot) :
        # le poll continue donc pendant tout le reboot du nœud.
        self._ensure_api_host_not(node)
        t0 = time.time()
        baseline = self._reboot_baseline.get(node)
        saw_down = False                       # preuve de la descente
        # l'échec des polls est le résultat ATTENDU pendant le reboot :
        # mode quiet (pas de carrousel bruyant), et si l'hôte API courant
        # tombe aussi, la bascule saute le nœud en reboot.
        node_ip = self.node_addr.get(node, node)
        last_beat = 0
        while time.time() - t0 < timeout:
            elapsed = int(time.time() - t0)
            if elapsed - last_beat >= 30:
                last_beat = elapsed
                self.log.info(f"  … {node} redémarre — {elapsed}s écoulées "
                              f"(max {timeout}s)")
            try:
                st = self.with_api(lambda p: p.nodes(node).status.get(),
                                   quiet=True)
                up = int(st.get("uptime", 0))
                if baseline is not None:
                    # preuve forte : l'uptime a redémarré depuis le boot
                    if up < baseline:
                        self.log.info(
                            f"{node} est de retour en ligne ✔ "
                            f"(uptime {up}s < {baseline}s avant reboot)")
                        self._wait_systemd_settled(node)
                        return
                elif saw_down and up < FRESH_BOOT_UPTIME:
                    # pas de référence : accepter seulement si le nœud a
                    # été vu INJOIGNABLE puis revenu avec un boot frais
                    self.log.info(f"{node} est de retour en ligne ✔ "
                                  f"(uptime {up}s = boot frais)")
                    self._wait_systemd_settled(node)
                    return
            except Exception as e:
                # le nœud ne répond plus : c'est le reboot en cours —
                # c'est AUSSI la preuve de la descente (sans référence).
                saw_down = True
                if "proxy handshake" not in str(e):
                    self._rotate_api_host(avoid=node_ip)
            time.sleep(REBOOT_CHECK_INTERVAL)
        raise RuntimeError(f"{node} n'est pas revenu (uptime réinitialisé) "
                          f"en {timeout}s")

    @staticmethod
    def _since(seconds: int) -> str:
        """Paramètre 'since' des endpoints syslog : l'API PVE (schéma PVE 9)
        exige une CHAÎNE date-heure locale « AAAA-MM-JJ HH:MM[:SS] »
        (regex ^\\d{4}-\\d{2}-\\d{2}( \\d{2}:\\d{2}(:\\d{2})?)?$) — PAS un
        timestamp Unix : un entier comme un float est refusé avec
        « value does not match the regex pattern ». La comparaison se
        fait contre les timestamps des lignes de syslog (heure locale
        du nœud) : on formate donc en heure locale de la machine qui
        exécute le script."""
        dt = datetime.now() - timedelta(seconds=seconds)
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def _wait_systemd_settled(self, node: str, timeout: int = 180):
        """Attend que systemd sorte de sa phase de démarrage (« starting »)
        vers un état stable : « running » (parfait) ou « degraded » (des
        units ont échoué — post_boot_checks les détaillera ensuite).
        NB : « systemctl is-system-running » sort avec un code != 0 pour
        tout état autre que running : le « || true » évite que _ssh prenne
        ça pour une erreur de commande."""
        t0 = time.time()
        last_beat = 0
        while time.time() - t0 < timeout:
            elapsed = int(time.time() - t0)
            if elapsed - last_beat >= 30:
                last_beat = elapsed
                self.log.info(f"  … {node}: systemd settling — "
                              f"{elapsed}s écoulées")
            try:
                state = self._ssh(
                    node, "systemctl is-system-running || true").strip()
            except Exception:
                state = ""          # SSH pas encore prêt : on poll
            if state in ("running", "degraded"):
                self.log.info(f"{node}: systemd '{state}' — "
                              f"démarrage des services terminé")
                return state
            time.sleep(10)
        self.log.warning(f"{node}: systemd toujours en phase de démarrage "
                          f"après {timeout}s — on continue quand même.")
        return "timeout"

    def post_boot_checks(self, node: str) -> bool:
        """2f : quorum, services défaillants, erreurs syslog récentes."""
        ok = True
        quorum = self.with_api(lambda p: p.cluster.status.get())
        quorate = any(q.get("quorate") == 1 for q in quorum if q.get("type") == "cluster")
        self.log.info(f"  Quorum cluster : {'OK' if quorate else 'PERDU !'}")
        ok &= quorate
        # Les unités en échec au tout début du boot sont souvent
        # TRANSITOIRES (mounts qui finissent de partir quelques dizaines
        # de secondes après l'API) : on réessaie avant de conclure.
        failed: List[str] = []
        for attempt in range(4):
            out = self._ssh(node, "systemctl --failed --no-legend | head -5")
            failed = [l for l in out.splitlines() if l.strip()]
            if not failed:
                break
            if attempt < 3:
                self.log.info(f"  Services en échec ({len(failed)}) — probablement "
                              f"transitoire, nouvel essai dans 30s…")
                time.sleep(30)
        self.log.info(f"  Services en échec : {len(failed)}")
        if failed:
            for l in failed:
                self.log.warning(f"    {l.strip()}")
        # 2f-bis : Ceph doit être revenu à HEALTH_OK après le reboot
        # (mons en quorum, OSDs up). Sans ça, un moniteur Ceph qui ne
        # remonte PAS après le reboot passe inaperçu : « Quorum cluster :
        # OK » parle de COROSYNC (quorum PVE), pas du quorum Ceph, et
        # systemd peut être 'running' pendant que ceph-mon crashe en
        # boucle. Vécu : 1/3 mons down après un reboot de nœud, le run
        # a continué et seule la gate du run suivant l'a signalé.
        try:
            st = self.ceph_status()
        except Exception:
            st = None
        if st is not None:
            allow_warn = str(_env("PVE_CEPH_ALLOW_WARN", "0")) == "1"
            # Attente de convergence Ceph : sur un cluster important, la
            # récupération des PGs après un reboot peut prendre des
            # HEURES — exiger HEALTH_OK comme gate dure est trop strict
            # à cette échelle. On distingue donc « CASSÉ » (mon ou OSD
            # réellement down → échec net) de « EN CONVERGENCE »
            # (structure saine : mons en quorum, tous les OSDs up, et
            # seules des PGs en récupération AVEC un nombre d'objets
            # dégradés en baisse depuis le début de l'attente → toléré,
            # la convergence continue en arrière-plan). Le délai
            # d'attente est configurable via PVE_CEPH_POSTBOOT_TIMEOUT
            # (secondes, défaut 300).
            # 2f-bis-0 : le mon Ceph de ce nœud doit être ACTIF —
            # certains ne remontent pas seuls au boot (ordre systemd),
            # la 2f-bis échouerait sinon alors qu'un simple restart
            # suffit. Journal loggé pour le diagnostic durable.
            self.ceph_mon_ensure(node)
            timeout = int(_env("PVE_CEPH_POSTBOOT_TIMEOUT", "300") or 300)
            t0 = time.time()
            diag_done = False       # diagnostic détaillé affiché UNE fois
            health, ignored = self.ceph_effective_health(st)
            if ignored:
                self.ceph_log_auth_insecure(ignored)

            def _vitals(s: dict):
                """(quorum, mons, osds_up, osds_in, osds_total,
                objets_dégradés) lus bruts du status Ceph. NB : le
                status PVE peut omettre num_mons (fallback : longueur
                de monmap.mons) et pgmap.degraded_objects (fallback :
                parse du résumé PG_DEGRADED « X/Y objects degraded ») —
                sans ça, MON_DOWN s'affichait « quorum 2/2 » et le
                verdict « cassé » de la 2f-bis était faussé."""
                monmap = s.get("monmap") or {}
                nq = len(s.get("quorum") or [])
                mons = monmap.get("mons") or []
                nmon = len(mons) or monmap.get("num_mons") or nq
                osdm = s.get("osdmap") or {}
                pgm = s.get("pgmap") or {}
                deg = pgm.get("degraded_objects")
                if deg is None:
                    # PVE 9.x : le « summary » d'un check Ceph du status
                    # est un OBJET {"message": "...", "severity": ...},
                    # PAS une chaîne — cf. _check_summary_text. Crash v13
                    # du 18/11 (nœud c01) : status de fin de recovery où
                    # pgmap.degraded_objects est ABSENT du payload alors
                    # que le check PG_DEGRADED est encore présent → le
                    # dict entier partait dans re.search. On normalise
                    # AVANT le parse, qu'importe la représentation.
                    raw = _check_summary_text(
                        ((s.get("health") or {}).get("checks")
                         or {}).get("PG_DEGRADED", {}).get("summary", ""))
                    m = re.search(r"(\d+)/\d+ objects degraded", raw)
                    if m:
                        deg = int(m.group(1))
                return (nq, nmon, osdm.get("num_up_osds"),
                        osdm.get("num_in_osds"), osdm.get("num_osds"),
                        deg)

            first_degraded = _vitals(st)[5]
            skew_attempted = False   # remédiation MON_CLOCK_SKEW tentée UNE fois
            while health != "HEALTH_OK" and time.time() - t0 < timeout:
                if not diag_done:
                    self.ceph_diagnose(st)
                    diag_done = True
                if health == "HEALTH_WARN" and allow_warn:
                    self.log.warning("  Ceph HEALTH_WARN après reboot — "
                                     "toléré (PVE_CEPH_ALLOW_WARN=1)")
                    break
                # MON_CLOCK_SKEW post-reboot : le mon de CE nœud mesure
                # une horloge encore décalée (RTC au boot, chrony pas
                # resynchronisé) — remédiation AUTOMATIQUE (restart
                # chrony / makestep sur le nœud signalé, puis restart du
                # mon en DERNIER RECOURS si majorité stricte) au lieu
                # d'attendre le timeout pour un warning d'horloge.
                if "MON_CLOCK_SKEW" in ((st.get("health") or {})
                                        .get("checks") or {}) \
                        and not skew_attempted:
                    skew_attempted = True
                    if self.ceph_clock_skew_fix(st, "après reboot"):
                        st = self.ceph_status() or {}
                        health, ignored = self.ceph_effective_health(st)
                        continue
                nq, nmon, up, n_in, tot, deg = _vitals(st)
                self.log.info(
                    f"  Ceph {health} après reboot — attente du retour à "
                    f"HEALTH_OK (recheck 15s, timeout {timeout}s)… "
                    f"[mons quorum {nq}/{nmon if nmon else '?'}, "
                    f"OSDs up/in {up if up is not None else '?'}/"
                    f"{n_in if n_in is not None else '?'}"
                    f"{'/' + str(tot) if tot is not None else ''}, "
                    f"dégradés {deg if deg is not None else '?'}]")
                time.sleep(15)
                try:
                    st = self.ceph_status() or {}
                except Exception:
                    st = {}
                health, ignored = self.ceph_effective_health(st)
            if health == "HEALTH_OK":
                self.log.info("  Ceph HEALTH_OK — mons en quorum, "
                              "OSDs remontés ✔")
            elif not (health == "HEALTH_WARN" and allow_warn):
                nq, nmon, up, n_in, tot, deg = _vitals(st)
                codes = set(((st.get("health") or {}).get("checks")
                             or {}).keys()) - set(ignored)
                # « cassé » : un mon OU un OSD est réellement down —
                # c'est la situation dangereuse (un mon down de plus =
                # perte de quorum Ceph au prochain reboot).
                broken = bool(nmon and nq < nmon) \
                    or bool(tot and n_in is not None
                            and up is not None and up < n_in)
                # « en convergence » : structure saine + uniquement des
                # PGs en récupération + moins d'objets dégradés qu'au
                # début de l'attente. PG_DEGRADED est le code standard
                # de « recovery en cours » (active+recovering+degraded).
                converging = (not broken
                              and codes <= {"PG_DEGRADED"}
                              and deg is not None and first_degraded is not None
                              and deg < first_degraded)
                if converging:
                    self.log.warning(
                        f"  Ceph toujours en {health} après {timeout}s, "
                        f"mais en CONVERGENCE (mons en quorum {nq}/{nmon}, "
                        f"tous les OSDs up, objets dégradés "
                        f"{first_degraded} → {deg}, en baisse) — "
                        f"récupération tolérée, elle continue en "
                        f"arrière-plan pendant le reste du run.")
                elif codes == {"MON_CLOCK_SKEW"}:
                    # verdict dédié : le message générique « mon/OSD
                    # probablement tombé » serait FAUX ici (quorum et
                    # OSDs sont sains, seule l'horloge est en cause).
                    self.ceph_diagnose(st)
                    self.log.error(
                        f"  Ceph toujours en MON_CLOCK_SKEW après le "
                        f"reboot malgré la remédiation (restart chrony / "
                        f"makestep, puis restart du mon en dernier "
                        f"recours si majorité stricte) — l'horloge de "
                        f"{node} ne se resynchronise pas : vérifiez "
                        f"« chronyc sources » (NTP joignable ?), le "
                        f"pare-feu UDP/123, puis relancez le run.")
                else:
                    self.ceph_diagnose(st)
                    self.log.error(
                        f"  Ceph toujours en {health} {timeout}s après le "
                        f"reboot (mons quorum {nq}/{nmon}, OSDs up/in "
                        f"{up}/{n_in}) — mon/OSD probablement tombé : "
                        f"corrigez AVANT de traiter le nœud suivant (un "
                        f"mon down + un reboot de plus = perte de quorum "
                        f"Ceph).")
                    ok = False
                ok = False
        # erreurs récentes dans syslog. NB : selon la version PVE / les
        # paramètres, l'endpoint renvoie soit une chaîne brute, soit une
        # liste de lignes, soit une liste de dicts {n: n° de ligne,
        # t: texte} (PVE 9). On normalise en texte (champ 't' si dict).
        syslog = self.with_api(lambda p: p.nodes(node).syslog.get(
            since=self._since(120))) or ""
        if isinstance(syslog, str):
            lines = syslog.splitlines()
        else:
            lines = [x.get("t", "") if isinstance(x, dict) else str(x)
                     for x in syslog]
        # bruit bénin à ignorer : les sessions SSH tuées par le reboot
        # laissent des « syslogin_perform_logout: logout() returned an
        # error » — sans conséquence, fréquent, pas une vraie erreur.
        # Idem pour les « Read error from remote host / Connection reset
        # by peer » de sshd : c'est NOTRE propre session SSH coupée
        # par le reboot du nœud.
        benign = re.compile(
            r"syslogin_perform_logout|Duplicate line for path "
            r"\"/run/lock\"|usermod: unlocking the user's password"
            r"|sshd[^:]*: Read error from remote host"
            r"|sshd[^:]*: Connection reset by peer",
            re.I)
        errors = [l for l in lines
                  if re.search(r"error|critical|fail(ed|ure)?", l, re.I)
                  and not benign.search(l)]
        for l in errors[:10]:
            self.log.warning(f"  syslog: {l.strip()}")
        ok &= len(failed) == 0
        return ok

    def ha_status(self) -> List[str]:
        """État HA courant, traduit en lignes lisibles.
        GET /cluster/ha/status/current renvoie une liste de dicts aux types :
        quorum, master, fencing, lrm, service."""
        items = self.with_api(lambda p: p.cluster.ha.status.current.get())
        lines: List[str] = []
        for i in items:
            t = i.get("type")
            if t == "quorum":
                ok = i.get("quorate") == 1
                lines.append(f"Quorum cluster      : "
                             f"{'OK — cluster opérable' if ok else 'PERDU — CLUSTER INOPÉRABLE !'}")
            elif t == "master":
                lines.append(f"Maître CRM           : {i.get('node')}")
            elif t == "fencing":
                lines.append(f"Fencing              : {i.get('status')} (nœud {i.get('node')})")
            elif t == "lrm":
                lines.append(f"Gestionnaire local   : {i.get('status')}")
                if "maintenance" in str(i.get("status", "")):
                    lines.append(
                        f"  ⚠ {i.get('node')} est TOUJOURS en mode maintenance "
                        f"(run précédent interrompu ?). Corriger avant de "
                        f"poursuivre : ha-manager crm-command "
                        f"node-maintenance disable")
            elif t == "service":
                lines.append(f"Ressource HA         : {i.get('status')}")
            else:
                lines.append(f"{t or '?'}                  : {i}")
        return lines

    def check_fencing(self, nodes_to_watch: List[str], logger: logging.Logger) -> List[str]:
        """Scrute les syslogs des AUTRES nœuds à la recherche d'actions
        de fencing. Retourne les lignes suspectes."""
        hits: List[str] = []
        for n in nodes_to_watch:
            try:
                syslog = self.with_api(lambda p: p.nodes(n).syslog.get(since=self._since(60))) or ""
                if isinstance(syslog, str):
                    lines = syslog.splitlines()
                else:
                    lines = [x.get("t", "") if isinstance(x, dict) else str(x)
                             for x in syslog]
                for line in lines:
                    if any(re.search(p, line, re.I) for p in FENCING_PATTERNS):
                        hits.append(f"[{n}] {line.strip()}")
            except Exception as e:
                logger.debug(f"syslog {n} illisible : {e}")
        return hits


# ---------------------------------------------------------------------------
# ORCHESTRATEUR — partagé entre mode réel et dry-run
# ---------------------------------------------------------------------------
class Updater:
    def __init__(self, logger: logging.Logger, dry_run: bool,
                 client: Optional[ProxmoxClient] = None):
        self.log = logger
        self.dry = dry_run
        self.client = client
        # Dry-run = RIEN n'est exécuté sur les nœuds : la remédiation
        # MON_CLOCK_SKEW (restart chrony / makestep / restart mon)
        # doit donc être désactivée côté client (elle se borne alors
        # à expliquer ce que le run réel ferait).
        if client is not None:
            client.can_remediate = not dry_run
        self.maintenance_nodes: List[str] = []   # pour le bloc finally
        self.touched = False   # le run a-t-il MODIFIÉ le cluster ?
        self.evacuated: Dict[str, List[Dict]] = {}   # nœud -> plans d'évacuation
        self.state: Optional[ClusterState] = None
        # sid -> état HA d'origine {"state","comment"} des ressources
        # détachées en 'ignored' : à restaurer en TOUT ÉTAT DE CAUSE.
        self.ha_snapshot: Dict[str, Dict] = {}
        # rid -> règle 'node-affinity' mise « en sommeil » par ce run
        # (disable, OU ressources vidées, OU suppression temporaire
        # selon le schéma de l'API PVE — cf. _ha_rule_disable), pour
        # libérer le placement pendant TOUTE l'Étape 1 — les règles
        # actives « pollueraient » le comportement du CRM et le
        # planning du script pendant les migrations pilotées :
        #   {"rule": <définition ORIGINALE complète de la règle>,
        #    "was_disabled": False, "mode": "disable|resources|delete"}
        # Réactivées à la FIN de l'Étape 1 (disable remis à son état
        # d'origine, ou définition restaurée par fusion/recréation),
        # rapatriement/rééquilibrage — une seule fois par run, pas à
        # chaque sortie de maintenance de nœud (sinon le CRM re-décide
        # des relocate à chaque nœud : churn). En mode --node, la fin de
        # l'Étape 1 EST la sortie de maintenance du nœud. Persistées
        # dans le fichier d'état ("ha_rules") pour la reprise après
        # interruption, avec le MODE de mise en sommeil utilisé
        # (disable / ressources vidées / suppression — cf.
        # _ha_rule_disable). NB : les règles déjà désactivées par un
        # admin ne sont PAS touchées (pas de snapshot, pas de PUT).
        self.ha_rules_snapshot: Dict[str, Dict] = {}
        # mode de mise en sommeil qui a fonctionné sur l'API de CE
        # cluster (déterminé à la première règle du run) : les règles
        # suivantes vont directement au bon mode, sans réessayer les
        # modes que le schéma de l'API refuse.
        self._ha_rule_mode_hint: Optional[str] = None
        # (ha_affinity, ha_affinity_hard) d'ORIGINE : sauvegarde au moment
        # de la désactivation des règles (ces deux structures ne sont
        # alimentées QUE par les règles node-affinity), rendue à la
        # réactivation — le rééquilibrage final et le rapatriement des
        # hors-règle redeviennent contraints par les règles, comme le
        # CRM. En mémoire uniquement : après une interruption, le run
        # suivant reconstruit tout via fetch_state.
        self._affinity_backup: Optional[Tuple[Dict[int, Set[str]],
                                              Dict[int, Set[str]]]] = None
        # Flags Ceph de maintenance posés PAR LE RUN (reboot planifié) :
        # {flag: True} — à retirer en fin de fenêtre, en TOUT ÉTAT DE
        # CAUSE (persistés dans le fichier d'état pour le run suivant).
        self.ceph_flags: Dict[str, bool] = {}
        # vmid des ressources HA repliées HORS règle (strict=0) pendant
        # ce run : leur réactivation HA est DIFFÉRÉE à la fin du run
        # (le CRM les re-migrerait immédiatement vers leurs nœuds
        # préférés, en pleine évacuation des nœuds suivants).
        self.off_rule_vmids: Set[int] = set()
        self.only_node: bool = False
        # --skip-minor-updates (v19) : ignorer les nœuds dont les
        # seules MAJ en attente sont des paquets Debian mineurs
        # (aucun noyau, aucun paquet pve-*/proxmox-*, aucun reboot
        # en attente) — ni évacuation ni upgrade ni reboot pour eux.
        self.skip_minor: bool = False
        self.minor_skipped: List[str] = []
        # Garde-fou onboot v20 : guests stopped+onboot=1 ancrés à leur
        # nœud par des disques LOCAUX — laissés sur place avec onboot
        # temporairement suspendu (restauré au finally du nœud et
        # TRACÉ dans le fichier d'état : la reprise après crash le
        # refera). Clé « vmtype:vmid ».
        self.onboot_suspended: Dict[str, Dict] = {}
        self._off_rule_deferred_logged: Set[str] = set()
        # vmid des ressources HA repliées hors règle puis RAPATRIÉES sur
        # un nœud de leur règle pendant le rééquilibrage final (gel CRM) :
        # pour le rapport final — dégel cohérent, CRM sans correction.
        self.off_rule_returned: Set[int] = set()
        # Échantillons de durées RÉELLES mesurés pendant CE run (mode
        # --execute uniquement) : alimentés par les timers de
        # l'apt/reboot/migrations, fusionnés dans .proxmox-rolling-
        # update.stats par save_stats() dans le finally de run() —
        # même un run partiel (erreur en cours de route) contribue.
        self.stats_new: Dict[str, list] = {"apt_update_s": [],
                                          "apt_upgrade_s": [],
                                          "reboot_s": [],
                                          "migrate": []}
        # ---- BILAN DRY-RUN : horloge simulée + journal des migrations —
        # durée approximative du run, volume transféré, fenêtres de
        # cohabitation des anti-affinités « keep separate » (évaluation
        # des risques avant l'exécution réelle). ----
        self.est_clock: float = 0.0       # temps simulé écoulé (secondes)
        self.est_mig_time: float = 0.0    # temps passé dans les migrations
        self.est_node_time: float = 0.0   # temps passé en apt/upgrade/reboot
        self.est_crm_time: float = 0.0     # fenêtres de stabilité CRM
        self.est_maint_nodes: int = 0      # nœuds avec maintenance complète
        self.mig_events: List[Dict] = []   # migrations chronologiques
        self.initial_place: Dict[int, str] = {}   # vmid -> nœud au départ
        # guests migrés ayant au moins un disque sur stockage NON partagé
        # (« LOCAL ») : leur migration copie les disques (with-local-disks),
        # non modélisé dans l'estimation → NB dédié en fin de bilan (la
        # liste n'est remplie qu'en dry-run ; "?" = stockage illisible).
        self.est_local_migs: List[str] = []    # "vmid (name)" sur LOCAL
        self.est_local_unknown: List[str] = [] # stockage indéterminé

    # ---------- fichier d'état (reprise après plantage) ----------
    def _state_file(self) -> str:
        """Chemin du fichier d'état du run (PVE_STATE_FILE, sinon à côté
        du fichier de log, sinon /tmp). Il contient l'« état zéro » à
        restaurer : ressources HA détachées + nœuds en maintenance."""
        p = _env("PVE_STATE_FILE", "").strip()
        if p:
            return p
        logf = _env("PVE_LOG_FILE", "").strip()
        base = os.path.dirname(os.path.abspath(logf)) if logf else "/tmp"
        return os.path.join(base, "proxmox-rolling-update.state.json")

    def _state_write(self) -> None:
        """Persiste l'état à restaurer. Appelé à CHAQUE transition (détach,
        réactivation) : si le script est tué, le fichier reflète le
        dernier état connu.
        En dry-run, SEULES les règles node-affinity sont réellement
        modifiées (mise en sommeil, cf. 2b-bis) : on ne persiste qu'elles,
        en FUSION avec un éventuel fichier d'un run --execute
        interrompu (ressources 'ignored', nœuds en maintenance…) que le
        dry-run ne doit JAMAIS écraser."""
        path = self._state_file()
        try:
            if self.dry:
                old: Dict[str, object] = {}
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8") as fh:
                            old = json.load(fh)
                    except Exception:
                        old = {}
                merged = dict(old.get("ha_rules") or {})
                merged.update(self.ha_rules_snapshot)
                data = {"updated": datetime.now().isoformat(
                            timespec="seconds"),
                        "maintenance": old.get("maintenance") or [],
                        "ha_ignored": old.get("ha_ignored") or {},
                        "ha_rules": merged,
                        "ceph_flags": old.get("ceph_flags") or {},
                        "onboot_suspended": old.get("onboot_suspended") or {}}
            else:
                data = {"updated": datetime.now().isoformat(timespec="seconds"),
                        "maintenance": self.maintenance_nodes,
                        "ha_ignored": self.ha_snapshot,
                        "ha_rules": self.ha_rules_snapshot,
                        "ceph_flags": self.ceph_flags,
                        "onboot_suspended": self.onboot_suspended}
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
        except Exception as e:
            self.log.warning(f"Fichier d'état non écrit ({e}) — "
                             f"la reprise après plantage sera dégradée.")

    def _state_rules_drop(self, rids) -> None:
        """Dry-run uniquement : retire du fichier d'état les règles
        node-affinity qui viennent d'être RÉELLEMENT réactivées (fin
        d'Étape 1 ou reprise au démarrage) ; supprime le fichier s'il
        ne reste plus rien à récupérer. Les éventuelles sections d'un
        run --execute interrompu (ressources 'ignored', maintenance,
        flags Ceph) sont PRÉSERVÉES telles quelles."""
        path = self._state_file()
        try:
            if not os.path.exists(path):
                return
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            self.log.warning(f"Fichier d'état non relu ({e}) — les règles "
                             f"restaurées y restent tracées (inoffensif).")
            return
        rules = dict(data.get("ha_rules") or {})
        for rid in rids:
            rules.pop(rid, None)
        if (not rules
                and not data.get("ha_ignored")
                and not data.get("maintenance")
                and not data.get("ceph_flags")
                and not data.get("onboot_suspended")):
            self._state_clear()
            return
        data["ha_rules"] = rules
        data["updated"] = datetime.now().isoformat(timespec="seconds")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
        except Exception as e:
            self.log.warning(f"Fichier d'état non écrit ({e}) — "
                             f"la reprise après plantage sera dégradée.")

    def _state_clear(self) -> None:
        """Run terminé avec succès : l'état zéro est restauré, le fichier
        n'a plus de raison d'être."""
        try:
            os.remove(self._state_file())
        except FileNotFoundError:
            pass
        except Exception as e:
            self.log.warning(f"Fichier d'état non supprimé ({e}).")

    def _recover_interrupted_run(self) -> None:
        """Étape 0 : un fichier d'état présent = un run --execute
        précédent s'est arrêté avant d'avoir tout restauré (plantage,
        kill, coupure). On connaît l'état zéro (ressources HA en
        'ignored' à réactiver, nœuds en maintenance à libérer).
        En dry-run : simple rapport. En réel : remise à l'état zéro."""
        path = self._state_file()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as e:
            self.log.error(f"Fichier d'état '{path}' illisible ({e}) — "
                           f"vérifiez MANUELLEMENT 'ha-manager config' et "
                           f"'ha-manager status' avant de relancer.")
            raise RuntimeError("Fichier d'état d'un run interrompu corrompu.")
        res = data.get("ha_ignored", {})
        maint = data.get("maintenance", [])
        flags = data.get("ceph_flags", {})
        rules = data.get("ha_rules", {})
        onbs = data.get("onboot_suspended", {})
        if not res and not maint and not flags and not rules and not onbs:
            # Fichier résiduel SANS rien à récupérer : run interrompu
            # (ex. Ctrl-C) APRÈS restauration complète de l'état zéro —
            # typiquement pendant la fenêtre de stabilité CRM de fin.
            # Pas de bannière d'alerte pour un non-événement : simple
            # information + nettoyage du fichier.
            self.log.info(
                "Fichier d'état résiduel d'un run interrompu (dernière "
                f"mise à jour : {data.get('updated', '?')}) — RIEN à "
                "récupérer, l'état zéro avait déjà été restauré. "
                "Fichier nettoyé.")
            self._state_clear()
            return
        banner(self.log, "RÉCUPÉRATION D'UN RUN PRÉCÉDEMMENT INTERROMPU",
               ColorFormatter.YELLOW)
        self.log.warning(f"Un run antérieur (dernière mise à jour : "
                         f"{data.get('updated', '?')}) n'a pas terminé "
                         f"proprement.")
        if res:
            self.log.info(f"Ressources HA laissées en 'ignored' "
                          f"({len(res)}) : {', '.join(sorted(res))}")
        if maint:
            self.log.info(f"Nœuds laissés en maintenance : "
                          f"{', '.join(maint)}")
        if flags:
            self.log.info(f"Flags Ceph de maintenance laissés posés "
                          f"(run interrompu pendant un reboot) : "
                          f"{', '.join(sorted(flags))}")
        if rules:
            self.log.info(f"Règles node-affinity laissées désactivées/"
                          f"détachées ({len(rules)}) : "
                          f"{', '.join(sorted(rules))}")
        if onbs:
            self.log.info(f"Guests avec 'onboot' suspendu (garde-fou "
                          f"disques locaux, à restaurer) "
                          f"({len(onbs)}) : {', '.join(sorted(onbs))}")
        if self.dry:
            # Règles node-affinity : réactivées POUR DE VRAI même en
            # dry-run — c'est la même action réversible que la
            # désactivation 2b-bis (le fichier d'état trace des PUT
            # disable=1 réellement posés), et c'est l'occasion de TESTER
            # le mécanisme de reprise sans attendre le run réel. Le
            # reste (ressources 'ignored', maintenance, flags Ceph)
            # reste SIMULÉ : sortir un nœud d'une maintenance ou
            # réactiver une ressource n'a rien d'anodin.
            if rules:
                reenabled: List[str] = []
                for rid, entry in sorted(rules.items()):
                    entry = entry or {}
                    try:
                        if "removed" in entry:
                            self._ha_rule_restore_legacy(rid, entry)
                        else:
                            self._ha_rule_restore(rid, entry)
                        self.log.info(f"  Règle {rid} : restaurée "
                                      f"(action RÉELLE — dry-run) ✔")
                        reenabled.append(rid)
                    except Exception as e:
                        self.log.error(f"Règle {rid} : restauration "
                                       f"IMPOSSIBLE ({e}) — vérifiez "
                                       f"manuellement (« pvesh get "
                                       f"/cluster/ha/rules »).")
                self._state_rules_drop(reenabled)
            self.log.info("[SIMULATION] Pour le reste (ressources HA en "
                          "'ignored', nœuds en maintenance, flags Ceph) : "
                          "AUCUNE action en dry-run — relancez en mode "
                          "--execute pour la remise à l'état zéro.")
            if onbs:
                self.log.info(
                    "[SIMULATION] Guests avec 'onboot' suspendu : leur "
                    "restauration (PUT de config) ne se fait qu'en "
                    "--execute — relancez en mode --execute.")
            return
        # Règles d'affinité D'ABORD : le CRM applique la préférence dès
        # la réactivation des ressources qui suit (failback attendu).
        # Deux formats possibles selon la version qui a laissé le
        # fichier : « removed » = ANCIEN format (ressources retirées,
        # règle éventuellement supprimée) ; sinon format actuel (mise
        # en sommeil par disable / ressources vidées / suppression,
        # selon le mode mémorisé dans l'entrée).
        for rid, entry in sorted(rules.items()):
            entry = entry or {}
            try:
                if "removed" in entry:
                    self._ha_rule_restore_legacy(rid, entry)
                else:
                    self._ha_rule_restore(rid, entry)
                self.log.info(f"  Règle {rid} : restaurée ✔")
            except Exception as e:
                self.log.error(f"Règle {rid} : restauration IMPOSSIBLE "
                               f"({e}) — vérifiez manuellement "
                               f"(« pvesh get /cluster/ha/rules »).")
        for sid, orig in res.items():
            try:
                # comment passé tel quel (même vide) pour EFFACER le label
                self.client.ha_set_resource(
                    sid, orig.get("state", "started"),
                    comment=orig.get("comment", ""))
                self.log.info(f"  {sid} : réactivée "
                              f"(state={orig.get('state', 'started')}) ✔")
            except Exception as e:
                self.log.error(f"  {sid} : réactivation IMPOSSIBLE ({e}) — "
                               f"vérifiez manuellement.")
        for n in maint:
            try:
                self.client.ha_maintenance_off(n)
                self.log.info(f"  {n} : sorti du mode maintenance ✔")
            except Exception as e:
                self.log.error(f"  {n} : sortie de maintenance impossible "
                               f"({e}) — vérifiez manuellement.")
        # Flags Ceph : le retrait est GLOBAL au cluster, on tente
        # chaque nœud connu jusqu'à ce qu'un SSH réponde. C'est une
        # opération SÛRE (même si l'upgrade n'a pas abouti : on VEUT que
        # Ceph reprenne sa reconstruction nominale) — c'est le
        # rattrapage demandé : les flags originaux sont remis, Ceph
        # reconstruit, même si l'upgrade est resté inachevé.
        if flags:
            nodes = list(self.client.node_addr) \
                or list(self.client.node_versions())
            try:
                removed = self.client.ceph_maintenance_off(flags, nodes)
            except Exception as e:
                self.log.error(f"Flags Ceph non retirés ({e}) — retrait "
                               f"manuel requis : « ceph osd unset "
                               f"<flag> ».")
            else:
                leftover = sorted(set(flags) - set(removed))
                if leftover:
                    self.log.error(f"Flags Ceph {', '.join(leftover)} "
                                   f"TOUJOURS POSÉS après la reprise — "
                                   f"retrait MANUEL requis : "
                                   f"« ceph osd unset <flag> » (sans retrait, "
                                   f"un OSD mort ne serait pas remplacé).")
        # Guests avec onboot suspendu (garde-fou v20 disques locaux) :
        # restaurer la valeur d'origine AVANT tout le reste du run — un
        # onboot resté à 0 ferait rater SILENCIEUSEMENT le boot du
        # guest au prochain reboot de son nœud. Même logique que les
        # ressources HA : l'échec d'une entrée n'empêche pas les
        # autres ; le message indique la vérification manuelle.
        for key, ent in sorted(onbs.items()):
            ent = ent or {}
            try:
                self.client.vm_set_onboot(
                    ent.get("node"), int(ent.get("vmid", 0)),
                    ent.get("vmtype", "qemu"),
                    bool(int(ent.get("onboot", 1))))
                self.log.info(f"  {key} : 'onboot' restauré à "
                              f"{int(ent.get('onboot', 1))} ✔")
            except Exception as e:
                self.log.error(f"  {key} : restauration de 'onboot' "
                               f"IMPOSSIBLE ({e}) — vérifiez MANUELLEMENT "
                               f"la config du guest (sinon il ne "
                               f"démarrera pas au prochain boot du "
                               f"nœud).")
        # l'état zéro est restauré : le fichier ne doit plus servir
        self._state_clear()
        # touched uniquement si la récupération a MODIFIÉ le cluster :
        # un fichier d'état vide (run précédent arrêté avant toute
        # écriture) ne justifie pas la fenêtre de stabilité de 60s
        # en fin de run.
        if res or maint or rules or onbs:
            self.touched = True
        if res or maint or rules or onbs:
            try:
                self.client.wait_ha_settled()
            except Exception as e:
                self.log.warning(f"Fenêtre de stabilité post-récupération : "
                                 f"{e}")

    # ---------- helpers ----------
    def _vm_on_local(self, node: str, vm) -> bool:
        """True si la VM est (ou peut être) sur stockage LOCAL : l'échantillon
        de migration serait biaisé (copie des disques, non modélisé), on
        l'exclut des statistiques. Indéterminé (None, storages illisibles)
        ou erreur : CONSERVATEUR → True (exclu) — mieux vaut un échantillon
        de moins qu'une régression faussée."""
        try:
            return self.client.vm_on_local_storage(
                node, vm.vmid, vm.vmtype) is not False
        except Exception:
            return True

    # ---------- LIVE MIGRATION RÉSILIENTE — REPRISE D'INCIDENT (v18) ------
    def _migrate_recover(self, src: str, tgt: str, real: VmInfo,
                         err: BaseException) -> str:
        """Diagnostic de LOCALISATION post-échec, puis reprise (v18).
        Retour :
        - 'target' : la guest est VIVANTE (ou dans son état attendu)
          sur la CIBLE — disques + config y sont, la migration est
          ABOUTIE : le plan continue son cours ;
        - 'retry'  : la guest est dans un état PROPRE sur sa SOURCE
          (rollback complet côté Proxmox, éventuellement après
          redémarrage de secours par le script) : la migration peut
          être retentée.
        Lève RuntimeError si la guest est arrêtée et IMPOSSIBLE à
        relancer : là seulement, le FATAL est justifié."""
        k = "CT" if real.vmtype == "lxc" else "VM"
        # 1) la guest vit-elle déjà sur la cible ?
        st_t = self.client.vm_status(tgt, real.vmid, real.vmtype)
        if st_t is not None:
            qmp = str(st_t.get("qmpstatus", st_t.get("status", "")))
            if qmp == "running":
                return "target"      # jamais réellement perdue
            if qmp == "stopped":
                if real.status != "running":
                    return "target"  # stopped → stopped : attendu ✔
                # course QEMU « resume » classique : la guest a été
                # ASSASSINÉE en fin de migration, transfert pourtant
                # complet — on la redémarre SUR LA CIBLE (un retour à
                # la source obligerait à recopier tout ce qui a déjà
                # été transféré, et l'évacuation doit aboutir).
                self.log.warning(
                    f"  {k} {real.vmid} : ARRÊTÉE sur {tgt} alors "
                    f"qu'elle tournait avant (course QEMU au « resume », "
                    f"transfert pourtant terminé) — REDÉMARRAGE sur la "
                    f"cible : disques et config y sont déjà…")
                self.client.vm_start(tgt, real.vmid, real.vmtype)
                if not self.client.vm_alive(tgt, real.vmid, real.vmtype,
                                            expect="running"):
                    raise RuntimeError(
                        f"{k} {real.vmid} redémarrée sur {tgt} mais "
                        f"toujours injoignable")
                return "target"
            # statut transitoire (paused, utilisateur…) : attendre un
            # peu et re-sonder une fois avant d'abandonner la reprise.
            self.log.warning(f"  {k} {real.vmid} sur {tgt} : statut "
                             f"'{qmp}' transitoire — nouvelle sonde "
                             f"dans 15s…")
            time.sleep(15)
            st_t = self.client.vm_status(tgt, real.vmid, real.vmtype)
            if st_t is not None:
                qmp = str(st_t.get("qmpstatus", st_t.get("status", "")))
                if qmp == "running":
                    return "target"
                if qmp == "stopped" and real.status != "running":
                    return "target"
                if qmp == "stopped":
                    self.log.warning(
                        f"  {k} {real.vmid} : ARRÊTÉE sur {tgt} après la "
                        f"course QEMU — REDÉMARRAGE sur la cible…")
                    self.client.vm_start(tgt, real.vmid, real.vmtype)
                    if not self.client.vm_alive(tgt, real.vmid,
                                                real.vmtype,
                                                expect="running"):
                        raise RuntimeError(
                            f"{k} {real.vmid} redémarrée sur {tgt} "
                            f"mais toujours injoignable")
                    return "target"
                raise RuntimeError(
                    f"{k} {real.vmid} sur {tgt} : statut '{qmp}' ni "
                    f"running ni stopped après re-sonde — reprise "
                    f"impossible en sécurité")
        # 2) la guest est-elle restée sur sa source (rollback complet) ?
        st_s = self.client.vm_status(src, real.vmid, real.vmtype)
        if st_s is not None:
            qmp = str(st_s.get("qmpstatus", st_s.get("status", "")))
            if qmp == "stopped" and real.status == "running":
                # tuée pendant la migration et rollbackée : service à
                # restaurer AVANT toute chose (le retry la re-migrera).
                self.log.warning(
                    f"  {k} {real.vmid} : ARRÊTÉE sur sa source {src} "
                    f"(rollback de la migration) — REDÉMARRAGE sur la "
                    f"source pour restaurer le service avant de "
                    f"retenter…")
                self.client.vm_start(src, real.vmid, real.vmtype)
                if not self.client.vm_alive(src, real.vmid, real.vmtype,
                                            expect="running"):
                    raise RuntimeError(
                        f"{k} {real.vmid} redémarrée sur {src} mais "
                        f"toujours injoignable")
            return "retry"
        raise RuntimeError(
            f"{k} {real.vmid} introuvable NI sur {src} NI sur {tgt} — "
            f"état incohérent à examiner à la main")

    def _migrate_resilient(self, src: str, tgt: str, real: VmInfo,
                           timeout: Optional[int]) -> None:
        """Migration d'un guest avec REPRISE D'INCIDENT (v18).
        Contexte : un échec de tâche qmigrate n'est pas toujours un
        échec de migration. Cas vécu 18/11/2026 (VM 374 → p-pes-
        proxspv-18) : transfert COMPLETE (3.2 GiB, downtime 94 ms,
        « migration status: completed ») mais le processus QEMU cible
        est déjà mort au « resume » du tunnel → « ERR: resume failed -
        VM 374 not running » → TASK ERROR « migration problems », VM
        éteinte, run ENTIer abandonné en FATAL pour une course
        transitoire (bug QEMU/PVE connu, souvent reproductible au
        second essai — variante documentée : tâche OK mais VM revenue
        arrêtée sur la cible).
        v18 : après CHAQUE échec (tâche en erreur OU guest injoignable
        post-tâche) → _migrate_recover localise la guest et la
        relance (cible si ses disques y sont, source sinon), puis la
        migration est retentée (PVE_MIGRATE_ATTEMPTS tentatives au
        total). FATAL uniquement si la guest est irrécupérable ou
        toutes les tentatives échouées — et JAMAIS sans avoir tenté
        de réallumer la guest d'abord."""
        k = "CT" if real.vmtype == "lxc" else "VM"
        # lu À L'APPEL (une valeur du --env-file doit rester effective
        # après la relecture de main(), cf. MIGRATE_TIMEOUT).
        total = max(1, int(MIGRATE_ATTEMPTS))
        last_err: Optional[BaseException] = None
        for attempt in range(1, total + 1):
            if attempt > 1:
                self.log.warning(f"… {k} {real.vmid} : nouvelle tentative "
                                 f"de migration {src} ➔ {tgt} "
                                 f"(tentative {attempt}/{total})")
                time.sleep(5)
            try:
                self.client.migrate_vm(src, real.vmid, tgt, real.vmtype,
                                       timeout=timeout)
                last_err = None
            except Exception as e:
                last_err = e
                self.log.error(f"  Échec de la migration de {k} "
                               f"{real.vmid} vers {tgt} "
                               f"(tentative {attempt}/{total}) : {e}")
            # diagnostic post-migration (acquis v13, intégré ici) : la
            # guest a-t-elle VRAIMENT survécu au déplacement ? La
            # variante « tâche OK mais guest revenue arrêtée » existe
            # (forum Proxmox) : le contrôle vaut pour les DEUX issues.
            if last_err is None and self.client.vm_alive(
                    tgt, real.vmid, real.vmtype, expect=real.status):
                return                      # succès franc
            if last_err is None:
                self.log.error(
                    f"  {k} {real.vmid} : tâche de migration OK mais "
                    f"guest injoignable sur {tgt} (running → stopped) "
                    f"— reprise v18 appliquée.")
                last_err = RuntimeError(
                    f"{k} {real.vmid} injoignable après migration vers "
                    f"{tgt}")
            # reprise : localiser + relancer la guest
            try:
                how = self._migrate_recover(src, tgt, real, last_err)
            except Exception as rec_err:
                raise RuntimeError(
                    f"{k} {real.vmid} : migration échouée ({last_err}) "
                    f"ET reprise impossible ({rec_err}) — arrêt avant "
                    f"d'aggraver la situation (fichier d'état "
                    f"conservé).") from rec_err
            if how == "target":
                if self.client.vm_alive(tgt, real.vmid, real.vmtype,
                                        expect=real.status):
                    self.log.info(
                        f"  ✔ {k} {real.vmid} : REPRISE RÉUSSIE — vivante "
                        f"sur {tgt}, migration aboutie, le run continue.")
                    return
                if attempt >= total:
                    raise RuntimeError(
                        f"{k} {real.vmid} injoignable sur {tgt} après "
                        f"reprise — arrêt avant d'aggraver la situation "
                        f"(fichier d'état conservé).")
                continue
            # how == 'retry' : guest remise en état PROPRE sur sa
            # source — on retente s'il reste des tentatives.
        raise RuntimeError(
            f"Migration de {k} {real.vmid} {src} ➔ {tgt} : {total} "
            f"tentative(s) échouée(s) — dernière erreur : {last_err}. "
            f"Arrêt avant d'aggraver la situation (fichier d'état "
            f"conservé).")

    def _apply_migrations(self, plans: List[Dict], state: ClusterState,
                          migrate: bool = True, ha_live: bool = False):
        """Exécute (ou simule) les migrations du plan et met à jour l'état.
        NB : les plans sont calculés sur un CLONE de l'état ; on retrouve donc
        chaque VM réelle par son vmid avant de la déplacer.
        migrate=False : ne déplace QUE l'état interne (pour les ressources HA,
        relocalisées séparément via ha-manager AVANT la maintenance)."""
        # À partir d'ici, l'état interne est MUTÉ (dry-run comme run réel) :
        # les vues suivantes affichent la PRESSION du modèle, et la RAM
        # d'un nœud vidé puis re-rempli y est ÉGALE à sa Σ déclarée
        # (structurel : seules les charges des running re-remplissent mem).
        state.simulated = True
        for p in plans:
            tgt = p["to"]
            # retrouver l'objet VM réel dans l'état courant (par vmid)
            real = next((v for v in state.nodes[p["from"]].vms
                         if v.vmid == p["vm"].vmid), None)
            if real is None:
                # déjà déplacée par un appel précédent : on met juste à jour la cible
                real = next((v for v in state.nodes[tgt].vms
                             if v.vmid == p["vm"].vmid), p["vm"])
            else:
                if not self.dry and migrate:
                    _t_mig = time.time()
                    # timeout adapté : live QEMU d'une VM running uniquement
                    # (une VM stopped migre sa config en quelques secondes ;
                    # un CT restart copie des disques, non modélisé ici —
                    # plancher PVE_MIGRATE_TIMEOUT dans les deux cas).
                    _mig_to = (None if (real.vmtype == "lxc"
                                        or real.status != "running")
                               else _migrate_timeout_for(vm_load(real)))
                    # v18 : migration RÉSILIENTE — reprise + retry sur
                    # échec transitoire (course QEMU « resume »), le
                    # diagnostic post-migration (guest vivant ?) est
                    # intégré à la boucle de reprise.
                    self._migrate_resilient(p["from"], tgt, real, _mig_to)
                    self.touched = True
                    # statistiques : une LIVE migration QEMU sur stockage
                    # PARTICIPATIF est un échantillon exploitable du
                    # modèle dur = ram/EST_MIGRATE_SPEED + overhead. Les
                    # LXC (mode restart : coupure, pas de transfert
                    # RAM en continu) et les disques LOCAUX (copie de
                    # disques, modèle différent) sont EXCLUS pour ne pas
                    # biaiser la régression.
                    if (real.vmtype != "lxc" and real.status == "running"
                            and not self._vm_on_local(tgt, real)):
                        self.stats_new["migrate"].append(
                            {"ram": vm_load(real),
                             "dur": round(time.time() - _t_mig, 1)})
                state.nodes[p["from"]].vms.remove(real)
                state.nodes[tgt].vms.append(real)
                # suivi des occupations RAM pour l'affichage/le placement
                # (pression : seules les VMs running consomment)
                state.nodes[tgt].mem += vm_load(real)
                state.nodes[p["from"]].mem = max(
                    state.nodes[p["from"]].mem - vm_load(real), 0)
                if self.dry:
                    # bilan dry-run : cette migration occupe la fenêtre
                    # [t0, t1] de la timeline simulée (une VM stopped sur
                    # stockage partagé ne transfère que ses métadonnées)
                    ram = vm_load(real)
                    dur = (ram / max(EST_MIGRATE_SPEED, 1)
                           + EST_MIGRATE_OVERHEAD_S)
                    self.mig_events.append({
                        "t0": self.est_clock, "t1": self.est_clock + dur,
                        "vmid": real.vmid, "name": real.name,
                        "vmtype": real.vmtype, "status": real.status,
                        "from": p["from"], "to": tgt, "ram": ram,
                        "overcommit": bool(p.get("overcommit"))})
                    self.est_clock += dur
                    self.est_mig_time += dur
                    if self.client is not None:
                        try:
                            loc = self.client.vm_on_local_storage(
                                p["from"], real.vmid, real.vmtype)
                        except Exception:
                            loc = None
                        lbl = f"{real.vmid} ({real.name})"
                        if loc is True:
                            if lbl not in self.est_local_migs:
                                self.est_local_migs.append(lbl)
                        elif loc is None and \
                                lbl not in self.est_local_unknown:
                            self.est_local_unknown.append(lbl)
            real.node = tgt
            if real.vmid in state.ha_vmids:
                ha_tag = (" [HA gelée 'ignored']" if ha_live
                          else " [HA détachée]")
            else:
                ha_tag = ""
            self.log.info(f"  {'[SIMULÉ] ' if self.dry else ''}"
                          f"{'CT' if real.vmtype == 'lxc' else 'VM'} "
                          f"{real.vmid} → {tgt} : OK{ha_tag}")

    def _watch_fencing_or_die(self, watch: List[str], phase: str):
        """Pendant/après chaque phase : détecte un fencing des autres nœuds.
        Si fencing => exception => arrêt propre via run()."""
        if self.dry:
            self.log.info(f"[DRY-RUN] Vérification fencing ({phase}) : simulation, rien détecté.")
            return
        hits = self.client.check_fencing(watch, self.log)
        if hits:
            for h in hits:
                self.log.error(f"FENCING DÉTECTÉ : {h}")
            raise RuntimeError(f"Fencing détecté pendant la phase '{phase}' — arrêt immédiat.")

    def check_orphan_ceph_flags(self) -> None:
        """Étape 0 : détecte des flags de maintenance Ceph ORPHELINS —
        posés par un run interrompu dont le fichier d'état a disparu
        (supprimé/corrompu à la main). Lecture pure : dry-run OK.
        Le retrait n'est PAS automatique : sans trace du run, ces flags
        sont indiscernables de ceux posés volontairement par
        l'administrateur (qui sont légitimes et ne doivent JAMAIS être
        retirés par le script). On alerte donc avec la procédure
        manuelle ; le run les traitera ensuite comme flags admin
        (conservés, non retirés en fin de fenêtre)."""
        nodes = list(self.client.node_addr) \
            or list(self.client.node_versions())
        cur = None
        for n in nodes:
            cur = self.client.ceph_flags_current(n)
            if cur is not None:
                break
        if cur is None:
            return          # pas de Ceph ou lecture impossible
        orphans = [f for f in ProxmoxClient.CEPH_MAINT_FLAGS if f in cur]
        if not orphans:
            return
        self.log.warning(
            f"[Ceph] Flags de maintenance ORPHELINS détectés "
            f"({', '.join(sorted(orphans))}) alors qu'aucun run en "
            f"cours ne les suit. S'ils ne sont pas de vous, retrait "
            f"manuel requis : « ceph osd unset <flag> » — sans "
            f"retrait, un OSD mort ne serait jamais remplacé "
            f"(PGs dégradées non reconstruites).")

    # ---------- étapes ----------
    def _stopped_to_leave(self, state: ClusterState, node: str) -> List[VmInfo]:
        """VMs stopped à LAISSER SUR PLACE pendant le traitement du nœud
        (aucune migration) : une VM éteinte ne court AUCUN risque pendant
        l'upgrade et le reboot, et sa migration ne gagne rien — déplacement
        de config sur stockage partagé, copie COMPLÈTE des disques sur
        stockage local. La ressource HA d'une stopped reste détachée
        ('ignored') comme les autres : sinon le mode maintenance la
        relocaliserait ; elle est réactivée dans son état d'origine
        ('stopped') en fin de traitement, sans churn (une ressource
        stopped reste stopped au retour du nœud).
        GARDE-FOU OBLIGATOIRE — 'onboot' : une VM stopped avec onboot=1
        (ou de config illisible — conservateur) est MIGRÉE comme avant :
        laissée sur place, elle DÉMARRERAIT au boot du nœud au retour
        d'upgrade (plus gérée par le HA en 'ignored'), puis serait
        ÉTEINTE par le CRM à la réactivation de sa ressource ('stopped'
        = état demandé, le CRM l'impose).
        En dry-run : seules les VMs réellement SUR le nœud (placement
        réel, pas simulé) sont candidates — l'état simulé a pu y
        déplacer des stopped lors des nœuds précédents."""
        src = state.nodes[node]
        stopped = [v for v in src.vms if v.status == "stopped"]
        if not stopped:
            return []
        real_nodes: Dict[int, str] = {}
        if self.dry:
            try:
                for r in self.client.with_api(
                        lambda p: p.cluster.resources.get()):
                    if (r.get("type") in ("qemu", "lxc")
                            and r.get("vmid") is not None):
                        try:
                            real_nodes[int(r.get("vmid"))] = r.get("node", "")
                        except (TypeError, ValueError):
                            continue
            except Exception as e:
                self.log.warning(
                    f"  Placement réel des guests illisible ({e}) : les "
                    f"VMs stopped sont migrées comme avant (conservateur).")
                return []
        leave: List[VmInfo] = []
        for v in stopped:
            if self.dry and real_nodes.get(v.vmid) != node:
                # artefact de simulation (stopped planifiée ICI par un
                # nœud précédent) : elle n'est pas réellement sur le
                # nœud — comportement inchangé, elle est migrée.
                continue
            onboot = self.client.vm_onboot(node, v.vmid, v.vmtype)
            if onboot is None:
                self.log.warning(
                    f"  {v} : stopped mais option 'onboot' illisible — "
                    f"MIGRÉE (conservateur : la laisser serait risqué "
                    f"si elle démarrait au boot du nœud).")
                continue
            if onboot:
                loc = self.client.vm_on_local_storage(node, v.vmid,
                                                     v.vmtype)
                if loc is False:
                    self.log.warning(
                        f"  {v} : stopped avec onboot=1 — MIGRÉE (laissée "
                        f"sur place, elle partirait au boot du nœud au "
                        f"retour d'upgrade, puis le CRM l'éteindrait à la "
                        f"réactivation de sa ressource 'stopped').")
                    continue
                # loc True (≥1 disque sur storage NON PARTAGÉ) ou None
                # (storages/config illisibles — conservateur) : la
                # migration devrait COPIER ses disques locaux vers des
                # storages qui n'existent QUE sur ce nœud — PVE refuse
                # l'appel cluster-wide (« storage '…' is not available
                # on node '…' »), quelle que soit la cible (vécu
                # 19/11 : VM 405, 2 tentatives FATA sur migration
                # vouée d'avance). On la laisse donc SUR PLACE et on
                # suspend TEMPORAIREMENT son onboot : elle ne
                # partira pas au boot du nœud, et la valeur d'origine
                # est restaurée au finally du nœud (fichier d'état en
                # couvre une interruption).
                if self.dry:
                    self.log.info(
                        f"  {v} : [SIMULATION] stopped avec onboot=1 et "
                        f"disques LOCAUX (ou storages indéterminés) : "
                        f"SERAIT laissée sur place avec onboot "
                        f"temporairement désactivé puis restauré (ses "
                        f"disques l'ancrent à {node}) — au lieu d'être "
                        f"migrée vers un nœud qui ne porte pas son "
                        f"storage.")
                    leave.append(v)
                    continue
                try:
                    self.client.vm_set_onboot(node, v.vmid, v.vmtype,
                                              False)
                except Exception as e:
                    # Impossible de suspendre l'auto-démarrage ET
                    # impossible de migrer (disques locaux) : rebooter
                    # le nœud ferait DÉMARRER cette VM contre toute
                    # intention (incident historique à l'origine du
                    # garde-fou). Arrêt AVANT l'évacuation du nœud,
                    # remédiation manuelle explicite.
                    raise RuntimeError(
                        f"{v} : stopped avec onboot=1, disques locaux "
                        f"(migration impossible) et option 'onboot' "
                        f"INMODIFIABLE ({e}) — abandon du nœud AVANT "
                        f"évacuation : un reboot le ferait démarrer "
                        f"contre toute intention. Suspendez-la à la "
                        f"main (qm set {v.vmid} --onboot 0) puis "
                        f"relancez (elle sera réactivée ensuite).")
                key = f"{v.vmtype}:{v.vmid}"
                self.onboot_suspended[key] = {
                    "vmid": v.vmid, "vmtype": v.vmtype, "node": node,
                    "onboot": 1}
                self._state_write()
                self.log.warning(
                    f"  {v} : stopped avec onboot=1 mais disques LOCAUX "
                    f"(storage non partagé inexistant sur les autres "
                    f"nœuds : migration vouée à l'échec) — LAISSÉE sur "
                    f"place avec 'onboot' TEMPORAIREMENT désactivé "
                    f"(restauré en fin de traitement du nœud ; tracé "
                    f"dans le fichier d'état en cas d'interruption).")
                leave.append(v)
                continue
            leave.append(v)
        return leave

    def preflight(self):
        banner(self.log, "ÉTAPE 0 — Pré-vérifications du cluster")
        # Les pré-vérifications sont de PURE LECTURE (quorum, versions PVE,
        # état HA) : elles s'exécutent aussi en dry-run — inutile de les
        # simuler, elles échoueraient réellement si le cluster allait mal.
        # ... sauf la récupération d'un run interrompu, qui MODIFIE le
        # cluster en --execute (réactivation des ressources HA laissées
        # en 'ignored', sortie des maintenances résiduelles) et, même en
        # dry-run, pour les SEULES règles node-affinity (mises en
        # sommeil réelles et réversibles, tracées dans le fichier d'état).
        self._recover_interrupted_run()
        st = self.client.with_api(lambda p: p.cluster.status.get())
        cname = next((s.get("name", "?") for s in st
                      if s.get("type") == "cluster"), "?")
        if not any(s.get("quorate") == 1 for s in st if s.get("type") == "cluster"):
            raise RuntimeError("Le cluster n'est PAS quorate — abandon.")
        versions = self.client.node_versions()
        self.log.info(f"Cluster : {cname} — "
                      f"versions/nœuds accessibles : {versions}")
        # Hétérogénéité QEMU (v13) : pendant un rolling upgrade, les
        # nœuds déjà upgradés portent un QEMU plus récent ; une VM
        # démarrée là-bas a pu RÉSOLU une machine (« pc-i440fx-11.1 »)
        # que les autres nœuds ne sauront pas exécuter à la migration.
        # Prévenir AVANT de démarrer, tant qu'on peut encore figer les
        # machines ou arrêter les VMs concernées.
        if self.state.node_qemu:
            uqs = sorted(set(self.state.node_qemu.values()))
            if len(uqs) > 1:
                self.log.warning(
                    f"QEMU HÉTÉROGÈNE sur ce cluster "
                    f"({', '.join(uqs)}) : "
                    + ", ".join(f"{n}={v}" for n, v in
                                sorted(self.state.node_qemu.items())))
                oldest = min(_qemu_version(v) for v in uqs)
                risky = [f"VM {vmid} ({mach})"
                         for vmid, mach in sorted(self.state.vm_machine.items())
                         if (_machine_version(mach) or (0, 0)) > oldest]
                if risky:
                    self.log.warning(
                        "  Machines PLUS RÉCENTES que le QEMU le plus "
                        "ancien (migration vers les nœuds anciens "
                        "refusée par PVE) : " + ", ".join(risky))
                    self.log.warning(
                        "  Si une évacuation les concerne : la FIGER "
                        "après arrêt (qm set <vmid> --machine "
                        "<famille>-<X.Y>), la laisser ARRÊTÉE pendant "
                        "le run, ou upgrader d'abord un nœud cible.")
        # Présence de Ceph (détection mémoïsée : ce premier appel pose
        # le drapeau _no_ceph si le cluster n'a pas de Ceph — les gates
        # Ceph seront donc silencieusement ignorées pendant tout le run).
        ceph = self.client.ceph_status()
        if ceph is not None:
            hstat, ignored = self.client.ceph_effective_health(ceph)
            self.log.info(f"Ceph : PRÉSENT (santé globale : {hstat}) — "
                          f"gates Ceph actives (HEALTH_OK exigée)")
            if ignored:
                self.client.ceph_log_auth_insecure(ignored)
            self.client.ceph_diagnose(ceph)
            # Flags de maintenance orphelins (run interrompu dont le
            # fichier d'état a disparu) : alerte + procédure manuelle.
            self.check_orphan_ceph_flags()
        else:
            self.log.info("Ceph : ABSENT sur ce cluster — "
                          "contrôles Ceph ignorés pendant le run.")
        self.log.info("État HA courant :")
        for line in self.client.ha_status():
            self.log.info(f"    {line}")
        # Règles d'affinité HA (PVE ≥ 9) : elles pilotent les cibles que
        # le CRM choisira lors des évacuations en mode maintenance.
        rules = self.client.ha_rules()
        if rules:
            self.log.info("Règles HA (affinités) :")
            for r in rules:
                rid = r.get("rule", "?")
                rtype = r.get("type", "?")
                if rtype == "resource-affinity":
                    # pas de champ « nodes » : affinité ENTRE RESSOURCES
                    sens = str(r.get("affinity", "positive")).lower()
                    lbl = ("à garder ENSEMBLE (affinity=positive)"
                           if sens != "negative" else
                           "à garder SÉPARÉES (affinity=negative, "
                           "anti-affinité)")
                    base = (f"    {rid} [{rtype}] : ENTRE RESSOURCES — "
                            f"{lbl}, "
                            f"ressources {r.get('resources', '?')}, "
                            f"strict={r.get('strict', 0)}")
                else:
                    base = (f"    {rid} [{rtype}] : nœuds {r.get('nodes', '?')}, "
                            f"ressources {r.get('resources', '?')}")
                    if rtype == "node-affinity":
                        base += f", affinity={r.get('affinity', 'positive')}"
                        base += f", strict={r.get('strict', 0)}"
                if r.get("disable"):
                    base += "  (désactivée)"
                self.log.info(base)

        # self.state a déjà été chargé dans run() (API en lecture seule pour dry-run)
        print_occupancy_table(
            self.log, self.state, "ÉTAT INITIAL DU CLUSTER",
            note=("« RAM réelle » = mémoire consommée MESURÉE du nœud ; "
                  "« Σ déclarée » = Σ RAM max des guests running — la "
                  "pression anti-overcommit que le run répartit/égalise. "
                  "Deux métriques distinctes : l'état final simulé "
                  "s'apprécie sur « Σ déclarée », pas sur « RAM réelle »."))
        gap = pressure_gap(self.state)
        if gap is not None:
            self.log.info(f"Écart de pression RAM initial (max-min) : {gap:.0%} "
                          f"(cible de rééquilibrage : "
                          f"AUTO — optimum théorique calculé en fin de run)")

    # ---------- mise en sommeil temporaire des règles node-affinity ----------
    # Le planning du script (plan_migrations) ET le CRM respectent les
    # règles HA « node-affinity » : pendant l'Étape 1 (évacuations +
    # upgrades), ces règles « pollueraient » le comportement du CRM
    # (relocate décidé à chaque sortie de maintenance, en pleine
    # évacuation du nœud suivant) et contraindraient le placement du
    # script (strict=1 : évacuation BLOQUÉE ; strict=0 : repli « hors
    # règle » avec réactivation HA différée). On met donc TOUTES les
    # règles node-affinity du cluster « en sommeil » une seule fois par
    # run, au début de l'Étape 1, selon le mode que le schéma de
    # l'API PVE du cluster accepte (cf. _ha_rule_disable : PUT
    # `type`+`disable=1` ; sinon PUT `type`+`resources=""` — la règle
    # ne s'applique plus à rien, définition conservée ; sinon DELETE
    # temporaire avec recréation à l'identique) et on les restaure
    # à la FIN de l'Étape 1, avant le rapatriement/rééquilibrage :
    # ceux-ci redeviennent contraints par les règles et le dégel
    # final reste cohérent (le CRM n'a pas une vague de relocate à
    # corriger en pleine Étape 2). Les règles déjà désactivées par un
    # admin ne sont pas touchées. Les resource-affinity (« keep
    # separate » / « together ») ne sont JAMAIS touchées : contraintes
    # de sécurité de groupe, elles restent actives du début à la fin.
    # NB dry-run : ces mises en sommeil/restaurations sont effectuées
    # POUR DE VRAI (action réversible ; retirer une préférence ne
    # déplace aucune ressource, et une restauration sur des
    # placements conformes n'en déplace pas non plus) — c'est le seul
    # moyen de TESTER le mécanisme avant le run réel. Tout le reste
    # (migrations, apt, reboot, maintenance, détachement HA) reste
    # simulé ; le fichier d'état trace ces actions réelles pour la
    # reprise après interruption, en préservant toute section d'un
    # run --execute interrompu.
    @staticmethod
    def _ha_rule_rid(r: Dict) -> str:
        """Identifiant d'une règle HA (champ « rid » de l'API PVE,
        avec repli sur d'autres libellés possibles)."""
        return str(r.get("rid") or r.get("rule") or r.get("id") or "")

    @staticmethod
    def _ha_rule_resources_list(s) -> List[str]:
        """Liste des sids ('vm:102', 'ct:8000') du champ `resources`
        d'une règle HA (chaîne séparée par des virgules)."""
        return [x.strip() for x in str(s or "").split(",") if x.strip()]

    @staticmethod
    def _ha_rule_res_vmids(resources) -> Set[int]:
        """vmids des ressources listées par une règle HA."""
        out: Set[int] = set()
        for s in Updater._ha_rule_resources_list(resources):
            if ":" not in s:
                continue
            try:
                out.add(int(s.split(":", 1)[1]))
            except ValueError:
                continue
        return out

    def _ha_affinity_recompute(self, state: ClusterState, rules: List[Dict],
                               vmids: Set[int]) -> None:
        """Ré-applique dans l'état en mémoire les contributions des
        règles node-affinity ACTIVES (non désactivées) pour les vmids
        donnés — sémantique EXACTE de fetch_state (positive : ses
        nœuds ; affinity=negative : tous les nœuds SAUF les siens ;
        strict=1 : intersection dure). Utilisé quand une désactivation
        de règle a ÉCHOUÉ : la règle est toujours active côté cluster,
        l'état en mémoire doit le refléter."""
        for v in vmids:
            state.ha_affinity.pop(v, None)
            state.ha_affinity_hard.pop(v, None)
        for r in rules:
            if r.get("type") != "node-affinity" or r.get("disable"):
                continue
            allowed = {n.strip() for n in str(r.get("nodes", "")
                                             ).split(",") if n.strip()}
            if not allowed:
                continue
            if str(r.get("affinity", "positive")).lower() == "negative":
                allowed = set(state.nodes.keys()) - allowed
                if not allowed:
                    continue
            try:
                strict_rule = bool(int(r.get("strict", 0) or 0))
            except (TypeError, ValueError):
                strict_rule = False
            for res in self._ha_rule_resources_list(r.get("resources", "")):
                if ":" not in res:
                    continue
                try:
                    vmid = int(res.split(":", 1)[1])
                except ValueError:
                    continue
                if vmid not in vmids:
                    continue
                state.ha_affinity.setdefault(vmid, set()).update(allowed)
                if strict_rule:
                    if vmid in state.ha_affinity_hard:
                        state.ha_affinity_hard[vmid] &= allowed
                    else:
                        state.ha_affinity_hard[vmid] = set(allowed)

    def _ha_rule_disable(self, rid: str, r: Dict) -> Optional[str]:
        """Met une règle node-affinity « en sommeil » de façon COMPATIBLE
        avec le schéma de l'API PVE de ce cluster, en cascade :
        1. « disable »  : PUT `type` + `disable=1`. Le schéma des règles
           est TYPE-DÉPENDANT : « type » est OBLIGATOIRE dans le PUT
           (sans lui, « disable » est refusé « property is not defined
           in schema » — constaté sur un PVE 9.1/9.2 en run réel) ; et
           selon la version de PVE, « disable » peut ne pas être exposé
           par l'API du tout (alors que ha-manager le connaît) ;
        2. « resources » : PUT `type` + `resources=""` — la règle ne
           s'applique plus à AUCUNE ressource : effet identique pour
           le CRM et pour le planning, identifiant et définition
           conservés (le champ `disable`, si le PVE l'expose, n'est
           pas touché) ;
        3. « delete »    : DELETE — dernier recours (API qui refuse
           aussi `resources` vides) ; la définition d'origine est dans
           le snapshot, la règle est recréée à l'identique à la
           restauration.
        Le mode qui fonctionne est mémorisé pour TOUT le run : les
        règles suivantes vont directement au bon mode (au plus UN
        refus 400 bruyant par run, au premier essai). Retourne le mode
        utilisé, None si toute la cascade a échoué."""
        rtype = str(r.get("type") or "node-affinity")
        modes = ["disable", "resources", "delete"]
        hint = getattr(self, "_ha_rule_mode_hint", None)
        if hint in modes:
            modes.remove(hint)
            modes.insert(0, hint)
        last_err: Optional[Exception] = None
        for mode in modes:
            try:
                if mode == "disable":
                    self.client.ha_rule_update(rid, type=rtype, disable=1)
                elif mode == "resources":
                    self.client.ha_rule_update(rid, type=rtype, resources="")
                else:
                    self.client.ha_rule_delete(rid)
            except Exception as e:
                last_err = e
                self.log.warning(f"  2b-bis) Règle {rid} : mode "
                                 f"« {mode} » refusé par l'API ({e}).")
                continue
            # VÉRIFICATION OBLIGATOIRE (re-lecture) : un PUT ACCEPTÉ
            # (HTTP 200) peut rester SANS EFFET côté HA Manager — le
            # code retour seul NE PROUVE RIEN. Le mode n'est retenu que
            # si l'effet est CONFIRMÉ sur le cluster.
            try:
                cur = self.client.ha_rule_get(rid)
            except Exception as e:
                # lecture impossible : ni confirmé ni infirmé — le mode
                # est retenu (comportement historique), mais explicité.
                self.log.warning(f"  2b-bis) Règle {rid} : effet du mode "
                                f"« {mode} » NON VÉRIFIABLE ({e}) — mode "
                                f"retenu sans confirmation de lecture.")
                self._ha_rule_mode_hint = mode
                return mode
            if mode == "disable":
                ok = cur is not None and bool(cur.get("disable"))
                attendu = "disable=1 constaté"
            elif mode == "resources":
                ok = cur is not None and not self._ha_rule_resources_list(
                    cur.get("resources", ""))
                attendu = "ressources vidées constatées"
            else:
                ok = cur is None
                attendu = "règle absente constaté"
            if not ok:
                last_err = RuntimeError(
                    f"PUT accepté mais effet NON CONSTATÉ ({attendu})")
                self.log.warning(f"  2b-bis) Règle {rid} : mode "
                                 f"« {mode} » accepté par l'API mais "
                                 f"SANS EFFET côté cluster — cascade "
                                 f"vers le mode suivant.")
                continue
            if getattr(self, "_ha_rule_mode_hint", None) is None \
                        and mode != "disable":
                self.log.info(f"  2b-bis) L'API de ce PVE refuse "
                              f"« disable » : mode « {mode} » retenu "
                              f"pour toutes les règles de ce run.")
            self._ha_rule_mode_hint = mode
            return mode
        self.log.error(f"Règle {rid} : mise en sommeil IMPOSSIBLE "
                       f"({last_err}) — elle reste ACTIVE, le "
                       f"planning garde sa contrainte.")
        return None

    def _ha_rule_equivalent_exists(self, rules: List[Dict],
                                   orig: Dict) -> Optional[Dict]:
        """Règle ÉQUIVALENTE à la définition d'origine (même type, mêmes
        nœuds, ressources couvrantes) : la règle a pu être recréée
        manuellement sous un AUTRE identifiant (GUI, pvesh, run
        antérieur). Retourne cette règle, sinon None. À n'appeler que si
        la règle d'origine est ABSENTE : évite de créer un DOUBLON à la
        restauration (cas réel : règle vm:502 recréée manuellement)."""
        orig_type = str(orig.get("type") or "node-affinity")
        orig_nodes = {n.strip() for n in str(orig.get("nodes", "")
                                           ).split(",") if n.strip()}
        orig_res = set(self._ha_rule_resources_list(orig.get("resources",
                                                             "")))
        for r in rules:
            if str(r.get("type") or "") != orig_type:
                continue
            r_nodes = {n.strip() for n in str(r.get("nodes", "")
                                            ).split(",") if n.strip()}
            if orig_nodes and r_nodes != orig_nodes:
                continue
            if orig_res and not orig_res <= set(
                    self._ha_rule_resources_list(r.get("resources", ""))):
                continue
            return r
        return None

    def _ha_rule_definition_restore(self, rid: str, orig: Dict) -> None:
        """Rend une définition de règle à nouveau effective (modes
        « resources » et « delete », et reprise de l'ANCIEN format de
        fichier d'état) : règle présente → PUT de FUSION (ressources
        courantes ∪ ressources d'origine) ; règle absente → recréation
        par POST (paramètre « rule » du schéma PVE 9, PAS « rid »), sauf
        si une règle équivalente a été recréée entre-temps
        (anti-doublon)."""
        rules = self.client.ha_rules()
        cur = next((r for r in rules if self._ha_rule_rid(r) == rid), None)
        orig_res = self._ha_rule_resources_list(orig.get("resources", ""))
        otype = str(orig.get("type")
                    or (cur or {}).get("type") or "node-affinity")
        if cur is None:
            equiv = self._ha_rule_equivalent_exists(rules, orig)
            if equiv is not None:
                self.log.info(f"  Règle {rid} : déjà recréée sous un autre "
                              f"identifiant ({self._ha_rule_rid(equiv)}) — "
                              f"aucun doublon créé.")
                return
            params: Dict[str, object] = {"rule": rid, "type": otype,
                                         "resources": ",".join(orig_res)}
            for k in ("nodes", "affinity", "strict", "comment"):
                v = orig.get(k)
                if v not in (None, ""):
                    params[k] = v
            self.client.ha_rule_create(**params)
        else:
            merged = sorted(set(self._ha_rule_resources_list(
                cur.get("resources", ""))) | set(orig_res))
            self.client.ha_rule_update(rid, type=otype,
                                       resources=",".join(merged))
        # VÉRIFICATION par re-lecture (même discipline que le mode
        # « disable ») : un PUT/POST ACCEPTÉ ne prouve rien — la règle
        # doit exister ET couvrir les ressources d'origine, sinon
        # échec EXPLICITE (la règle reste dans le fichier d'état, le
        # prochain run la réactivera).
        cur2 = self.client.ha_rule_get(rid)
        if cur2 is None or not (set(orig_res) <= set(
                self._ha_rule_resources_list(cur2.get("resources", "")))):
            raise RuntimeError(
                "restauration de la définition sans effet constaté "
                "(règle absente ou ressources d'origine non couvertes "
                "après un PUT/POST pourtant accepté)")

    def _ha_rule_restore(self, rid: str, entry: Dict) -> None:
        """Restaure une règle mise en sommeil selon le mode utilisé :
        « disable » → réactivation (cf. ci-dessous) ou disable remis
        à 1 si la règle ÉTAIT déjà désactivée avant le run ;
        « resources »/« delete » → définition d'origine de nouveau
        effective (fusion ou recréation). Lève en cas d'échec :
        l'appelant garde alors la règle dans le fichier d'état pour le
        prochain run.
        NB RÉACTIVATION (mode « disable », bug PVE 9 constaté en run
        réel RHOSPDC 9.1.2 + correctif officiel pve-manager ≥ 9.0.7) :
        depuis un changement du HA Manager, « disable=0 » ne réactive
        PLUS une règle désactivée — le PUT est ACCEPTÉ (HTTP 200) mais
        reste SANS EFFET. La seule réactivation fiable est de
        SUPPRIMER la propriété « disable » (paramètre standard
        « delete » des PUT PVE : delete=disable). Cascade avec
        « disable=0 » en repli (PVE antérieurs), puis VÉRIFICATION par
        re-lecture : plus jamais de « réactivée ✔ » de façade."""
        orig = entry.get("rule") or {}
        mode = str(entry.get("mode") or "disable")
        if mode == "disable":
            otype = str(orig.get("type") or "node-affinity")
            was = int(bool(entry.get("was_disabled", False)))
            if was:
                self.client.ha_rule_update(rid, type=otype, disable=1)
                return
            err: Optional[Exception] = None
            for attempt in ("delete-prop", "zero"):
                try:
                    if attempt == "delete-prop":
                        self.client.ha_rule_update(rid, type=otype,
                                                   delete="disable")
                    else:
                        self.client.ha_rule_update(rid, type=otype,
                                                   disable=0)
                except Exception as e:
                    err = e
                    continue
                cur = self.client.ha_rule_get(rid)
                if cur is None:
                    err = RuntimeError("la règle a DISPARU du cluster "
                                       "pendant la restauration")
                    continue
                if not bool(cur.get("disable")):
                    return      # réactivation CONFIRMÉE par re-lecture
                err = RuntimeError("PUT accepté mais la règle est restée "
                                   "désactivée côté cluster")
            raise RuntimeError(
                "réactivation IMPOSSIBLE : la propriété « disable » n'a "
                "pu être ni supprimée (« delete=disable ») ni remise à 0 "
                f"({err}) — la règle est restée DÉSACTIVÉE côté cluster")
        self._ha_rule_definition_restore(rid, orig)

    def _ha_rules_disable_all(self, state: ClusterState) -> None:
        """2b-bis) Met « en sommeil » TOUTES les règles HA
        « node-affinity » du cluster, une seule fois par run (idempotent
        : un snapshot non vide = déjà traitées). Mode adapté au schéma
        de l'API PVE (cf. _ha_rule_disable) : disable, sinon ressources
        vidées, sinon suppression temporaire. Les règles déjà
        désactivées par un admin ne sont ni touchées ni mémorisées ;
        les resource-affinity ne sont jamais touchées. L'état en
        mémoire (ha_affinity / ha_affinity_hard, alimentés UNIQUEMENT
        par les node-affinity) est sauvegardé puis vidé : le planning
        de toute l'Étape 1 est LIBRE. L'opération est effectuée POUR DE
        VRAI aussi en dry-run (action réversible : test du mécanisme),
        persistée dans le fichier d'état pour la reprise."""
        if self.ha_rules_snapshot:
            return          # déjà désactivées ce run
        try:
            rules = self.client.ha_rules()
        except Exception as e:
            self.log.warning(f"Règles HA illisibles ({e}) — désactivation "
                             f"IMPOSSIBLE, le planning garde les "
                             f"contraintes actuelles.")
            return
        kept: List[Dict] = []      # mise en sommeil échouée : reste ACTIVE
        disabled: List[str] = []
        for r in rules:
            if r.get("type") != "node-affinity" or r.get("disable"):
                continue
            rid = self._ha_rule_rid(r)
            if not rid:
                continue
            if not self._ha_rule_resources_list(r.get("resources", "")):
                continue   # déjà sans ressources : n'affecte rien
            # NB : la mise en sommeil est effectuée POUR DE VRAI aussi
            # en dry-run — action réversible et sans effet de bord sur
            # des placements conformes (retirer une préférence ne
            # déplace rien) : c'est le seul moyen de TESTER le
            # mécanisme avant le run réel, comme demandé. Les
            # migrations/apt/reboot restent, eux, simulés.
            mode = self._ha_rule_disable(rid, r)
            if mode is None:
                kept.append(r)
                continue
            self.ha_rules_snapshot[rid] = {"rule": dict(r),
                                           "was_disabled": False,
                                           "mode": mode}
            disabled.append(rid)
            lbl = {"disable": "désactivée (disable=1, effet vérifié "
                              "par re-lecture)",
                   "resources": "mise en sommeil (ressources vidées — "
                                "plus aucune ressource concernée, "
                                "définition conservée)",
                   "delete": "supprimée temporairement (recréée à "
                             "l'identique en fin d'Étape 1)"}[mode]
            if self.dry:
                self.log.info(f"  2b-bis) Règle {rid} : {lbl} — action "
                              f"RÉELLE même en dry-run (test du "
                              f"mécanisme) ; restauration à la fin de "
                              f"l'Étape 1 ✔")
            else:
                self.log.info(f"  Règle {rid} : {lbl} — restaurée à la "
                              f"fin de l'Étape 1 ✔")
        if not disabled:
            return
        # sauvegarde intégrale puis vidage : plus AUCUNE contrainte
        # node-affinity pendant l'Étape 1.
        self._affinity_backup = (
            {k: set(v) for k, v in state.ha_affinity.items()},
            {k: set(v) for k, v in state.ha_affinity_hard.items()})
        state.ha_affinity.clear()
        state.ha_affinity_hard.clear()
        # mises en sommeil échouées : leurs contributions restent valables
        # (règles toujours actives côté cluster).
        if kept:
            try:
                vmids = set()
                for r in kept:
                    vmids |= self._ha_rule_res_vmids(r.get("resources", ""))
                self._ha_affinity_recompute(state,
                                            self.client.ha_rules(), vmids)
            except Exception as e:
                self.log.warning(f"Ré-application des règles non "
                                 f"désactivables impossible ({e}).")
        hint = getattr(self, "_ha_rule_mode_hint", None)
        mode_note = f" (mode : {hint})" if hint and hint != "disable" else ""
        self.log.info(f"{len(disabled)} règle(s) node-affinity mise(s) en "
                      f"sommeil pour l'Étape 1 ({', '.join(disabled)})"
                      f"{mode_note} — placement "
                      f"LIBRE pendant les évacuations, restauration avant "
                      f"le rééquilibrage.")
        # persister DANS TOUS LES MODES : les mises en sommeil sont
        # RÉELLES (dry-run compris) — un run tué en pleine Étape 1 doit
        # pouvoir être rattrapé par la reprise du run suivant.
        self._state_write()

    def _ha_rules_restore_all(self, state: Optional[ClusterState]) -> None:
        """Fin de l'Étape 1 : réactive les règles node-affinity mises en
        sommeil au début du run — AVANT le rapatriement (--node) / le
        rééquilibrage et le plan de failback des hors-règle : tout ce
        qui suit redevient contraint par les règles, comme le CRM au
        dégel final. Réactivation ADAPTÉE au mode utilisé (_ha_rule_
        restore : disable remis à son état d'origine, ou définition
        restaurée par fusion/recréation). En cas d'échec : la règle
        reste dans le fichier d'état, le prochain run la réactivera.
        L'action est effectuée POUR DE VRAI aussi en dry-run (miroir de
        la mise en sommeil 2b-bis : test du mécanisme)."""
        if not self.ha_rules_snapshot:
            return
        reenabled: List[str] = []
        for rid in sorted(self.ha_rules_snapshot):
            entry = self.ha_rules_snapshot[rid]
            lbl = {"disable": "propriété « disable » supprimée ou remise "
                              "à son état d'origine — réactivation "
                              "VÉRIFIÉE par re-lecture",
                   "resources": "ressources d'origine restaurées",
                   "delete": "règle recréée à l'identique"}.get(
                str(entry.get("mode") or "disable"))
            # RÉEL aussi en dry-run : miroir exact de la mise en sommeil
            # 2b-bis (action réversible — c'est le test demandé).
            try:
                self._ha_rule_restore(rid, entry)
                if self.dry:
                    self.log.info(f"  Fin d'Étape 1 : règle {rid} "
                                  f"réactivée ({lbl}) — action RÉELLE "
                                  f"même en dry-run (test du mécanisme) ✔")
                else:
                    self.log.info(f"  Règle {rid} : réactivée ({lbl}) ✔")
            except Exception as e:
                self.log.error(f"Règle {rid} : réactivation IMPOSSIBLE "
                               f"({e}) — elle reste dans le fichier "
                               f"d'état, le prochain run la réactivera.")
                continue
            del self.ha_rules_snapshot[rid]
            reenabled.append(rid)
        if reenabled:
            if state is not None and self._affinity_backup is not None:
                aff, hard = self._affinity_backup
                state.ha_affinity.clear()
                state.ha_affinity.update({k: set(v)
                                          for k, v in aff.items()})
                state.ha_affinity_hard.clear()
                state.ha_affinity_hard.update({k: set(v)
                                               for k, v in hard.items()})
                self._affinity_backup = None
            self.log.info(f"{len(reenabled)} règle(s) node-affinity "
                          f"réactivée(s) — le placement redevient contraint "
                          f"par les règles ; le CRM applique ses préférences "
                          f"aux prochains placements (failback possible : "
                          f"ATTENDU, pas une anomalie).")
            if self.dry:
                # ne retirer DU FICHIER que les règles réellement
                # réactivées — une section d'un run --execute interrompu
                # (ressources 'ignored', maintenance…) doit survivre.
                self._state_rules_drop(reenabled)
            else:
                self._state_write()

    def _ha_rule_restore_legacy(self, rid: str, entry: Dict) -> None:
        """Reprise d'un fichier d'état de l'ANCIENNE version du script
        (retrait des ressources évacuées des règles, règle SUPPRIMÉE si
        vidée) : passe par _ha_rule_definition_restore — recrée la règle
        manquante avec sa définition d'origine (POST, identifiant
        « rule » — le paramètre « rid » est REFUSÉ par le schéma PVE 9),
        ou fusionne les ressources d'origine avec les courantes si la
        règle existe encore ; avec anti-doublon si elle a été recréée
        sous un autre identifiant entre-temps."""
        self._ha_rule_definition_restore(rid, entry.get("rule") or {})

    def hosts_sync(self) -> None:
        """ÉTAPE 0-bis : /etc/hosts de CHAQUE nœud doit résoudre tous
        les nœuds du cluster par nom court (corosync, migrations, ceph,
        SSH inter-nœuds). Audit complet en lecture AVANT de toucher au
        premier nœud — en dry-run : rapport SEULEMENT (aucune
        modification) ; en --execute : correction par nœud (ajout des
        manquants, IP incohérentes, doublons et entrées obsolètes mises
        en commentaire) après sauvegarde datée, puis re-vérification.
        Désactivable via PVE_HOSTS_CHECK=0 (audit refusé si un nœud ne
        peut pas être corrigé : un /etc/hosts faux en pleine migration
        peut casser la résolution de noms au pire moment)."""
        if str(_env("PVE_HOSTS_CHECK", "1")) != "1":
            self.log.info("/etc/hosts : audit désactivé (PVE_HOSTS_CHECK=0).")
            return
        banner(self.log,
               "ÉTAPE 0-bis — /etc/hosts : résolution de tous les nœuds "
               "du cluster", ColorFormatter.CYAN)
        expected: Dict[str, str] = {}
        for name, ni in sorted(self.state.nodes.items()):
            ip = self.client.node_addr.get(name)
            if not ip or ip == name:
                self.log.warning(
                    f"  {name} : IP de gestion inconnue (API) — "
                    "l'entrée /etc/hosts ne sera pas vérifiée/corrigée "
                    "pour ce nœud.")
                continue
            expected[name] = ip
        contents: Dict[str, str] = {}
        for name in expected:
            try:
                contents[name] = self.client.hosts_read(name)
            except Exception as e:
                self.log.warning(
                    f"  {name} : /etc/hosts illisible ({e}) — audit "
                    "non bloquant pour CE nœud, poursuivi pour les autres.")
        # FQDN de référence (format « IP  FQDN  nom ») : d'abord ceux déjà
        # présents dans les fichiers du cluster, sinon « hostname -f » —
        # seulement si un MANQUANT est à quelque part (lecture pure).
        fqdns: Dict[str, str] = {}
        need_fqdn = {m["name"] for c in contents.values()
                     for m in hosts_audit(c, expected)["missing"]}
        for name in need_fqdn:
            for c in contents.values():
                for e in _hosts_entries(c):
                    if name in e["aliases"]:
                        dotted = [a for a in e["aliases"]
                                  if "." in a and a.split(".")[0] == name]
                        if dotted:
                            fqdns[name] = dotted[0]
                            break
                if name in fqdns:
                    break
            if name not in fqdns:
                fq = self.client.hosts_fqdn(name)
                if fq:
                    fqdns[name] = fq
                else:
                    self.log.info(
                        f"  {name} : FQDN introuvable — l'entrée ajoutée "
                        "sera au format « IP nom ».")
        fixed = 0
        dirty_nodes = 0
        for name in sorted(contents):
            node_expected = expected
            audit = hosts_audit(contents[name], node_expected)
            n_pb = (len(audit["missing"]) + len(audit["wrong"])
                    + len(audit["shortless"]) + len(audit["dup"])
                    + len(audit["stale"]))
            if not n_pb:
                self.log.info(f"  {name} : /etc/hosts complet "
                              f"({len(expected)}/{len(expected)} nœuds "
                              "résolus, aucune entrée obsolète) ✔")
                continue
            dirty_nodes += 1
            self.log.warning(f"  {name} : {n_pb} correction(s) nécessaire(s)")
            for kind in ("missing", "wrong", "shortless", "dup", "stale"):
                for it in audit[kind]:
                    self.log.warning(f"      {hosts_item_str(it, kind)}")
            if self.dry:
                self.log.info(
                    f"      [DRY-RUN] aucune correction appliquée sur "
                    f"{name} — le fichier serait réécrit (sauvegarde "
                    "datée puis ajout/correction/commentaire).")
                continue
            new_content, actions = hosts_fix(contents[name], node_expected,
                                              fqdns)
            try:
                bak = self.client.hosts_write(name, new_content)
            except Exception as e:
                raise RuntimeError(
                    f"{name}: correction de /etc/hosts IMPOSSIBLE ({e}) "
                    "— abandon AVANT toute migration : un fichier "
                    "incohérent peut casser la résolution de noms en "
                    "plein run.")
            fixed += 1
            for a in actions:
                self.log.info(f"      ✔ {a}")
            self.log.info(f"      /etc/hosts de {name} corrigé — "
                          f"sauvegarde : {bak}")
            # re-vérification : le correctif doit avoir TOUT réglé.
            after = hosts_audit(self.client.hosts_read(name), node_expected)
            n_after = (len(after["missing"]) + len(after["wrong"])
                       + len(after["shortless"]) + len(after["dup"])
                       + len(after["stale"]))
            if n_after:
                raise RuntimeError(
                    f"{name}: /etc/hosts corrigé mais l'audit re-détecte "
                    f"{n_after} anomalie(s) — abandon (état du fichier : "
                    "voir ci-dessus, sauvegarde disponible).")
        if self.dry:
            if dirty_nodes:
                self.log.warning(
                    f"/etc/hosts : {dirty_nodes} nœud(s) à corriger — "
                    "rejouez ce dry-run après les corrections ou passez "
                    "en --execute.")
            else:
                self.log.info(
                    f"/etc/hosts : conforme sur les {len(contents)} "
                    "nœud(s) audités ✔")
        elif dirty_nodes:
            self.log.info(
                f"/etc/hosts : {fixed} nœud(s) corrigés "
                f"(sur {len(contents)} audités) ✔")
        elif contents:
            self.log.info(
                f"/etc/hosts : conforme sur les {len(contents)} "
                "nœud(s) audités ✔")

    def update_node(self, node: str, progress: str = ""):
        state = self.state
        ip = self.client.node_addr.get(node, "?")
        step = f" — nœud {progress} " if progress else ""
        banner(self.log, f"ÉTAPE 1 — Traitement de {node} ({ip}){step}",
               ColorFormatter.CYAN)

        # --- Phase 0 : ÉVALUATION des mises à jour AVANT toute évacuation.
        # On se connecte au nœud et on rafraîchit les listes (apt update),
        # puis une simulation apt (mode -s, aucune action) indique s'il y a
        # des paquets à mettre à jour et si le noyau est concerné.
        # Identique en dry-run et en exécution : c'est ce qui permet à la
        # simulation de reposer sur des données réelles.
        # statistiques : durée réelle de l'évaluation (apt update +
        # simulation apt), mesurée dans les DEUX modes mais enregistrée
        # uniquement en exécution réelle (identique dans les deux cas,
        # mais seul --execute doit alimenter les moyennes).
        _t_eval = time.time()
        self.client.apt_update(node)
        n_up, kernel_up, dl_b, inst_b, pve_up = \
            self.client.apt_upgrade_pending(node)
        if not self.dry:
            self.stats_new["apt_update_s"].append(
                round(time.time() - _t_eval, 1))

        # --- DIAGNOSTIC ESPACE DISQUE (chaque nœud, avec l'apt update) :
        # lecture pure (df + simulation apt), jouée aussi en dry-run.
        disks = self.client.disk_free(node)
        for mnt in ("/", "/var", "/boot/efi"):
            if mnt in disks:
                avail, total = disks[mnt]
                self.log.info(f"{node}: espace disque {mnt} — "
                              f"{gb(avail)} libres / {gb(total)} "
                              f"({avail / max(total, 1):.0%} libre)")

        reboot_only = False
        if n_up == 0:
            # REBOOT EN ATTENTE même sans paquets : cas d'un run précédent
            # interrompu (Ctrl-C / kill) APRÈS l'apt full-upgrade mais
            # AVANT le reboot. Sans cette détection, le nœud resterait
            # indéfiniment sur un noyau obsolète : le run suivant voit
            # « aucun paquet à mettre à jour » et saute le nœud, alors que
            # uname -r ≠ dernier noyau installé (vécu : v-testprox01 resté
            # sur 7.0.14-19-pve après un Ctrl-C au milieu du run du
            # 29/10). On planifie donc une maintenance complète
            # (évacuation + reboot) SANS upgrade.
            if not self.client.reboot_required(node):
                self.log.info(f"{node}: aucun paquet à mettre à jour, pas de "
                              f"reboot en attente — ni maintenance ni "
                              f"évacuation nécessaires ✔")
                return
            reboot_only = True
            self.log.warning(
                f"{node}: aucun paquet à mettre à jour MAIS un reboot est "
                f"en attente (noyau courant ≠ dernier installé, ou "
                f"/var/run/reboot-required — run précédent interrompu "
                f"avant le reboot ?) — maintenance planifiée : évacuation "
                f"puis reboot, SANS upgrade")
        # --- PORTE --skip-minor-updates (v19) : un nœud dont les seules
        # MAJ en attente sont des paquets Debian mineurs (aucun noyau, aucun
        # paquet pve-*/proxmox-*, aucun reboot en attente) est IGNORÉ
        # pour ce run : ni évacuation, ni upgrade, ni reboot. Cas
        # d'usage : reprise après incident — Debian publie des MAJ
        # mineures pendant un run de ~5 h, et chaque nœud déjà traité
        # se verrait sinon infliger une évacuation complète (~25 min)
        # pour quelques paquets sans importance.
        if (self.skip_minor and n_up > 0 and not reboot_only
                and not kernel_up and not pve_up
                and not self.client.reboot_required(node)):
            self.log.info(
                f"{node}: --skip-minor-updates : {n_up} paquet(s) Debian en "
                f"attente, mais AUCUN changement significatif (ni noyau, ni "
                f"paquet pve-*/proxmox-*, ni reboot en attente) — nœud "
                f"IGNORÉ : ni évacuation ni upgrade ni reboot. Les MAJ de "
                f"ce nœud restent en attente : relancer un run SANS "
                f"l'option pour les appliquer.")
            self.minor_skipped.append(node)
            return
        self.log.info(f"{node}: {n_up} paquet(s) à mettre à jour"
                      + (" — noyau inclus, reboot attendu après upgrade"
                         if kernel_up else "")
                      + (" — dont paquet(s) PVE (version pve-*/proxmox-*)"
                         if pve_up else ""))
        if self.dry:
            # bilan : apt update + simulation — SEULEMENT si CE nœud va
            # vraiment en maintenance (paquets OU reboot en attente) ;
            # un nœud sans rien à faire ne consomme que quelques secondes
            # de lectures (non comptées — hypothèse « par nœud maintenu »).
            self.est_clock += EST_APT_MIN * 60
            self.est_node_time += EST_APT_MIN * 60

        # --- GATE ESPACE DISQUE : refuser l'upgrade AVANT toute évacuation
        # si le disque risque de se remplir. Estimation prudente :
        # - / (ou fs racine de /var si séparé) doit absorber
        #   2× l'espace d'installation (fichiers installés + dépaquetage
        #   temporaire + ancien noyau conservé) + 1 GiB de marge ;
        # - /var (le cas échéant) doit absorber le téléchargement
        #   (archives apt) + 1 GiB de marge ; s'il est sur le même fs
        #   que /, tout est cumulé sur /.
        if disks:
            root_avail, root_total = disks.get("/", (0, 0))
            var_same_as_root = ("/var" not in disks
                                or disks["/var"] == disks["/"])
            var_avail, _vt = (root_avail, root_total) if var_same_as_root \
                else disks["/var"]
            margin = max(1024**3, int(0.05 * root_total))
            need_root = 2 * max(inst_b, 0) + margin \
                + (dl_b if var_same_as_root else 0)
            need_var = (dl_b + max(inst_b, 0) + margin
                        if not var_same_as_root else 0)
            ok_root = root_avail >= need_root
            ok_var = var_avail >= need_var
            self.log.info(
                f"{node}: espace requis estimé : {gb(need_root)} sur /"
                + (f" + {gb(need_var)} sur /var" if need_var else "")
                + f" — disponible : {gb(root_avail)} sur /"
                + (f", {gb(var_avail)} sur /var" if need_var else ""))
            if not ok_root or not ok_var:
                where = []
                if not ok_root:
                    where.append(f"/ ({gb(root_avail)} libres "
                                 f"< {gb(need_root)} requis)")
                if not ok_var:
                    where.append(f"/var ({gb(var_avail)} libres "
                                 f"< {gb(need_var)} requis)")
                raise RuntimeError(
                    f"{node}: espace disque INSUFFISANT pour l'upgrade "
                    f"({'; '.join(where)}). Nettoyez (apt clean, anciens "
                    f"noyaux, journaux) ou augmentez le disque AVANT de "
                    f"relancer — un apt qui remplit le fs racine en pleine "
                    f"migration peut corrompre le nœud. Aucune évacuation "
                    f"n'a été lancée.")
            self.log.info(f"{node}: espace disque suffisant pour l'upgrade ✔")

        # --- PHASE 1 : ÉVACUATION du nœud (détachement HA puis
        # migrations pilotées par le script selon les marges RAM).
        # Les plans de migration sont DISSOCIÉS de la phase
        # d'upgrade système (phase 2).
        banner(self.log, f"PHASE 1 — ÉVACUATION DE {node}", ColorFormatter.CYAN)
        print_occupancy_table(self.log, state, f"OCCUPATIONS — avant traitement de {node}",
                              highlight=node)
        # HYPERCONVERGENCE : Ceph doit être sain avant d'évacuer/rebooter.
        # Lecture pure : s'exécute aussi en dry-run.
        self.client.check_ceph_ready(node, "évacuation")

        # --- Ressources HA : détachées temporairement ('ignored') puis
        # migrées PAR LE SCRIPT (PVE < 9.2 : le CRM ne tient pas compte
        # de la charge lors des évacuations). Le mode maintenance reste
        # actif pour empêcher le CRM de placer quoi que ce soit sur le
        # nœud traité, et les ressources sont réactivées dans le
        # finally avec une fenêtre de stabilité CRM.
        ha_vmids = self.client.ha_vmids()
        src = state.nodes[node]
        ha_vms_here = [v for v in src.vms if v.vmid in ha_vmids]
        other_plans: List[Dict] = []
        # VMs stopped « laissées sur place » (garde-fou onboot appliqué,
        # avertissements émis par le helper) : exclues du plan, elles
        # restent sur le nœud pendant l'upgrade/reboot sans aucun risque.
        leave = self._stopped_to_leave(state, node)
        leave_ids = {v.vmid for v in leave}
        # stopped HA laissées sur place : détachées/réactivées comme les
        # autres (le mode maintenance relocaliserait leur entrée ressource)
        ha_left = [v for v in leave if v.vmid in ha_vmids]

        if self.dry:
            # ===== simulation : plan complet, VMs HA marquées =====
            # 2b-bis simulé : désactivation de TOUTES les règles
            # node-affinity (une seule fois par run) AVANT le plan —
            # état en mémoire vidé pour un plan RÉALISTE, réactivation
            # simulée à la fin de l'Étape 1.
            self._ha_rules_disable_all(state)
            sim = state.clone()
            if leave_ids:
                sim.nodes[node].vms = [v for v in sim.nodes[node].vms
                                       if v.vmid not in leave_ids]
            all_plans = plan_migrations(sim, sim.nodes[node], self.log)
            ha_plans = [p for p in all_plans if p["vm"].vmid in ha_vmids]
            other_plans = [p for p in all_plans if p["vm"].vmid not in ha_vmids]
            for p in all_plans:
                if p.get("off_rule"):
                    self.off_rule_vmids.add(p["vm"].vmid)
            print_migration_plan(self.log, all_plans,
                                 f"PLAN DE MIGRATION — vider {node}",
                                 ha_vmids=ha_vmids,
                                 ha_affinity=state.ha_affinity,
                                 ha_affinity_hard=state.ha_affinity_hard)
            # résumé explicite : qui est HA (donc détachée) et qui ne l'est pas
            n_detach = len(ha_plans) + len(ha_left)
            if n_detach:
                ha_desc = (f"{n_detach} ressource HA à détacher"
                           if n_detach == 1 else
                           f"{n_detach} ressources HA à détacher")
                ids = ([str(p["vm"].vmid) for p in ha_plans]
                       + [str(v.vmid) for v in ha_left])
                self.log.info(f"  Résumé : {len(all_plans)} guest(s) à "
                              f"migrer dont {ha_desc} en 'ignored' ("
                              + ", ".join(ids)
                              + f") et {len(other_plans)} guest(s) sans HA.")
            else:
                self.log.info(f"  Résumé : {len(all_plans)} guest(s) à "
                              f"migrer — AUCUNE ressource HA sur {node}, "
                              f"rien à détacher.")
            if leave:
                self.log.info(
                    f"  Stopped laissées sur place (aucune migration — "
                    f"elles ne courent aucun risque, reboot inclus) : "
                    + ", ".join(str(v) for v in leave))
            # mémoriser l'évacuation pour un éventuel rapatriement (--node)
            self.evacuated[node] = all_plans

            # ===== 2a) détachement HA — UNIQUEMENT s'il y a des HA =====
            if ha_plans or ha_left:
                self.log.info(f"[SIMULATION] 2a) Détachement HA : état "
                              f"'ignored' + label {PRU_LABEL} dans le "
                              f"comment — le CRM ne les gère plus")
                for v in [p["vm"] for p in ha_plans] + ha_left:
                    sid = self.client.ha_sids().get(v.vmid, f"vm:{v.vmid}")
                    orig = self.client.ha_resource_snapshot(sid)
                    self.log.info(f"[SIMULATION] 2a)    {sid} "
                                  f"({v.name}) : {orig['state']} → "
                                  f"ignored (état d'origine mémorisé)")
            else:
                self.log.info(f"[SIMULATION] 2a) Aucune ressource HA sur "
                              f"{node} — pas de détachement.")
            # ===== 2b) mode maintenance =====
            self.log.info(f"[SIMULATION] 2b) Mode maintenance de {node} "
                          f"(le CRM ne doit rien y placer)")
            src.in_maintenance = True

            # ===== diagnostic pré-migration (lecture PURE : guest agent
            # si présent, sinon qmpstatus/qemu — s'exécute DONC aussi en
            # dry-run). Inutile de rehearser la migration d'une VM
            # plantée : autant le savoir AVANT le run réel. =====
            # NB : en dry-run, l'état SIMULÉ peut déjà avoir déplacé des
            # VMs lors des nœuds précédents ; on interroge donc le nœud
            # RÉEL de chaque VM (GET /cluster/resources) et non le nœud
            # simulé p["from"] — sinon l'API répond « .conf does not
            # exist » pour une VM qui n'est pas là en réalité.
            real_nodes: Dict[int, str] = {}
            if all_plans:
                try:
                    for r in self.client.with_api(
                            lambda p: p.cluster.resources.get()):
                        if r.get("type") in ("qemu", "lxc"):
                            try:
                                real_nodes[int(r.get("vmid"))] = \
                                    r.get("node", "")
                            except (TypeError, ValueError):
                                continue
                except Exception as e:
                    self.log.warning(f"Placement réel des VMs illisible "
                                      f"({e}) — diagnostic dégradé.")
            if all_plans and real_nodes:
                self.log.info(f"Diagnostic des {len(all_plans)} guest(s) à "
                              f"migrer (lecture seule) :")
            dead = 0
            for p in all_plans:
                where = real_nodes.get(p["vm"].vmid, p["from"])
                if not self.client.vm_alive(where, p["vm"].vmid,
                                            p["vm"].vmtype,
                                            expect=p["vm"].status):
                    dead += 1
            if dead:
                self.log.warning(f"{dead} guest(s) à migrer sont dans un "
                                 f"état anormal — le run réel échouera sur "
                                 f"elles (vm_alive post-migration).")

            # ===== 2c) migrations =====
            if ha_plans:
                detached = (f"{len(ha_plans)} ressource HA détachée"
                            if len(ha_plans) == 1 else
                            f"{len(ha_plans)} ressources HA détachées")
                self.log.info(f"[SIMULATION] 2c) Migration des "
                              f"{len(all_plans)} guest(s) — dont {detached} "
                              f"— selon les marges RAM…")
            else:
                self.log.info(f"[SIMULATION] 2c) Migration des "
                              f"{len(all_plans)} guest(s) (aucune ressource "
                              f"HA) selon les marges RAM…")
            # Les cibles sont maintenant EXACTES (le script migre lui-même
            # les VMs HA détachées) : l'état simulé les applique, sinon le
            # nœud vidé continuerait d'afficher « 2 VMs / 0.0G » et la RAM
            # des cibles ne s'accumulerait pas pour les nœuds suivants.
            self._apply_migrations(all_plans, state)
            state.nodes[node].mem = 0
            state.nodes[node].cpu = 0.0
            print_occupancy_table(self.log, state,
                                  f"ÉTAT SIMULÉ APRÈS MIGRATION — {node} vidé"
                                  + (" (hors stopped laissées sur place)"
                                     if leave else ""),
                                  highlight=node, plans=all_plans)

            # ===== PHASE 2 : UPGRADE SYSTÈME (sans lien avec les plans) =====
            banner(self.log, f"PHASE 2 — UPGRADE SYSTÈME DE {node}",
                   ColorFormatter.CYAN)
            self.log.info(f"[SIMULATION] 2d) {node} : "
                          + ("reboot en attente (pas d'upgrade nécessaire)"
                             if reboot_only else
                             "apt-get full-upgrade -y "
                             "(montée de version mineure des paquets)"))
            if kernel_up or reboot_only:
                self.log.info(f"[SIMULATION] 2d) {node} : vérif noyau — "
                              f"reboot REQUIS (noyau dans la liste apt)")
                self.log.info(f"[SIMULATION] 2e) {node} : POST /nodes/{node}/status "
                              f"(command=reboot) puis attente du retour en ligne…")
            else:
                self.log.info(f"[SIMULATION] 2d) {node} : vérif noyau — "
                              f"pas de reboot requis (noyau absent de la liste apt)")
            if kernel_up or reboot_only:
                self.log.info(f"[SIMULATION] 2e) {node} : nœud de retour en ligne, "
                              f"quorum cluster OK (hypothèse simulation)")
                self.log.info(f"[SIMULATION] 2f) {node} : vérifications post-reboot — "
                              f"pvecm status (quorum), systemctl --failed, "
                              f"pveversion, syslog sans erreur : OK")
            self.log.info(f"[SIMULATION] Détection fencing sur les autres nœuds : "
                          f"aucune action détectée (hypothèse simulation)")
            # bilan : upgrade + reboot de CE nœud (inclut la fenêtre de
            # stabilité CRM 60s de la réactivation 2g)
            add = ((0.0 if reboot_only else EST_UPGRADE_MIN * 60)
                   + (EST_REBOOT_MIN * 60
                      if kernel_up or reboot_only else 0.0))
            self.est_clock += add
            self.est_node_time += add
            self.est_maint_nodes += 1
            if ha_plans or ha_left:
                detached = (f"{len(ha_plans) + len(ha_left)} ressource HA détachée"
                            if len(ha_plans) + len(ha_left) == 1 else
                            f"{len(ha_plans) + len(ha_left)} ressources HA détachées")
                self.log.info(f"[SIMULATION] 2g) Sortie de maintenance de "
                              f"{node} + réactivation des {detached} "
                              f"dans leur état d'origine (comment "
                              f"restauré) + fenêtre de stabilité CRM 60s")
                for v in [p["vm"] for p in ha_plans] + ha_left:
                    sid = self.client.ha_sids().get(v.vmid, f"vm:{v.vmid}")
                    orig = self.client.ha_resource_snapshot(sid)
                    off = any(p.get("off_rule") for p in ha_plans
                              if p["vm"].vmid == v.vmid)
                    if off:
                        self.log.info(
                            f"[SIMULATION] 2g)    {sid} "
                            f"({v.name}) : réactivation DIFFÉRÉE "
                            f"(repli hors règle strict=0) — reste "
                            f"'ignored' jusqu'à la fin du run")
                    else:
                        self.log.info(f"[SIMULATION] 2g)    {sid} "
                                      f"({v.name}) : ignored → "
                                      f"{orig['state']} (comment d'origine "
                                      f"restauré)")
            else:
                self.log.info(f"[SIMULATION] 2g) Sortie de maintenance de "
                              f"{node} — aucune ressource HA n'a été "
                              f"détachée sur ce nœud, rien à réactiver.")
            # 2g-bis simulé : règles node-affinity — réactivation à la
            # sortie de maintenance seulement en mode --node ; en run
            # complet elles restent désactivées jusqu'à la fin de
            # l'Étape 1 (miroir du mode réel).
            if self.only_node:
                self._ha_rules_restore_all(state)
            elif self.ha_rules_snapshot:
                self.log.info(f"[SIMULATION] 2g) {node}: règles "
                              f"node-affinity maintenues désactivées "
                              f"(réactivation à la fin de l'Étape 1).")
            src.in_maintenance = False
            src.status = "online"
            return

        # --- réel : détachement HA + migrations pilotées par le script ---
        # Les clusters cibles sont en PVE < 9.2 : pas de CRS dynamic, le
        # CRM ne tient PAS compte de la charge pour placer les ressources
        # évacuées (risque d'empilement de plusieurs VMs sur un même
        # nœud, proche du OOM). Le script prend donc la main :
        #   2a) snapshot des ressources HA du nœud (état + comment
        #       d'origine, persisté dans le fichier d'état) puis passage
        #       en 'ignored' avec le label PRU_LABEL — le CRM ne les
        #       gère plus (ni recovery, ni relocate) ;
        #   2b) mode maintenance du nœud : le CRM ne doit rien y placer
        #       non plus (recovery d'une VM d'un AUTRE nœud pendant le
        #       reboot, par exemple) ;
        #   2c) migration de TOUTES les VMs (HA comprises) selon les
        #       marges RAM du script + diagnostic post-migration ;
        #   2d-f) upgrade système + reboot + vérifications ;
        #   2g) finally : sortie de maintenance + réactivation des
        #       ressources HA dans leur état d'origine + fenêtre de
        #       stabilité CRM (il peut décider un relocate) — TOUJOURS,
        #       même sur incident.
        if ha_vms_here:
            self.log.info(f"{node}: détachement HA de {len(ha_vms_here)} "
                          f"VM(s) — état 'ignored', migrations pilotées "
                          f"par le script (label {PRU_LABEL})")
            ts = datetime.now().strftime("%Y-%m-%d %H:%M")
            # sid complet de chaque guest ('vm:<id>' OU 'ct:<id>' pour un
            # conteneur LXC en HA) :
            try:
                sid_of = self.client.ha_sids()
            except Exception:
                sid_of = {}
            for v in ha_vms_here:
                sid = sid_of.get(v.vmid, f"vm:{v.vmid}")
                if sid in self.ha_snapshot:
                    # ressource déjà détachée + mémorisée (repli hors
                    # règle d'un nœud précédent, réactivation différée)
                    # : NE PAS re-snapshotter — l'état courant est
                    # 'ignored' et écraserait l'état d'ORIGINE
                    # mémorisé ('started'...). Elle reste 'ignored'.
                    self.log.info(
                        f"  {sid} ({v.name}) : déjà détachée et mémorisée "
                        f"(réactivation différée — repli hors règle) — "
                        f"état d'origine préservé ✔")
                    continue
                orig = self.client.ha_resource_snapshot(sid)
                lbl = (f"{orig['comment']} — " if orig["comment"] else "")
                self.client.ha_set_resource(
                    sid, "ignored",
                    comment=f"{lbl}{PRU_LABEL} ignored temporaire "
                            f"(run {ts})")
                self.ha_snapshot[sid] = orig
                self._state_write()
                self.log.info(f"  {sid} ({v.name}) : "
                              f"{orig['state']} → ignored ✔ "
                              f"(état d'origine mémorisé)")
        else:
            self.log.info(f"{node}: aucune ressource HA sur ce nœud — "
                          f"pas de détachement nécessaire.")
        self.client.ha_maintenance_on(node)
        self.maintenance_nodes.append(node)
        # Persister IMMÉDIATEMENT : sans ce _state_write, le JSON reste
        # à jour du détachement HA mais n'indique PAS le nœud en
        # maintenance — si le script meurt pendant l'upgrade (long), le
        # run suivant ne sortirait pas ce nœud de maintenance.
        self._state_write()
        self.touched = True
        src.in_maintenance = True
        # 2b-bis) désactivation de TOUTES les règles node-affinity du
        # cluster (une seule fois par run) : le planning (2c) et le CRM
        # sont LIBRES de toute préférence/contrainte node-affinity
        # pendant TOUTE l'Étape 1 — réactivation à la fin de l'Étape 1,
        # avant le rapatriement/rééquilibrage (run complet) ou à la
        # sortie de maintenance du nœud (mode --node).
        self._ha_rules_disable_all(state)

        try:
            # 2c) plan puis migrations réelles : les ressources HA sont
            # 'ignored', le script peut les déplacer comme des VMs
            # ordinaires (qm migrate live) ; les VMs stopped « laissées
            # sur place » (garde-fou onboot appliqué) sont EXCLUES du
            # plan — elles restent sur le nœud pendant l'upgrade/reboot.
            sim = state.clone()
            if leave_ids:
                sim.nodes[node].vms = [v for v in sim.nodes[node].vms
                                       if v.vmid not in leave_ids]
            plans = plan_migrations(sim, sim.nodes[node], self.log)
            plan_title = (f"PLAN DE MIGRATION — vider {node} "
                          f"(dont {len(ha_vms_here)} "
                          + ("ressource HA détachée)"
                             if len(ha_vms_here) == 1 else
                             "ressources HA détachées)")) if ha_vms_here else \
                          f"PLAN DE MIGRATION — vider {node} " \
                          f"(aucune ressource HA)"
            print_migration_plan(self.log, plans, plan_title,
                                 ha_vmids=state.ha_vmids,
                                 ha_affinity=state.ha_affinity,
                                 ha_affinity_hard=state.ha_affinity_hard)
            if leave:
                self.log.info(
                    f"  Stopped laissées sur place (aucune migration — "
                    f"elles ne courent aucun risque, reboot inclus) : "
                    + ", ".join(str(v) for v in leave))
            self.evacuated[node] = plans
            for p in plans:
                if p.get("off_rule"):
                    self.off_rule_vmids.add(p["vm"].vmid)
            self._apply_migrations(plans, state)
            state.nodes[node].mem = 0
            state.nodes[node].cpu = 0.0
            # occupation APRÈS les migrations : preuve que le nœud est
            # vidé avant de toucher au système
            print_occupancy_table(self.log, state,
                                  f"OCCUPATIONS — après migration ({node} vidé"
                                  + (", hors stopped laissées sur place)"
                                     if leave else ")"),
                                  highlight=node, plans=plans)

            # ===== PHASE 2 : UPGRADE SYSTÈME (dissociée de l'évacuation) =====
            banner(self.log, f"PHASE 2 — "
                   + ("REBOOT EN ATTENTE" if reboot_only else "UPGRADE SYSTÈME")
                   + f" DE {node}", ColorFormatter.CYAN)
            # per-nœud : le marqueur de début de reboot est remis à
            # zéro (un résidu du nœud précédent ne doit pas créer un
            # échantillon 'reboot_s' fantôme sur un nœud sans reboot).
            self._reboot_t0 = 0.0
            if reboot_only:
                self.log.info(f"{node}: apt full-upgrade Sauté — aucun "
                              f"paquet à mettre à jour, seul le reboot du "
                              f"noyau en attente est traité")
            else:
                _t_up = time.time()
                self.client.apt_upgrade(node)
                if not self.dry:
                    self.stats_new["apt_upgrade_s"].append(
                        round(time.time() - _t_up, 1))
            if self.client.reboot_required(node):
                # le nœud va tomber : re-contrôle Ceph (l'upgrade a pu
                # durer longtemps, un recovery a pu démarrer entre-temps)
                self.client.check_ceph_ready(node, "reboot")
                # 2d-bis) FLAGS DE MAINTENANCE CEPH : reboot PLANIFIÉ —
                # on maîtrise la fenêtre, le cluster ne reconstruit PAS
                # (pas de marquage 'out' → pas de backfill puis de
                # rebalancement en retour). Persister AVANT le reboot :
                # si le run meurt pendant la fenêtre, le run suivant
                # retirera les flags via le fichier d'état.
                newly = self.client.ceph_maintenance_on(node)
                if newly:
                    self.ceph_flags.update(newly)
                    self._state_write()
                # 2e) reboot + attente du retour
                self._reboot_t0 = time.time()
                self.client.reboot_node(node)
                self.client.wait_node_back(node)
                # 2e-bis) fenêtre de reboot TERMINÉE : le nœud est de
                # retour — on retire les flags de maintenance Ceph
                # MAINTENANT, AVANT les checks post-reboot. Sans ça,
                # l'attente HEALTH_OK de 2f-bis ne peut JAMAIS aboutir :
                # nos propres flags maintiennent OSDMAP_FLAGS en
                # HEALTH_WARN, et norecover/nobackfill bloquent la
                # reprise des PGs dégradées (vécu : run du 29/10, 2f-bis
                # en échec 300s après un reboot pourtant sain). Le
                # finally 2g-0 reste en filet de sécurité : il ne
                # retirera que les flags restants (échec SSH, etc.).
                if self.ceph_flags:
                    removed = self.client.ceph_maintenance_off(
                        self.ceph_flags,
                        [node] + [n for n in state.nodes if n != node])
                    for f in (removed or []):
                        self.ceph_flags.pop(f, None)
                    self._state_write()
            else:
                if reboot_only:
                    raise RuntimeError(
                        f"{node}: incohérence — reboot requis détecté en "
                        f"évaluation mais plus en phase 2. État du nœud "
                        f"incohérent, abandon.")
                self.log.info(f"{node}: pas de reboot requis.")

            # fencing pendant la maintenance de ce nœud ? (toujours phase 2)
            others = [n for n in state.nodes if n != node]
            self._watch_fencing_or_die(others, f"maintenance {node}")

            # 2f) vérifications post-reboot
            if not self.client.post_boot_checks(node):
                raise RuntimeError(f"Les vérifications post-reboot de {node} ont échoué.")
            # statistiques : séquence reboot complète (reboot → retour
            # en ligne → quorum → post-checks), uniquement si un reboot
            # a VRAIMENT eu lieu sur ce nœud pendant ce run.
            if not self.dry and getattr(self, "_reboot_t0", 0):
                self.stats_new["reboot_s"].append(
                    round(time.time() - self._reboot_t0, 1))
                self._reboot_t0 = 0

        finally:
            # INTERRUPTION UTILISATEUR (Ctrl-C) pendant le traitement de
            # ce nœud : NE PAS restaurer l'état zéro. Contrairement à
            # une erreur du script (nœud sain, on rend l'état zéro au
            # cluster), un Ctrl-C pendant l'upgrade/reboot peut
            # interrompre apt au milieu d'un dpkg (paquets à moitié
            # configurés, noyau neuf pas encore booté) : rendre ce nœud
            # au CRM (sortie maintenance + réactivation HA) pourrait
            # l'y faire replacer des VMs sur un nœud incohérent. On
            # FIGE donc l'état actuel — maintenance conservée,
            # ressources HA laissées 'ignored' — entièrement suivi par
            # le fichier d'état : le prochain run reprendra via
            # l'Étape 0 (après « dpkg --configure -a », fait
            # automatiquement par apt_update).
            if isinstance(sys.exc_info()[1], KeyboardInterrupt):
                self._state_write()
                self.log.critical(
                    f"Interruption utilisateur pendant le traitement "
                    f"de {node} — ÉTAT FIGÉ : le nœud RESTE en "
                    f"maintenance et ses ressources HA en 'ignored' "
                    f"(volontairement : un apt interrompu peut laisser "
                    f"des paquets à moitié configurés). Le prochain "
                    f"run reprendra proprement (Étape 0 + "
                    f"« dpkg --configure -a » automatique).")
                raise
            # 2g-0) FLAGS CEPH : retirés en TOUT ÉTAT DE CAUSE (même sur
            # incident, même upgrade raté : le cluster doit reprendre
            # son fonctionnement nominal — c'est le but recherché par
            # Nicolas, que Ceph reconstruise même si l'upgrade n'a pas
            # abouti). Les flags sont globaux : on tente le nœud traité,
            # puis les autres s'il est injoignable.
            if self.ceph_flags:
                try:
                    removed = self.client.ceph_maintenance_off(
                        self.ceph_flags,
                        [node] + [n for n in state.nodes if n != node])
                except Exception as e:
                    self.log.error(f"Flags Ceph non retirés ({e}) — ils "
                                   f"resteront dans le fichier d'état, "
                                   f"le prochain run les retirera.")
                else:
                    for f in removed:
                        self.ceph_flags.pop(f, None)
                    self._state_write()
            # 2g) sortie de maintenance + réactivation des ressources HA —
            # TOUJOURS tentées, même sur incident (l'état zéro doit être
            # restauré). En cas d'échec, le fichier d'état permet au run
            # suivant de finir le travail.
            try:
                self.client.ha_maintenance_off(node)
            except Exception as e:
                self.log.error(f"Sortie de maintenance de {node} "
                               f"impossible ({e}) — vérifiez manuellement.")
            if node in self.maintenance_nodes:
                self.maintenance_nodes.remove(node)
                # persister immédiatement : le fichier doit refléter la
                # sortie de maintenance de ce nœud (règle : TOUTE mutation
                # de l'état zéro est suivie d'un _state_write — sinon le
                # fichier peut garder un nœud en maintenance qui n'y est
                # plus si le run meurt juste après).
                self._state_write()
            src.in_maintenance = False
            src.status = "online"
            # 2g-bis) règles node-affinity : en mode --node, la fin
            # d'Étape 1 EST la sortie de maintenance de CE nœud →
            # réactivation AVANT la réactivation des ressources HA
            # (le CRM applique la préférence dès la réactivation :
            # failback ATTENDU, pas une anomalie). En run complet,
            # elles restent désactivées jusqu'à la fin de l'Étape 1
            # (sinon le CRM re-déciderait des relocate à CHAQUE sortie
            # de maintenance, en pleine évacuation du nœud suivant).
            if self.only_node:
                self._ha_rules_restore_all(state)
            elif self.ha_rules_snapshot:
                self.log.info(f"{node}: règles node-affinity maintenues "
                              f"désactivées (fin de l'Étape 1) — pas de "
                              f"relocate CRM en pleine évacuation.")
            restored = []
            deferred_here: List[str] = []
            for sid, orig in list(self.ha_snapshot.items()):
                try:
                    sid_vmid: Optional[int] = None
                    try:
                        sid_vmid = int(str(sid).split(":", 1)[1])
                    except (ValueError, IndexError):
                        pass
                    if (sid_vmid in self.off_rule_vmids
                            and not self.only_node):
                        # repli hors règle (strict=0) : réactivation
                        # DIFFÉRÉE à la fin du run — le CRM la
                        # re-migrerait immédiatement vers ses nœuds
                        # préférés (churn en pleine évacuation des
                        # nœuds suivants). Reste 'ignored' : sans
                        # protection HA jusqu'au dégel final (assumé ;
                        # le fichier d'état couvre une interruption).
                        deferred_here.append(sid)
                        if sid not in self._off_rule_deferred_logged:
                            self._off_rule_deferred_logged.add(sid)
                            self.log.warning(
                                f"  {sid} : réactivation DIFFÉRÉE (repli "
                                f"hors règle strict=0 — le CRM la "
                                f"rapatrierait immédiatement) : reste "
                                f"'ignored' jusqu'à la fin du run.")
                        else:
                            self.log.info(
                                f"  {sid} : réactivation toujours "
                                f"différée (repli hors règle) ✔")
                        continue
                    if sid_vmid in self.off_rule_vmids and self.only_node:
                        self.log.warning(
                            f"  {sid} : réactivation normale (mode --node) "
                            f"mais repli hors règle (strict=0) de ce run : "
                            f"le CRM peut la re-migrer vers ses nœuds "
                            f"préférés — c'est attendu.")
                    # NB : on passe le comment TEL QUEL, même vide ("") :
                    # None = "ne pas toucher" et laisserait le label
                    # [proxmox-rolling-update] en place ; "" l'efface.
                    self.client.ha_set_resource(
                        sid, orig.get("state", "started"),
                        comment=orig.get("comment", ""))
                    restored.append(sid)
                    del self.ha_snapshot[sid]
                    self._state_write()
                    self.log.info(f"  {sid} : ignored → "
                                  f"{orig.get('state', 'started')} ✔ "
                                  f"(comment d'origine restauré)")
                except Exception as e:
                    self.log.error(f"Ressource {sid} : réactivation "
                                   f"IMPOSSIBLE ({e}) — elle reste en "
                                   f"'ignored', le prochain run la "
                                   f"réactivera via le fichier d'état.")
            if deferred_here:
                self.log.warning(
                    f"{len(set(deferred_here))} ressource(s) HA différée(s) "
                    f"(repli hors règle) reste(nt) 'ignored' — sans "
                    f"protection HA pendant le traitement des nœuds "
                    f"restants ; le dégel final les réactivera.")
            if restored:
                self.log.info(f"Ressources HA réactivées "
                              f"({', '.join(restored)}) — le CRM reprend "
                              f"la main")
                try:
                    # le CRM peut décider un relocate pour satisfaire les
                    # règles : attendre qu'il n'ait plus RIEN en cours
                    # avant de passer au nœud suivant.
                    self.client.wait_ha_settled()
                except Exception as e:
                    self.log.warning(f"Fenêtre de stabilité post-"
                                     f"réactivation : {e}")
            elif not self.ha_snapshot:
                self.log.info(f"{node}: aucune ressource HA n'a été "
                              f"détachée sur ce nœud — rien à réactiver.")
            # 2g-ter) ONBOOT SUSPENDUS (garde-fou v20) : restaurer la
            # valeur d'origine des guests stopped à disques LOCAUX
            # laissés sur place sur CE nœud. Toujours tenté (même sur
            # incident) : un onboot resté à 0 ferait silencieusement
            # rater le boot du guest au prochain reboot — en cas d'échec
            # l'entrée RESTE dans le fichier d'état, le prochain run la
            # restaurera (même mécanisme que les ressources HA).
            for key, ent in list(self.onboot_suspended.items()):
                if ent.get("node") != node:
                    continue        # guest d'un AUTRE nœud : pas ici
                try:
                    self.client.vm_set_onboot(
                        node, int(ent["vmid"]), ent.get("vmtype", "qemu"),
                        bool(int(ent.get("onboot", 1))))
                    del self.onboot_suspended[key]
                    self._state_write()
                    self.log.info(f"  {key} : 'onboot' restauré à "
                                  f"{int(ent.get('onboot', 1))} ✔")
                except Exception as e:
                    self.log.error(
                        f"  {key} : restauration de 'onboot' IMPOSSIBLE "
                        f"({e}) — l'entrée reste dans le fichier d'état, "
                        f"le prochain run la restaurera. Sans elle, le "
                        f"guest ne démarrera PAS au prochain boot du "
                        f"nœud.")

    def restore_vms(self, node: str):
        """Mode --node : rapatrie sur le nœud traité les VMs qui ont été
        évacuées au début de son traitement, dans la mesure où la capacité
        (RAM max avec marge, CPU) le permet. Les VMs non rapatriables restent
        sur leur hôte d'accueil, avec un warning explicite."""
        plans = self.evacuated.get(node, [])
        if not plans:
            self.log.info(f"Aucune VM n'a été évacuée de {node} — rien à rapatrier.")
            return
        banner(self.log, f"RAPATRIEMENT DES VMs VERS {node} "
               f"({self.client.node_addr.get(node, '?')})", ColorFormatter.GREEN)
        state = self.state
        back_plans: List[Dict] = []
        skipped: List[str] = []
        tgt = state.nodes[node]
        # Σ RAM déclarée déjà rapatriée dans CE plan : sert au contrôle
        # de capacité SANS pré-muter tgt.mem — _apply_migrations fera
        # l'incrémentation réelle UNE seule fois (l'ancienne
        # pré-mutation doublait la charge des VMs rapatriées).
        declared_back = 0
        for p in plans:
            vm = p["vm"]                    # vmid de la VM évacuée
            current = p["to"]              # hôte d'accueil actuel
            if vm.vmid in state.ha_vmids:
                skipped.append(f"VM {vm.vmid} ({vm.name}) : ressource HA — "
                               f"rapatriement géré par le CRM (règles "
                               f"d'affinité/failback)")
                continue
            # le nœud est-il de retour avec la capacité suffisante ?
            # (marge réelle MOINS les retours déjà planifiés ici)
            if vm.maxmem > tgt.ram_free_margin() - declared_back:
                skipped.append(f"VM {vm.vmid} ({vm.name}) : RAM max {gb(vm.maxmem)} "
                               f"> marge libre "
                               f"{gb(tgt.ram_free_margin() - declared_back)} sur {node}")
                continue
            declared_back += vm_load(vm)   # pression : running uniquement
            back_plans.append({"vm": vm, "from": current, "to": node,
                               # pression DÉCLARÉE cumulée du nœud
                               # restauré (vms pas encore re-appendées)
                               "target_mem_after": declared_load(tgt)
                                                   + declared_back,
                               "target_maxmem": tgt.maxmem})
        print_migration_plan(self.log, back_plans,
                             f"PLAN DE RAPATRIEMENT — {node}",
                             ha_vmids=state.ha_vmids)
        self._apply_migrations(back_plans, state)
        for s in skipped:
            self.log.warning(f"Non rapatriée — {s} (la VM reste sur son hôte d'accueil)")

    def _ha_freeze_all(self) -> int:
        """Rééquilibrage : détache TOUTES les ressources HA du cluster en
        état 'ignored' (gel CRM : le CRM ne fait RIEN — ni recovery,
        ni relocate). NB : l'état natif 'freeze' de PVE est INTERNE au
        CRM (il n'est pas assignable via l'API ha-manager : l'énum
        acceptée est started/stopped/enabled/disabled/ignored), on
        utilise donc 'ignored' — même mécanique éprouvée que le
        détachement de l'Étape 1. Le script est alors seul maître à
        bord pour les migrations live : aucune collision possible avec
        le CRM/LRM. Snapshot état+comment mémorisé (fichier d'état)
        pour pouvoir restaurer, même sur run interrompu."""
        try:
            sid_of = self.client.ha_sids()
        except Exception:
            sid_of = {}
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        n = 0
        for vmid in sorted(self.state.ha_vmids):
            sid = sid_of.get(vmid, f"vm:{vmid}")
            if sid in self.ha_snapshot:
                continue          # déjà mémorisée (reprise de run interrompu)
            orig = self.client.ha_resource_snapshot(sid)
            lbl = (f"{orig['comment']} — " if orig["comment"] else "")
            self.client.ha_set_resource(
                sid, "ignored",
                comment=f"{lbl}{PRU_LABEL} gel CRM temporaire (run {ts})")
            self.ha_snapshot[sid] = orig
            self._state_write()
            self.touched = True
            self.log.info(f"  {sid} : {orig['state']} → 'ignored' (gel CRM) ✔ "
                          f"(état d'origine mémorisé)")
            n += 1
        return n

    def _ha_restore_frozen(self) -> None:
        """Fin du rééquilibrage : restaure les ressources HA gelées dans
        leur état d'origine (state + comment), puis attend que le CRM
        n'ait plus rien en cours."""
        restored = []
        off_rule_restored: List[str] = []
        for sid, orig in list(self.ha_snapshot.items()):
            try:
                try:
                    sid_vmid = int(str(sid).split(":", 1)[1])
                except (ValueError, IndexError):
                    sid_vmid = None
                off_rule = sid_vmid in self.off_rule_vmids
                # comment passé TEL QUEL, même vide ("" l'efface, None
                # laisserait le label [proxmox-rolling-update] en place)
                self.client.ha_set_resource(
                    sid, orig.get("state", "started"),
                    comment=orig.get("comment", ""))
                restored.append(sid)
                del self.ha_snapshot[sid]
                self._state_write()
                if off_rule:
                    off_rule_restored.append(sid)
                    self.log.info(
                        f"  {sid} : 'ignored' → "
                        f"{orig.get('state', 'started')} ✔ — réactivation "
                        f"différée (repli hors règle) : le CRM va "
                        f"probablement la rapatrier vers ses nœuds "
                        f"préférés (strict=0) : ATTENDU, pas une anomalie.")
                else:
                    self.log.info(f"  {sid} : 'ignored' (gel CRM) → "
                                  f"{orig.get('state', 'started')} ✔ "
                                  f"(comment d'origine restauré)")
            except Exception as e:
                self.log.error(f"Ressource {sid} : dégel IMPOSSIBLE ({e}) "
                               f"— elle reste détachée ('ignored'), le "
                               f"prochain run la restaurera via le "
                               f"fichier d'état.")
        if restored:
            self.log.info("Ressources HA dégélées — le CRM/LRM reprennent "
                          "la main. (L'attente de stabilité CRM est faite "
                          "une SEULE fois en fin de run, pas ici.)")
        if off_rule_restored:
            self.log.warning(
                f"{len(off_rule_restored)} ressource(s) repliée(s) hors "
                f"règle d'affinité (strict=0) viennent d'être réactivée(s) "
                f"({', '.join(off_rule_restored)}) : le CRM peut les "
                f"rapatrier vers leurs nœuds préférés — comportement "
                f"ATTENDU, pas une anomalie.")

    def rebalance(self):
        banner(self.log, "ÉTAPE 2 — Rééquilibrage final du cluster")
        # Les VMs HA ont été RÉACTIVÉES en fin d'Étape 1 (2g) : le CRM/LRM
        # sont de nouveau actifs. Le rééquilibrage migre des VMs HA en
        # live : le CRM pourrait décider un relocate/recovery en pleine
        # migration (politique de répartition du CRM, action différée
        # d'une 2g, ...). On gèle donc TOUTES les ressources HA du
        # cluster ('ignored' = détachement temporaire), on rééquilibre, puis on
        # restaure les états d'origine — TOUJOURS, même sur incident
        # (finally), via le même snapshot/fichier d'état que l'Étape 1.
        if self.dry:
            sim = self.state.clone()
            failback_plans = plan_off_rule_failback(
                sim, self.log, set(self.off_rule_vmids))
            plans = plan_rebalance(sim, self.log)
            self.state.theoretical_gap = sim.theoretical_gap
            if failback_plans:
                print_migration_plan(
                    self.log, failback_plans,
                    "PLAN DE RAPATRIEMENT HORS-RÈGLE (SIMULATION)",
                    ha_vmids=self.state.ha_vmids,
                    ha_affinity=self.state.ha_affinity,
                    ha_affinity_hard=self.state.ha_affinity_hard,
                    ha_live=True)
            print_migration_plan(self.log, plans, "PLAN DE RÉÉQUILIBRAGE (SIMULATION)",
                                 ha_vmids=self.state.ha_vmids,
                                 ha_affinity=self.state.ha_affinity,
                                 ha_affinity_hard=self.state.ha_affinity_hard,
                                 ha_live=True)
            if not plans and not failback_plans:
                # MIROIR du mode réel : rien à migrer = le CRM n'est PAS
                # gelé (et la fenêtre de stabilité finale est sautée, le
                # run n'ayant rien touché) — PAS de 60s à estimer.
                self.log.info("[SIMULATION] [rebalance] Aucune migration "
                              "nécessaire — le CRM n'est pas gelé.")
            else:
                self.log.info("[SIMULATION] 3a) Gel CRM : "
                              + str(len(self.state.ha_vmids))
                              + " ressource(s) HA détachée(s) en 'ignored' "
                              "le temps du rééquilibrage")
                if failback_plans:
                    self._apply_migrations(failback_plans, self.state,
                                           ha_live=True)
                    for p in failback_plans:
                        self.off_rule_vmids.discard(p["vm"].vmid)
                        self.off_rule_returned.add(p["vm"].vmid)
                    self.log.info("[SIMULATION] 3a+) Rapatriement des "
                                  "ressources hors règle (repli strict=0 "
                                  "ou déplacement pendant le sommeil des "
                                  "règles) vers leurs nœuds de règle ✔ — "
                                  "dégel final cohérent, le CRM n'aura "
                                  "rien à corriger")
                self._apply_migrations(plans, self.state, ha_live=True)
                # SECONDE PASSE de rapatriement : le rééquilibrage vient
                # de déplacer de la charge — il a pu LIBÉRER un nœud de
                # règle qui était saturé au moment de la 1re passe (cas
                # réel RHOSPDC : les DUREs 101/103 échouaient AVANT le
                # rééquilibrage, leurs nœuds de règle (pes/c4) reprenaient
                # de la place JUSTE APRÈS, libérée par les migrations du
                # rééquilibrage). On rejoue donc le rapatriement TOUJOURS
                # dans la fenêtre de gel, avant le dégel : sans cela, le
                # CRM relocaliserait ces DUREs AU dégel (churn hors
                # fenêtre, exactement ce que le rapatriement évite).
                sim2 = self.state.clone()
                second = plan_off_rule_failback(sim2, self.log,
                                                set(self.off_rule_vmids),
                                                second_pass=True)
                if second:
                    print_migration_plan(
                        self.log, second,
                        "PLAN DE RAPATRIEMENT HORS-RÈGLE — SECONDE PASSE "
                        "(post-rééquilibrage) (SIMULATION)",
                        ha_vmids=self.state.ha_vmids,
                        ha_affinity=self.state.ha_affinity,
                        ha_affinity_hard=self.state.ha_affinity_hard,
                        ha_live=True)
                    self._apply_migrations(second, self.state, ha_live=True)
                    for p in second:
                        self.off_rule_vmids.discard(p["vm"].vmid)
                        self.off_rule_returned.add(p["vm"].vmid)
                    self.log.info(
                        "[SIMULATION] 3a+ bis) Seconde passe de "
                        "rapatriement (post-rééquilibrage) : la place "
                        "libérée par le rééquilibrage a permis de ramener "
                        "les ressources restées hors règle à la 1re "
                        "passe — dégel final sans relocalisation CRM ✔")
                self.log.info("[SIMULATION] 3b) Dégel CRM : ressources HA "
                              "restaurées dans leur état d'origine + fenêtre "
                              "de stabilité CRM 60s")
                # bilan : fenêtre de stabilité CRM finale (le
                # wait_ha_settled de fin de run — sauté en réel si le run
                # n'a rien touché, donc sauté ici aussi)
                self.est_clock += 60.0
                self.est_crm_time += 60.0
        else:
            # Garde Ceph MINIMALE pour le rééquilibrage : les migrations
            # live ne font perdre AUCUN daemon Ceph (pas de reboot) et un
            # mon down avec quorum conservé (ex. 2/3) laisse l'IO RBD
            # opérationnel — HEALTH_WARN est donc toléré ici, contraire-
            # ment à l'Étape 1 où la gate exige HEALTH_OK avant
            # évacuation/upgrade/reboot. En revanche, un cluster en
            # HEALTH_ERR (ou pire) ne peut pas servir l'IO de façon
            # fiable : on refuse avant de geler le CRM.
            try:
                cst = self.client.ceph_status()
            except Exception:
                cst = None
            if cst is not None:
                chealth, ignored = self.client.ceph_effective_health(cst)
                if ignored:
                    self.client.ceph_log_auth_insecure(ignored)
                if chealth not in ("HEALTH_OK", "HEALTH_WARN"):
                    raise RuntimeError(
                        f"Ceph est en {chealth} — rééquilibrage REFUSÉ : "
                        f"les migrations live ont besoin d'un stockage "
                        f"opérationnel (quorum mon, IO RBD). Corrigez "
                        f"Ceph et relancez.")
                allow_warn = str(_env("PVE_CEPH_ALLOW_WARN", "0")) == "1"
                if chealth == "HEALTH_WARN":
                    self.client.ceph_diagnose(cst)
                    if not allow_warn:
                        self.log.warning(
                            "[rebalance] Ceph en HEALTH_WARN — "
                            "rééquilibrage SAUTÉ : on ne migre pas des "
                            "VMs RBD par-dessus un cluster dégradé sans "
                            "accord explicite. Réparez Ceph (ou posez "
                            "PVE_CEPH_ALLOW_WARN=1 pour tolérer, à vos "
                            "risques) et relancez : le cluster reste "
                            "simplement dans son état actuel, aucune "
                            "incohérence.")
                        self.log.info("[rebalance] Rééquilibrage sauté "
                                      "(Ceph en HEALTH_WARN).")
                        return
                    self.log.warning(
                        "[rebalance] Ceph en HEALTH_WARN — toléré pour "
                        "les migrations live (PVE_CEPH_ALLOW_WARN=1 : "
                        "aucun reboot, aucun daemon Ceph ne descend). "
                        "NB : la gate HEALTH_OK reste exigée pour "
                        "l'évacuation/upgrade/reboot des nœuds "
                        "(Étape 1).")
            sim = self.state.clone()
            failback_plans = plan_off_rule_failback(
                sim, self.log, set(self.off_rule_vmids))
            plans = plan_rebalance(sim, self.log)
            self.state.theoretical_gap = sim.theoretical_gap
            if failback_plans:
                print_migration_plan(
                    self.log, failback_plans,
                    "PLAN DE RAPATRIEMENT HORS-RÈGLE",
                    ha_vmids=self.state.ha_vmids,
                    ha_affinity=self.state.ha_affinity,
                    ha_affinity_hard=self.state.ha_affinity_hard,
                    ha_live=True)
            print_migration_plan(self.log, plans, "PLAN DE RÉÉQUILIBRAGE",
                                 ha_vmids=self.state.ha_vmids,
                                 ha_affinity=self.state.ha_affinity,
                                 ha_affinity_hard=self.state.ha_affinity_hard,
                                 ha_live=True)
            if not plans and not failback_plans:
                self.log.info("[rebalance] Aucune migration nécessaire — "
                              "le CRM n'est pas gelé.")
            else:
                self.log.info(f"[rebalance] Gel CRM : les "
                              f"{len(self.state.ha_vmids)} "
                              f"ressource(s) HA passent en 'ignored' "
                              f"(gel CRM) — le CRM ne touche à rien "
                              f"pendant le rééquilibrage")
                self._ha_freeze_all()
                try:
                    if failback_plans:
                        self.log.info(
                            "[rebalance] Rapatriement des ressources "
                            "hors règle (repli strict=0 ou déplacement "
                            "pendant le sommeil des règles) vers leurs "
                            "nœuds de règle — AVANT le rééquilibrage, "
                            "pour un dégel final cohérent")
                        self._apply_migrations(failback_plans, self.state,
                                               ha_live=True)
                        # ne retirer du différé QUE si la migration a
                        # réussi (sinon exception : reste différée ✔)
                        for p in failback_plans:
                            self.off_rule_vmids.discard(p["vm"].vmid)
                            self.off_rule_returned.add(p["vm"].vmid)
                    if plans:
                        self._apply_migrations(plans, self.state,
                                               ha_live=True)
                    # SECONDE PASSE de rapatriement (post-rééquilibrage,
                    # même fenêtre de gel, cf. branche dry) : le
                    # rééquilibrage peut avoir LIBÉRÉ le nœud de règle
                    # saturé qui avait fait échouer la 1re passe — sans
                    # cette passe, le CRM relocaliserait ces DUREs AU
                    # dégel (churn hors fenêtre de gel).
                    sim2 = self.state.clone()
                    second = plan_off_rule_failback(sim2, self.log,
                                                    set(self.off_rule_vmids),
                                                    second_pass=True)
                    if second:
                        print_migration_plan(
                            self.log, second,
                            "PLAN DE RAPATRIEMENT HORS-RÈGLE — SECONDE "
                            "PASSE (post-rééquilibrage)",
                            ha_vmids=self.state.ha_vmids,
                            ha_affinity=self.state.ha_affinity,
                            ha_affinity_hard=self.state.ha_affinity_hard,
                            ha_live=True)
                        self.log.info(
                            "[rebalance] Seconde passe de rapatriement "
                            "(post-rééquilibrage) : la place libérée par "
                            "le rééquilibrage permet de ramener les "
                            "ressources restées hors règle à la 1re "
                            "passe — AVANT le dégel, pour que le CRM "
                            "n'ait rien à corriger")
                        self._apply_migrations(second, self.state,
                                               ha_live=True)
                        # ne retirer du différé QUE si la migration a
                        # réussi (sinon exception : reste différée ✔)
                        for p in second:
                            self.off_rule_vmids.discard(p["vm"].vmid)
                            self.off_rule_returned.add(p["vm"].vmid)
                finally:
                    self.log.info("[rebalance] Dégel CRM : restauration "
                                  "des ressources HA dans leur état "
                                  "d'origine")
                    self._ha_restore_frozen()

    # ---------- BILAN DRY-RUN : durée, migrations, risques ---------------
    def estimation_report(self) -> None:
        """Bilan de fin de dry-run, pour évaluer AVANT l'exécution réelle :
        - durée approximative du run (horloge simulée : migrations + apt +
          upgrade + reboot + fenêtres de stabilité CRM) ;
        - nombre de migrations et RAM totale transférée ;
        - fenêtres de NON-RESPECT des règles d'anti-affinité « keep
          separate » : quand deux membres d'un groupe « à garder séparés »
          cohabitent sur un même nœud (repli soft, strict=0), l'impact
          d'une panne de ce nœud pendant la fenêtre est multiplié.
        Les fenêtres sont reconstituées en rejouant la chronologie des
        migrations depuis les placements initiaux."""
        state = self.state
        n_mig = len(self.mig_events)
        ram_tot = sum(e["ram"] for e in self.mig_events)

        _dur, _mark = _est_hms, _est_mark

        banner(self.log, "BILAN D'ESTIMATION (DRY-RUN)", ColorFormatter.GREEN)
        # « rien à faire » : ni maintenance ni migration planifiée — la
        # durée réelle du run sera celle des vérifications seules (non
        # comptée) ; les détails/hypothèses seraient tous ~0 et hors
        # sujet : affichage réduit.
        nothing = (self.est_maint_nodes == 0 and n_mig == 0)
        if nothing:
            self.log.info(
                f"Durée totale approximative : ~{_dur(self.est_clock)} — "
                f"{self.est_maint_nodes} nœud(s) avec maintenance complète")
            self.log.info(
                "  rien à faire : ni maintenance ni migration planifiée — "
                "la durée réelle du run sera celle des vérifications "
                "seules (non comptée)")
        else:
            self.log.info(
                f"Durée totale approximative : ~{_dur(self.est_clock)} (±30% : "
                f"hypothèses ci-dessous) — {self.est_maint_nodes} nœud(s) "
                f"avec maintenance complète")
            self.log.info(
                f"  détail : migrations ~{_dur(self.est_mig_time)}")
            self.log.info(
                f"  détail : apt/upgrade/reboot ~{_dur(self.est_node_time)}")
            self.log.info(
                f"  détail : stabilité CRM ~{_dur(self.est_crm_time)}")
            self.log.info(
                "  hypothèses (ajustables par env) : migration live ~"
                + str(EST_MIGRATE_SPEED // (1024 ** 2))
                + f" Mo/s + {EST_MIGRATE_OVERHEAD_S}s par migration "
                  f"[{EST_PROV.get('débit migration', 'défaut')} / "
                  f"{EST_PROV.get('overhead migration', 'défaut')}] "
                  "(PVE_EST_MIGRATE_SPEED_MBPS, PVE_EST_MIGRATE_OVERHEAD_S)")
            self.log.info(
                f"  hypothèses (ajustables par env) : apt {EST_APT_MIN:.0f} min "
                f"+ upgrade {EST_UPGRADE_MIN:.0f} min + reboot "
                f"{EST_REBOOT_MIN:.0f} min par nœud maintenu "
                f"[{EST_PROV.get('apt update+simulation', 'défaut')} / "
                f"{EST_PROV.get('apt full-upgrade', 'défaut')} / "
                f"{EST_PROV.get('reboot+quorum+post-checks', 'défaut')}] "
                "(PVE_EST_APT_MIN, PVE_EST_UPGRADE_MIN, PVE_EST_REBOOT_MIN)")
            self.log.info(
                "  NB : les valeurs marquées « stats (n=X) » sont des "
                "moyennes OBSERVÉES sur vos runs --execute précédents "
                f"({STATS_FILE}) ; « défaut » = constantes du script, "
                "à affiner au fil des runs.")
        # NB stockage LOCAL : seulement si le CAS a eu lieu pendant ce
        # dry-run (au moins un guest migré avec disque sur stockage non
        # partagé — détection réelle via la config du guest) ;
        # sinon rien, ou mention réduite si le stockage est illisible.
        if self.est_local_migs:
            self.log.info(
                "  NB : guest(s) sur stockage LOCAL (non partagé) migré(s) "
                "pendant ce run : " + ", ".join(self.est_local_migs)
                + " — la copie de leurs disques n'est PAS modélisée : "
                  "majorer l'estimation.")
        elif self.est_local_unknown:
            self.log.info(
                "  NB : stockage illisible pour : "
                + ", ".join(self.est_local_unknown)
                + " — si l'un de ces guests est sur stockage LOCAL, la "
                  "copie de ses disques n'est pas modélisée : majorer "
                  "l'estimation.")
        self.log.info(
            f"Migrations : {n_mig} guest(s) — {gb(ram_tot)} de RAM "
            f"transférés (RAM max des guests running ; une VM stopped sur "
            f"stockage partagé ne transfère que ses métadonnées)")
        # CTs migrés : PAS de live migration possible pour LXC — le mode
        # 'restart' fait un ARRET ➔ transfert ➔ REDÉMARRAGE, donc une
        # COUPURE de service par CT (les VMs QEMU, elles, sont migrées à
        # chaud : zéro downtime). Seul un CT RUNNING cause une coupure ;
        # un CT déjà à l'arrêt reste arrêté (rien de nouveau).
        cts_run = [e for e in self.mig_events
                   if e.get("vmtype") == "lxc"
                   and e.get("status") == "running"]
        cts_off = [e for e in self.mig_events
                   if e.get("vmtype") == "lxc"
                   and e.get("status") != "running"]
        if cts_run:
            self.log.warning(
                f"  dont {len(cts_run)} CT(s) migré(s) en mode RESTART "
                f"(arrêt ➔ transfert ➔ redémarrage : COUPURE de service "
                f"de quelques secondes à quelques minutes PAR CT) — "
                + ", ".join(f"{e['vmid']} ({e['name']})" for e in cts_run)
                + " (les VMs QEMU sont migrées à chaud, sans interruption)")
        if cts_off:
            self.log.info(
                f"  {len(cts_off)} CT(s) migré(s) déjà à l'arrêt ("
                + ", ".join(f"{e['vmid']} ({e['name']})" for e in cts_off)
                + ") : pas de coupure supplémentaire (ils restent "
                  "arrêtés)")
        # Overcommit mémoire (dernier recours du sélecteur de placement) :
        # guest(s) placé(s) sur une cible dont la Σ RAM max DÉCLARÉE des
        # guests running dépasse capacité − marge — si ces guests
        # consomment réellement leur maximum, la cible swappera (voire
        # OOM killer). Un WARNING par guest a déjà été émis au moment du
        # plan ; ce récapitulatif les regroupe pour le bilan.
        ocs = [e for e in self.mig_events if e.get("overcommit")]
        if ocs:
            self.log.warning(
                f"  dont {len(ocs)} guest(s) placé(s) en OVERCOMMIT "
                f"mémoire (dernier recours du placement : la cible "
                f"héberge plus de RAM max déclarée que sa capacité − "
                f"marge) — "
                + ", ".join(f"{e['vmid']} ({e['name']}) → {e['to']}"
                            for e in ocs)
                + " : risque de swap/OOM si les guests consomment "
                  "réellement leur maximum.")

        self._keep_separate_report()
        self._ram_peak_report()

    def _keep_separate_report(self) -> None:
        """Fenêtres de NON-RESPECT des règles d'anti-affinité « keep
        separate » pendant le run, reconstituées en rejouant la
        chronologie des migrations depuis les placements initiaux."""
        _dur, _mark = _est_hms, _est_mark
        state = self.state
        # --- fenêtres de cohabitation « keep separate » -----------------
        if not state.ha_rules_info:
            self.log.info(
                "Anti-affinités « keep separate » : aucune règle sur ce "
                "cluster — rien à surveiller ✔")
            return
        members = {m for ri in state.ha_rules_info
                   for m in ri["members"]}
        names: Dict[int, str] = {v.vmid: v.name
                                 for n in state.nodes.values()
                                 for v in n.vms}
        # trajectoire de chaque membre : (t, nœud) — départ + migrations
        traj: Dict[int, List[Tuple[float, str]]] = {}
        for m in members:
            if m in self.initial_place:
                traj[m] = [(0.0, self.initial_place[m])]
        for e in self.mig_events:
            if e["vmid"] in traj:
                traj[e["vmid"]].append((e["t1"], e["to"]))

        def _node_at(walk: List[Tuple[float, str]], t: float) -> str:
            cur = walk[0][1]
            for tt, nn in walk:
                if tt <= t:
                    cur = nn
            return cur

        def _pair_windows(a: int, b: int):
            pts = sorted({t for t, _ in traj[a]}
                         | {t for t, _ in traj[b]}
                         | {self.est_clock})
            raw = []
            for t0, t1 in zip(pts, pts[1:]):
                na = _node_at(traj[a], t0)
                nb = _node_at(traj[b], t0)
                if t1 > t0 and na == nb:
                    raw.append((t0, t1, na))
            merged = []
            for w in raw:
                if (merged and abs(merged[-1][1] - w[0]) < 1e-9
                        and merged[-1][2] == w[2]):
                    merged[-1] = (merged[-1][0], w[1], w[2])
                else:
                    merged.append(w)
            return merged

        self.log.info(
            "Anti-affinités « keep separate » — respect pendant l'upgrade "
            "(une fenêtre de cohabitation = risque accru si panne du nœud "
            "hôte PENDANT la fenêtre) :")
        n_violated = 0
        for ri in sorted(state.ha_rules_info, key=lambda r: str(r["id"])):
            grp = ri["members"]
            kind = ("DURE, strict=1" if ri["strict"] else "soft, strict=0")
            desc = " ≠ ".join(
                f"{m} ({names.get(m, '?')})" for m in grp)
            missing = [m for m in grp if m not in traj]
            if missing:
                self.log.warning(
                    f"  ? règle {ri['id']} [{desc}] ({kind}) : membre(s) "
                    + ", ".join(str(m) for m in missing)
                    + " absent(s) de l'inventaire — fenêtres NON vérifiables")
                continue
            wins = []           # (t0, t1, nœud, a, b)
            for i in range(len(grp)):
                for j in range(i + 1, len(grp)):
                    for t0, t1, node in _pair_windows(grp[i], grp[j]):
                        wins.append((t0, t1, node, grp[i], grp[j]))
            if not wins:
                self.log.info(
                    f"  règle {ri['id']} [{desc}] ({kind}) : JAMAIS "
                    f"violée — aucun couple ne cohabite")
                continue
            n_violated += 1
            union = []
            for t0, t1, _node, _a, _b in sorted(wins):
                if union and t0 <= union[-1][1] + 1e-9:
                    union[-1] = (union[-1][0], max(union[-1][1], t1))
                else:
                    union.append((t0, t1))
            total = sum(t1 - t0 for t0, t1 in union)
            worst = max(t1 - t0 for t0, t1 in union)
            self.log.warning(
                f"  règle {ri['id']} [{desc}] ({kind}) : cohabitation "
                f"~{_dur(total)} au total (pire fenêtre continue : "
                f"~{_dur(worst)}) :")
            for t0, t1, node, a, b in sorted(wins)[:8]:
                self.log.warning(
                    f"      {_mark(t0)} ➔ {_mark(t1)} "
                    f"(durée du risque : ~{_dur(t1 - t0)}) : VM {a} "
                    f"({names.get(a, '?')}) cohabite avec VM {b} "
                    f"({names.get(b, '?')}) sur {node}")
            if len(wins) > 8:
                self.log.warning(
                    f"      … et {len(wins) - 8} autre(s) fenêtre(s)")
        if n_violated == 0:
            self.log.info(
                "  Toutes les règles « keep separate » ont été respectées "
                "pendant tout l'upgrade ✔")
        else:
            self.log.warning(
                f"  {n_violated} règle(s) « keep separate » violée(s) "
                f"temporairement (repli soft strict=0 : le script répartit "
                f"au mieux, et le rééquilibrage final referme ces fenêtres "
                f"avant le dégel) — pendant une fenêtre, une panne du nœud "
                f"hôte toucherait plusieurs membres SIMULTANÉMENT.")

    def _ram_peak_report(self) -> None:
        """Pic de pression RAM durant la mise à jour : le(s) nœud(s)
        ayant atteint la pression la plus forte pendant le run —
        typiquement un nœud qui absorbe les VMs évacuées d'un voisin
        en maintenance. Rejoué depuis les placements initiaux ; la
        pression d'un nœud = somme des charges des VMs running qu'il
        héberge (un nœud en maintenance/reboot est vide). Un pic
        AU-DESSUS de 100 % signifie que la Σ RAM max déclarée des
        guests running dépasse la RAM PHYSIQUE du nœud (sur-engagement
        mémoire) : soit PRÉEXISTANT à l'inventaire, soit repli
        overcommit documenté plus haut dans le bilan — le risque de
        swap/OOM est alors réel si les guests consomment leur max.
        Le pic ne porte QUE sur les nœuds IMPLIQUÉS dans une
        migration du run (source ou cible) ; un nœud non impliqué
        garde une pression constante — déjà sur-engagé à
        l'inventaire, il est signalé à part (PRÉEXISTANT).
        La fenêtre d'un pic couvre TOUS les intervalles où le max
        persiste (t0 = premier, t1 = dernier) — pas seulement le
        premier, qui peut s'arrêter sur un événement sans rapport
        avec ce nœud. Les nœuds EX ÆQUO (pression à ±0.5 point du
        max) sont listés ensemble : à ce niveau, la pression
        affichée est identique et choisir arbitrairement l'un
        masquerait les fenêtres de résorption des autres."""
        state = self.state
        if not self.mig_events or not state.nodes \
                or not self.initial_place:
            return
        vm_load_of = {v.vmid: vm_load(v)
                      for n in state.nodes.values() for v in n.vms}
        place = dict(self.initial_place)
        node_mem: Dict[str, float] = {nm: 0.0 for nm in state.nodes}
        for v, nm in place.items():
            node_mem[nm] = node_mem.get(nm, 0.0) \
                + vm_load_of.get(v, 0)
        # nœuds IMPLIQUÉS dans ce run (source ou cible d'au moins
        # une migration) : seuls concernés par le « pic durant la
        # mise à jour » ci-dessous
        touched = ({e["from"] for e in self.mig_events}
                   | {e["to"] for e in self.mig_events})
        # pression INITIALE de chaque nœud (avant toute migration) :
        # sert à signaler à part le sur-engagement PRÉEXISTANT des
        # nœuds non impliqués (constant pendant tout le run)
        p0 = {nm: mem / max(state.nodes[nm].maxmem, 1)
              for nm, mem in node_mem.items()}
        pts = sorted({0.0} | {e["t1"] for e in self.mig_events}
                     | {self.est_clock})
        if len(pts) < 2:
            return
        events = sorted(self.mig_events, key=lambda e: e["t1"])
        ei = 0
        peak: Dict[str, Tuple[float, float, float]] = {}
        for t0, t1 in zip(pts, pts[1:]):
            # migrations ABOUTIES à t <= t0 : intégrées au placement
            while ei < len(events) and events[ei]["t1"] <= t0 + 1e-9:
                e = events[ei]
                ei += 1
                vm, ld = e["vmid"], vm_load_of.get(e["vmid"], 0)
                old = place.get(vm)
                if old is not None:
                    node_mem[old] = node_mem.get(old, 0.0) - ld
                node_mem[e["to"]] = \
                    node_mem.get(e["to"], 0.0) + ld
                place[vm] = e["to"]
            # pressions CONSTANTES sur [t0, t1) : relever les pics ;
            # un pic qui PERSISTE sur plusieurs intervalles étend sa
            # fenêtre (t0 = premier intervalle au max, t1 = DERNIER) —
            # sinon la fenêtre s'arrêterait sur un point de la timeline
            # qui ne concerne pas ce nœud (ex. la fin de la migration
            # d'un autre nœud) et la « durée du risque » serait fausse
            for nm, mem in node_mem.items():
                p = mem / max(state.nodes[nm].maxmem, 1)
                pk = peak.get(nm)
                if pk is None or p > pk[0] + 1e-9:
                    peak[nm] = (p, t0, t1)
                elif abs(p - pk[0]) <= 1e-9:
                    peak[nm] = (pk[0], pk[1], t1)
        # pic DU RUN : uniquement parmi les nœuds IMPLIQUÉS dans
        # une migration (source ou cible) — un nœud non impliqué
        # garde une pression CONSTANTE (état d'inventaire) : son
        # éventuel sur-engagement est PRÉEXISTANT, pas un pic
        # « durant la mise à jour » ; une fenêtre T+X serait
        # trompeuse (le risque est constant sur TOUT le run, et
        # existe aussi avant/après)
        best = max((pk[0] for nm, pk in peak.items()
                    if nm in touched), default=0.0)
        n_oc = sum(1 for e in self.mig_events if e.get("overcommit"))
        if best > 1e-9:
            # holders : le(s) nœud(s) au pic — EX ÆQUO inclus : des
            # nœuds à pression quasi identique (à ±0.5 point près,
            # invisible à l'arrondi de l'affichage) ne doivent pas
            # être départagés arbitrairement ; lister les ex æquo
            # donne à chacun SA fenêtre de résorption dans le détail
            holders = sorted(nm for nm, pk in peak.items()
                             if nm in touched
                             and pk[0] >= best - 0.005)
            qui = (f"nœud {holders[0]}" if len(holders) == 1
                   else "nœuds " + ", ".join(holders))
            if best > 1.0:
                self.log.warning(
                    f"Pic de pression RAM DÉCLARÉE (Σ RAM max des guests "
                    f"running) durant la mise à jour : "
                    f"{best:.0%} — " + qui
                    + " : AU-DESSUS de la RAM physique du nœud "
                      "(sur-engagement mémoire — risque de swap/OOM si les "
                      "guests consomment réellement leur maximum)")
            else:
                self.log.info(
                    f"Pic de pression RAM DÉCLARÉE (Σ RAM max des guests "
                    f"running) durant la mise à jour : "
                    f"{best:.0%} — " + qui
                    + " (jamais au-dessus de la RAM physique ✔)")
                if n_oc:
                    self.log.info(
                        f"  ({n_oc} repli(s) overcommit documenté(s) plus "
                        f"haut : le pic déclaré reste pourtant ≤ 100% ici)")
            for nm in holders:
                p, t0, t1 = peak[nm]
                n = state.nodes[nm]
                self.log.info(
                    f"  {nm} : pic {p:.0%} de {_est_mark(t0)} à "
                    f"{_est_mark(t1)} — durée du risque : "
                    f"~{_est_hms(t1 - t0)} ({gb(p * n.maxmem)} / "
                    f"{gb(n.maxmem)})")
        # sur-engagement PRÉEXISTANT : nœuds NON impliqués dans ce
        # run déjà au-dessus de leur RAM physique à l'inventaire —
        # état CONSTANT (avant, pendant et après le run), non
        # résorbé par ce run — signalé à part pour ne pas masquer
        # le vrai pic de la mise à jour
        for nm, p in sorted(
                ((nm, p) for nm, p in p0.items()
                 if nm not in touched and p > 1.0 + 1e-9),
                key=lambda kv: -kv[1]):
            n = state.nodes[nm]
            self.log.warning(
                f"  {nm} : sur-engagement PRÉEXISTANT : {p:.0%} "
                f"({gb(p * n.maxmem)} / {gb(n.maxmem)}) — nœud non "
                f"impliqué dans ce run (aucune migration depuis/vers) : "
                f"constant, non résorbé par ce run")

    def final_report(self):
        # v9 : en dry-run l'état final est SIMULÉ — sa « RAM (pression) »
        # est la pression DÉCLARÉE du modèle (égale à « Σ déclarée »),
        # pas un usage mesuré. Sans ce NB, comparer l'état initial
        # (« RAM réelle » ~50 %) à l'état final (« pression » ~85 %)
        # laissait croire que la mémoire des nœuds avait gonflé, alors
        # qu'une migration DÉPLACE la mémoire, elle ne la crée pas.
        # En run réel ayant touché le cluster, l'état est re-lu après
        # la fenêtre de stabilité CRM (simulated=False) : pas de NB.
        note = None
        if self.state.simulated:
            note = (
                "« RAM (pression) » = Σ RAM max DÉCLARÉE des guests "
                "running du modèle, muté par les migrations "
                + ("SIMULÉES (dry-run)" if self.dry else "appliquées")
                + " — PAS une consommation mesurée. Comparez-la à "
                "« Σ déclarée » de l'état initial (même métrique), pas "
                "à « RAM réelle » : une migration déplace la mémoire, "
                "elle ne la crée pas ; l'usage réel du nœud ne peut pas "
                "être simulé.")
        print_occupancy_table(self.log, self.state, "ÉTAT FINAL DU CLUSTER",
                              note=note)
        gap = pressure_gap(self.state)
        if gap is not None:
            thr = rebalance_threshold(self.state)
            if gap <= thr:
                if self.state.theoretical_gap >= 0:
                    if gap < self.state.theoretical_gap:
                        verdict = (f"MEILLEUR que l'optimum théorique "
                                   f"approché "
                                   f"({self.state.theoretical_gap:.0%}) ✔")
                    else:
                        verdict = (f"à l'optimum théorique approché "
                                   f"({self.state.theoretical_gap:.0%}) ✔")
                else:
                    verdict = "sous la cible ✔"
            else:
                verdict = "au-dessus de la cible (granularité des VMs)"
            self.log.info(f"Écart de pression RAM final (max-min) : {gap:.0%} — {verdict}")
        if self.off_rule_returned:
            self.log.info(
                f"{len(self.off_rule_returned)} ressource(s) HA repliée(s) "
                f"ou déplacée(s) hors règle pendant l'Étape 1 (repli "
                f"strict=0 ou sommeil des règles), puis "
                f"RAPATRIÉE(S) sur un nœud de leur règle pendant le "
                f"rééquilibrage final (1re passe, ou 2e passe "
                f"post-rééquilibrage) : dégel cohérent, le CRM n'a rien "
                f"à corriger ✔ ("
                + ", ".join(sorted(str(v) for v in self.off_rule_returned))
                + ")")
        if self.off_rule_vmids:
            # NB : une ressource repliée hors règle PENDANT le run a pu
            # rentrer chez elle par la suite — via le planning NORMAL
            # d'une évacuation suivante (ex. repliée p-c4 ➔ p-pes au
            # nœud 1, puis re-répartie p-pes ➔ p-c4 au nœud 2 : sa
            # cible EST son nœud de règle). Elle n'est donc ni dans
            # off_rule_returned (rapatriement dédié) ni réellement hors
            # règle : ne PAS l'inclure dans l'alerte, sinon le message
            # final annoncerait au CRT des rapatriements qui n'auront
            # pas lieu. Ne signaler que celles ENCORE hors règle sur
            # l'état final.
            final_node = {}
            for n in self.state.nodes.values():
                for v in n.vms:
                    final_node[v.vmid] = n.name

            def _still_off(vmid):
                rule = self.state.ha_affinity.get(vmid)
                return (rule is not None
                        and final_node.get(vmid) not in rule)

            still_off = sorted(v for v in self.off_rule_vmids
                               if _still_off(v))
            back_home = sorted(set(self.off_rule_vmids) - set(still_off))
            if back_home:
                self.log.info(
                    f"{len(back_home)} ressource(s) HA repliée(s) ou "
                    f"déplacée(s) hors règle pendant ce run, puis "
                    f"rentrée(s) d'elles-mêmes sur un nœud de leur règle "
                    f"(placement normal des évacuations suivantes) — déjà "
                    f"chez elles à la fin du run, le CRM n'aura rien à "
                    f"corriger ✔ ("
                    + ", ".join(str(v) for v in back_home) + ")")
            if still_off:
                self.log.warning(
                    f"{len(still_off)} ressource(s) HA toujours HORS "
                    f"règle d'affinité (strict=0) à la fin du run : "
                    + ", ".join(str(v) for v in still_off)
                    + " — le CRM va probablement les rapatrier vers "
                    "leurs nœuds préférés : c'est ATTENDU, pas une "
                    "anomalie.")
        # Filet général : TOUTE ressource HA encore hors de sa règle
        # node-affinity à la fin du run (dure OU soft) — y compris les
        # déplacées pendant le sommeil des règles et non rapatrieables
        # (aucun nœud de règle ne respectait la marge RAM/CPU, cf. le
        # WARNING émis au moment du rapatriement). Le CRM agira au
        # dégel : certain pour une règle DURE, probable pour une soft.
        still_hors = sorted(hors_rule_vmids(self.state))
        if still_hors:
            n_hard = sum(1 for v in still_hors
                         if v in self.state.ha_affinity_hard)
            self.log.warning(
                f"{len(still_hors)} ressource(s) HA encore HORS de "
                f"leur règle node-affinity à la fin du run ("
                + ", ".join(str(v) for v in still_hors)
                + f") — dont {n_hard} sous règle DURE (strict=1 : "
                "relocalisation CRM certaine au dégel ; les soft : "
                "probable). Comportement ATTENDU (marge RAM/CPU "
                "insuffisante sur les nœuds de règle au moment du "
                "rapatriement), pas une anomalie.")
        if self.dry:
            self.estimation_report()
            self.log.info("✅ DRY-RUN terminé — migrations/upgrades/reboots "
                          "SIMULÉS ; seules les règles node-affinity ont été "
                          "réellement désactivées puis réactivées (test du "
                          "mécanisme, sans effet sur des placements "
                          "conformes).")

    # ---------- point d'entrée ----------
    def run(self, only_node: Optional[str], skip_minor: bool = False):
        try:
            if not self.dry:
                self.state = self.client.fetch_state()
            else:
                # en dry-run, l'état initial doit venir de l'API (lecture seule)
                if self.client is not None:
                    self.state = self.client.fetch_state()
                else:
                    raise RuntimeError("Dry-run nécessite un accès API en lecture.")
            # placements initiaux : point de départ de la timeline du
            # bilan dry-run (fenêtres keep separate) — avant TOUTE migration
            self.initial_place = {
                v.vmid: v.node
                for n in self.state.nodes.values() for v in n.vms}
            nodes = NODE_ORDER or sorted(self.state.nodes)
            nodes = [n for n in nodes if n not in NODES_TO_EXCLUDE]
            if only_node:
                nodes = [n for n in nodes if n == only_node]
                if not nodes:
                    raise RuntimeError(f"Nœud '{only_node}' introuvable.")
            self.only_node = bool(only_node)
            self.skip_minor = bool(skip_minor)
            self.preflight()
            # ÉTAPE 0-bis (v15) : /etc/hosts de chaque nœud doit résoudre
            # tous les pairs AVANT la première évacuation. Lecture pure
            # en dry-run (rapport des manquants/en trop), correction
            # sauvegardée en --execute.
            self.hosts_sync()
            # fichier d'état : trace ce qu'il faudra restaurer si ce run
            # plante (ressources HA détachées, nœuds en maintenance).
            # Mis à jour à CHAQUE transition, supprimé en fin de run OK.
            if not self.dry:
                self._state_write()
            for idx, node in enumerate(nodes, 1):
                self.update_node(node, f"{idx}/{len(nodes)}")
            # Récap --skip-minor-updates (v19) : nœuds ignorés ce run
            # (MAJ Debian mineures seules). Rappel EXPLICITE : ces MAJ
            # (parfois des correctifs de sécurité) ne sont pas
            # supprimées, seulement DIFFÉRÉES — relancer un run sans
            # l'option dans une autre fenêtre pour les appliquer.
            if self.minor_skipped:
                self.log.info(
                    f"--skip-minor-updates : {len(self.minor_skipped)} "
                    f"nœud(s) ignoré(s) — MAJ Debian mineures uniquement : "
                    f"{', '.join(self.minor_skipped)}. Les MAJ de ces nœuds "
                    f"restent en attente : relancez un run SANS l'option "
                    f"pour les appliquer.")
            # FIN de l'Étape 1 : réactivation des règles node-affinity
            # désactivées au premier nœud — AVANT le rapatriement
            # (--node) / le rééquilibrage et le plan de failback des
            # hors-règle, qui redeviennent contraints par les règles
            # (dégel final cohérent : le CRM n'a pas de vague de
            # relocate à corriger en pleine Étape 2).
            self._ha_rules_restore_all(self.state)
            # Rééquilibrage global uniquement en run complet : avec --node,
            # on rapatrie à la place les VMs évacuées vers leur nœud d'origine.
            if only_node:
                self.restore_vms(nodes[0])
            else:
                self.rebalance()
            if not self.dry:
                # attendre que le CRM ait fini TOUTES ses tâches HA
                # (failback, fin de migration...) et rafraîchir l'état :
                # le rapport final ne doit plus montrer de « postmigrate ».
                # NB : uniquement si le run a MODIFIÉ le cluster (upgrade,
                # migration, maintenance). Un run sans action (cluster déjà
                # à jour, rien à rééquilibrer) n'a aucune raison de faire
                # attendre la fenêtre de stabilité de 60s.
                if self.touched:
                    self.client.wait_ha_settled()
                    self.state = self.client.fetch_state()
                else:
                    self.log.info("Aucune action n'a modifié le cluster — "
                                  "attente de stabilité CRM inutile.")
            self.final_report()
            # run terminé avec succès : l'état zéro est restauré
            # (plus rien en 'ignored', plus de maintenance) — le fichier
            # d'état n'a plus de raison d'être.
            if not self.dry:
                self._state_clear()
        except Exception as e:
            self.log.critical(f"Échec : {e}")
            self.log.critical("Arrêt propre : remise en état…")
            raise
        finally:
            # Ctrl-C : l'état est FIGÉ volontairement par update_node
            # (nœud potentiellement incohérent) — ne PAS sortir les
            # nœuds de maintenance ici, le fichier d'état prend le
            # relais pour le prochain run.
            if isinstance(sys.exc_info()[1], KeyboardInterrupt):
                raise
            # Sortie de maintenance pour TOUT nœud encore en maintenance
            if not self.dry and self.maintenance_nodes:
                for n in list(self.maintenance_nodes):
                    try:
                        self.client.ha_maintenance_off(n)
                        self.maintenance_nodes.remove(n)
                        self._state_write()
                    except Exception as ee:
                        self.log.error(f"Impossible de sortir {n} du mode maintenance : {ee}")
            # Filet de sécurité règles node-affinity : un run complet qui
            # échoue en pleine Étape 1 ne doit pas laisser les règles
            # désactivées sur le cluster jusqu'au prochain run — le
            # fichier d'état couvrirait, mais autant restaurer tout de
            # suite (le CRM reprend ses préférences le plus tôt possible).
            # Dry-run inclus : les désactivations y sont RÉELLES.
            if self.ha_rules_snapshot:
                try:
                    self._ha_rules_restore_all(self.state)
                except Exception as ee:
                    self.log.error(f"Réactivation des règles node-affinity "
                                   f"impossible ({ee}) — le prochain run la "
                                   f"fera via le fichier d'état.")
            # STATISTIQUES : fusion des durées réelles mesurées pendant ce
            # run dans .proxmox-rolling-update.stats — dans le finally,
            # donc MÊME un run partiel (erreur en cours de route, sortie
            # de maintenance en filet de sécurité) contribue ses
            # échantillons. Une écriture impossible n'échoue jamais le run.
            if not self.dry:
                try:
                    added = save_stats(self.stats_new)
                except Exception as ee:
                    added = 0
                    self.log.warning(f"Statistiques non enregistrées : {ee}")
                if added:
                    self.log.info(
                        f"Statistiques : {added} échantillon(s) de durée(s) "
                        f"réelle(s) ajouté(s) à {STATS_FILE} — les "
                        f"estimations des prochains dry-run s'affineront.")


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
def load_env_file(path: str, logger: logging.Logger):
    """Charge un fichier KEY=VALUE (ex. /etc/proxmox-updater/proxmox.env).
    Les variables déjà présentes dans l'environnement ne sont PAS écrasées."""
    loaded = 0
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
            loaded += 1
    logger.info(f"Fichier d'environnement chargé : {path} ({loaded} entrées)")


def main():
    parser = argparse.ArgumentParser(
        description="Mise à jour glissante Proxmox VE sans fencing (méthode officielle).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true",
                      help="Simulation complète, aucune écriture sur les nœuds.")
    mode.add_argument("--execute", action="store_true",
                      help="Exécution réelle.")
    parser.add_argument("--node", help="Ne traiter que ce nœud (optionnel).")
    parser.add_argument(
        "--skip-minor-updates", action="store_true",
        help="Ignorer les nœuds dont les seules mises à jour en attente "
             "sont des paquets Debian mineurs (aucun changement de noyau, "
             "aucun paquet pve-*/proxmox-*, aucun reboot en attente) : "
             "ni évacuation ni upgrade ni reboot pour eux. Conçu pour la "
             "REPRISE après incident : Debian publie des MAJ mineures "
             "pendant un run, et chaque nœud déjà traité se verrait "
             "sinon infliger une évacuation complète pour presque rien. "
             "Les MAJ ignorées (parfois des correctifs de sécurité) ne "
             "sont PAS supprimées, seulement différées : relancer plus "
             "tard un run SANS cette option pour les appliquer.")
    parser.add_argument("--env-file", default="/etc/proxmox-updater/proxmox.env",
                        help="Fichier d'environnement contenant les secrets "
                             "(par défaut /etc/proxmox-updater/proxmox.env).")
    parser.add_argument("--log-file", default=None,
                        help="Écrire les logs en parallèle dans ce fichier "
                             "(sans ANSI, horodatage complet).")
    parser.add_argument("--no-color", action="store_true",
                        help="Forcer la désactivation des couleurs.")
    parser.add_argument("--force-color", action="store_true",
                        help="Forcer l'activation des couleurs (ex. dans un TTY via un pipe).")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logger = setup_logger(args.verbose, args.log_file,
                          args.no_color, args.force_color)
    # Charger les secrets AVANT que le bloc CONFIGURATION ne soit relu :
    # les constantes sont évaluées à l'import, on recharge donc les valeurs ici.
    try:
        load_env_file(args.env_file, logger)
    except FileNotFoundError:
        # FATAL : sans le fichier env, les secrets/hosts sont absents et le
        # script se lancerait sur des défauts vides — on sort immédiatement
        # plutôt que de continuer en mode dégradé silencieux.
        logger.error(f"Fichier d'environnement '{args.env_file}' introuvable — "
                     f"arrêt. Indiquez le bon chemin via --env-file.")
        sys.exit(1)
    # Log fichier via PVE_LOG_FILE (variable d'env OU entrée du fichier env).
    # Vide/absente => pas de fichier de log. --log-file (CLI) reste prioritaire.
    env_log_file = _env("PVE_LOG_FILE", "").strip()
    if env_log_file and not args.log_file:
        try:
            # Stream ligne-buffered PARTAGÉ avec le tee stderr : un seul
            # descripteur → ordre d'écriture préservé entre logger et
            # stderr (tracebacks, diagnostics bibliothèques).
            stream = open(env_log_file, "a", encoding="utf-8", buffering=1)
            fh = logging.StreamHandler(stream)
            fh.setFormatter(PlainFileFormatter())
            logger.addHandler(fh)
            _tee_stderr_to(stream)
            logger.info(f"Logs également écrits dans : {env_log_file} "
                        f"(stderr y est aussi capturé)")
        except OSError as e:
            logger.warning(f"Fichier de log '{env_log_file}' inutilisable ({e}) "
                           f"— poursuite sans log fichier.")
    # PREMIÈRE ligne de chaque run (console ET fichier de log) : la version
    # du script, pour identifier sans ambiguïté la copie qui s'exécute.
    logger.info(f"proxmox-rolling-update — version {SCRIPT_VERSION}")
    # Relecture des constantes maintenant que l'environnement est chargé
    # (elles ont été évaluées avant le chargement du fichier d'env).
    global API_HOST, API_HOSTS, API_USER, API_TOKEN_NAME, API_TOKEN_VALUE, VERIFY_SSL
    global SSH_USER, SSH_PRIVATE_KEY, SSH_PORT, SSH_KEY_PASSPHRASE, SSH_RETRIES
    global WITH_LOCAL_DISKS
    global EST_MIGRATE_SPEED, EST_MIGRATE_OVERHEAD_S
    global EST_APT_MIN, EST_UPGRADE_MIN, EST_REBOOT_MIN
    global STATS_FILE, STATS_MAX_SAMPLES
    global MIGRATE_TIMEOUT, MIGRATE_ATTEMPTS, START_TIMEOUT
    API_HOST = _env("PVE_API_HOST", API_HOST)
    # PVE_API_HOSTS et PVE_EST_* : relus APRÈS le fichier d'env comme les
    # autres — sinon une valeur posée UNIQUEMENT dans ce fichier serait
    # silencieusement ignorée (constante déjà évaluée à l'import ; la
    # précédence reste : shell env > fichier env > défaut).
    API_HOSTS = [h.strip() for h in _env("PVE_API_HOSTS", "").split(",") if h.strip()]
    # --- STATISTIQUES DE DURÉES : les moyennes OBSERVÉES (.proxmox-
    # rolling-update.stats) servent de DÉFAUTS dans _env() ci-dessous.
    # La précédence de chaque PVE_EST_* devient donc :
    #   shell env > fichier env > statistiques observées > défaut du code.
    # _env() lit os.environ (déjà chargé du fichier env à ce stade) :
    # une variable D'ENV a toujours le dernier mot sur les stats.
    STATS_FILE = _env("PVE_STATS_FILE", STATS_FILE)
    STATS_MAX_SAMPLES = int(_env("PVE_STATS_MAX_SAMPLES",
                                 str(STATS_MAX_SAMPLES)))
    # MIGRATE_TIMEOUT est un _env au niveau module : relecture ici pour
    # qu'une valeur posée UNIQUEMENT dans le --env-file prenne effet
    # (le timeout par défaut d'un argument de fonction aurait capturé
    # la valeur d'import, avant chargement du fichier env).
    MIGRATE_TIMEOUT = int(_env("PVE_MIGRATE_TIMEOUT",
                               str(MIGRATE_TIMEOUT)))
    MIGRATE_ATTEMPTS = int(_env("PVE_MIGRATE_ATTEMPTS",
                                str(MIGRATE_ATTEMPTS)))
    START_TIMEOUT = int(_env("PVE_START_TIMEOUT",
                             str(START_TIMEOUT)))
    derived = stats_derive(load_stats())
    EST_PROV.clear()
    EST_MIGRATE_SPEED = int(_env(
        "PVE_EST_MIGRATE_SPEED_MBPS",
        str(derived.get("speed_mbps",
                        (EST_MIGRATE_SPEED // 1024 ** 2, 0))[0]))) * 1024 ** 2
    EST_MIGRATE_OVERHEAD_S = int(_env(
        "PVE_EST_MIGRATE_OVERHEAD_S",
        str(derived.get("overhead_s", (EST_MIGRATE_OVERHEAD_S, 0))[0])))
    EST_APT_MIN = float(_env(
        "PVE_EST_APT_MIN", str(derived.get("apt_min", (EST_APT_MIN, 0))[0])))
    EST_UPGRADE_MIN = float(_env(
        "PVE_EST_UPGRADE_MIN", str(derived.get("upgrade_min",
                                               (EST_UPGRADE_MIN, 0))[0])))
    EST_REBOOT_MIN = float(_env(
        "PVE_EST_REBOOT_MIN", str(derived.get("reboot_min",
                                              (EST_REBOOT_MIN, 0))[0])))
    # provenance de chaque paramètre (pour le bilan final) : env si la
    # variable est POSÉE, statistiques si des échantillons existent,
    # sinon défaut du code.
    for env_name, key, label in (
            ("PVE_EST_MIGRATE_SPEED_MBPS", "speed_mbps", "débit migration"),
            ("PVE_EST_MIGRATE_OVERHEAD_S", "overhead_s", "overhead migration"),
            ("PVE_EST_APT_MIN", "apt_min", "apt update+simulation"),
            ("PVE_EST_UPGRADE_MIN", "upgrade_min", "apt full-upgrade"),
            ("PVE_EST_REBOOT_MIN", "reboot_min", "reboot+quorum+post-checks")):
        if os.environ.get(env_name):
            EST_PROV[label] = "env"
        elif key in derived:
            EST_PROV[label] = f"stats (n={derived[key][1]})"
        else:
            EST_PROV[label] = "défaut"
    if derived:
        logger.info(
            "Statistiques de durées : " + " ; ".join(
                f"{lbl} = {val}{'' if prov == 'env' else f' [{prov}]'}"
                for lbl, val, prov in (
                    ("débit migr.", f"{EST_MIGRATE_SPEED // 1024 ** 2} Mo/s",
                     EST_PROV["débit migration"]),
                    ("overhead migr.", f"{EST_MIGRATE_OVERHEAD_S}s",
                     EST_PROV["overhead migration"]),
                    ("apt éval.", f"{EST_APT_MIN:.1f}min",
                     EST_PROV["apt update+simulation"]),
                    ("upgrade", f"{EST_UPGRADE_MIN:.1f}min",
                     EST_PROV["apt full-upgrade"]),
                    ("reboot", f"{EST_REBOOT_MIN:.1f}min",
                     EST_PROV["reboot+quorum+post-checks"]))))
    else:
        logger.info(
            "Statistiques de durées : aucune pour l'instant — valeurs par "
            "défaut ; chaque run --execute mesurera ses durées réelles "
            f"et les accumulera dans {STATS_FILE}.")
    API_USER = _env("PVE_API_USER", API_USER)
    API_TOKEN_NAME = _env("PVE_API_TOKEN_NAME", API_TOKEN_NAME)
    API_TOKEN_VALUE = _env("PVE_API_TOKEN_VALUE", API_TOKEN_VALUE)
    VERIFY_SSL = _env("PVE_VERIFY_SSL", str(VERIFY_SSL)).lower() in ("1", "true", "yes")
    SSH_USER = _env("PVE_SSH_USER", SSH_USER)
    SSH_PRIVATE_KEY = _env("PVE_SSH_KEY", SSH_PRIVATE_KEY)
    SSH_PORT = int(_env("PVE_SSH_PORT", str(SSH_PORT)))
    SSH_KEY_PASSPHRASE = _env("PVE_SSH_PASSPHRASE", "")
    SSH_RETRIES = int(_env("PVE_SSH_RETRIES", str(SSH_RETRIES)))
    WITH_LOCAL_DISKS = _env("PVE_WITH_LOCAL_DISKS", str(WITH_LOCAL_DISKS)).lower() in ("1", "true", "yes")
    logger.info(f"Marges RAM : {margins_desc()}")
    # Diagnostic : la passphrase SSH est-elle disponible AVANT tout usage ?
    logger.info(f"Passphrase SSH        : "
                f"{'définie via PVE_SSH_PASSPHRASE' if SSH_KEY_PASSPHRASE else 'absente (aucune invite si la clé est nue)'}")
    dry = args.dry_run
    banner(logger, f"PROXMOX ROLLING UPDATE v{SCRIPT_VERSION} — mode {'DRY-RUN (simulation)' if dry else 'EXÉCUTION RÉELLE'}",
           ColorFormatter.GREEN if dry else "\033[91;1m")

    # Le client Proxmox est instancié dans TOUS les cas : l'inventaire du
    # cluster (lecture seule) est nécessaire aussi bien en dry-run (pour
    # simuler sur l'état réel) qu'en exécution. C'est le paramètre `dry`
    # passé à l'Updater qui garantit qu'AUCUNE action d'écriture n'est
    # effectuée sur les nœuds en mode dry-run. L'instanciation est DANS
    # le try : un échec de connexion initiale est loggée dans le fichier
    # de log (plus jamais de traceback brut perdu hors log).
    try:
        client = ProxmoxClient(logger)

        updater = Updater(logger, dry, client)
        updater.run(args.node, skip_minor=args.skip_minor_updates)
        sys.exit(0)
    except KeyboardInterrupt:
        # Ctrl-C : les blocs finally ont DÉJÀ restauré l'état zéro
        # (sortie maintenance, réactivation HA, retrait des flags
        # Ceph) — on remplace le traceback brut par un message clair.
        # S'il reste des irrécupérables (SSH mort pendant le finally),
        # le fichier d'état JSON les couvrira au prochain run (Étape 0).
        logger.critical("Interruption utilisateur (Ctrl-C) — état zéro "
                        "restauré par les blocs finally. Relancez le "
                        "run : l'Étape 0 reprendra le reste via le "
                        "fichier d'état si besoin.")
        sys.exit(130)
    except Exception as e:
        # Les erreurs du run sont déjà loggées (⛔ Échec) par run() ;
        # celle-ci couvre les échecs ANTÉRIEURS (connexion initiale,
        # inventaire) et confirme la sortie en échec dans le log.
        logger.error(f"Run échoué : {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
