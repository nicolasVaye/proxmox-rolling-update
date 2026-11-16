#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxmox_ceph_rolling_update.py
==============================
Mise à jour glissante du Ceph d'un cluster Proxmox VE hyperconvergé.
Script COMPAGNON de proxmox_rolling_update.py : à exécuter APRÈS le
rolling update PVE (qui a déjà upgradé/rebooté les nœuds).

Trois actions MUTUELLEMENT EXCLUSIVES :

  1. mineur (défaut)  : mise à jour des paquets Ceph (patch, ex. 19.2.6 →
     19.2.7), nœud par nœud, puis redémarrage ORDONNÉ des daemons du
     nœud (mon → mgr → osd → mds), SANS reboot du nœud, avec gates de
     santé Ceph entre chaque nœud et chaque type de daemon.

  2. --major RELEASE : changement de version majeure (ex. squid →
     tentacle), procédure officielle Proxmox (wiki Ceph_*_to_*) :
     préflight renforcé (montée d'EXACTEMENT une release majeure —
     descente et saut refusés ; prérequis de la release cible :
     pve-manager/ceph minimaux), puis bascule du dépôt apt sur TOUS
     les nœuds, apt full-upgrade sur tous les nœuds (les binaires
     nouveaux sont installés mais les anciens tournent encore), PUIS
     passes de redémarrage PAR TYPE DE DAEMON : mons un par un →
     vérification min_mon_release → mgrs → OSDs UNE PAR UNE (arrêt →
     test du sharding RocksDB réel pendant l'arrêt, « ceph-bluestore-
     tool show-sharding » → démarrage sur les nouveaux binaires ;
     équivalent plus progressif du restart ceph-osd.target par nœud)
     → MDS (procédure max_mds) → vérification que TOUTES les OSDs
     tournent
     sur la nouvelle release → « ceph osd require-osd-release » →
     retrait des flags de maintenance.

  3. --rotate-keys    : remédiation CVE-2025-30156 (Ceph Squid 19.2.6 /
     Tentacle 20.2.4 — AES-CBC non authentifié dans CephX, bypass
     d'authentification) : rotation de TOUTES les clés CephX « aes »
     vers « aes256k » (AES256-CTS-HMAC-SHA384-192, RFC 8009), procédure
     officielle Ceph en 10 étapes :
       ciphers autorisés → cipher préféré → clé mon. + restart des mons →
       clés mgr/osd/mds daemon par daemon (label bluestore des OSDs
       ceph-volume compris) → auth_service_cipher → interdiction des
       nouvelles clés faibles → client.admin avec clé de secours →
       clients restants → retrait de « aes » des ciphers autorisés.
     Une fois terminé : retirer PVE_CEPH_ALLOW_AUTH_INSECURE=1 du env —
     les checks AUTH_INSECURE_* disparaissent et la santé redevient
     HEALTH_OK sans tolérance.

SÉCURITÉ — flags de maintenance Ceph : avant toute action, le script
pose noout, norecover, norebalance, nobackfill, noscrub, nodeep-scrub
(seulement ceux qu'il pose lui-même ; les orphelins d'un run précédent
interrompu sont ADOPTÉS puis retirés, les vôtres sont conservés), et
les RETIRE dans le bloc finally — même en cas d'abort. Un fichier
d'état JSON trace les flags et la progression (reprise possible pour
--rotate-keys : les entités déjà migrées sont re-détectées et sautées).
Gates PENDANT la fenêtre : santé OK + quorum + PGs ACTIVES + OSDs
'up' — « clean » n'est pas exigible tant que nos flags gèlent le
backfill (une PG « active+remapped » au retour d'une OSD est normale) ;
la convergence complète (active+clean) est vérifiée par la
CONVERGENCE FINALE, APRÈS le retrait des flags (avertissement sans
abort si le backfill est encore en cours : le run a réussi).

ANTI-BRUIT : les gates interrogent la santé du cluster à intervalle
régulier (PVE_CEPH_POLL_S, défaut 15 s) et à chaque unité redémarrée —
une santé IDENTIQUE à la précédente n'est PAS redumpée, et le
diagnostic est réimprimé dès que les dégradations CHANGENT (le message
de convergence NOMME au contraire les checks qui bloquent encore). Le
diagnostic n'affiche que les dégradations BLOQUANTES : les checks
AUTH_INSECURE_* tolérés (avertissement cephx dédié, imprimé une seule
fois par changement) et OSDMAP_FLAGS de maintenance (posés par le run
lui-même) sont masqués ; sur les chemins d'échec (abort, timeout de
gate), le contexte complet est réimprimé de force.

PHASE E — DÉFAUT ET OPT-IN : la version COURANTE de chaque daemon
OSD (« ceph osd metadata ») est lue avant la passe — un nœud dont
TOUTES les OSDs tournent déjà sur la release cible est SAUTÉ (un
daemon qui TOURNE sur la cible a nécessairement été redémarré APRÈS
l'upgrade des paquets : c'est une preuve, pas une hypothèse) ; sinon
ses OSDs sont redémarrées d'un coup via « systemctl restart
ceph-osd.target » (une seule gate par nœud — plus rapide, mais
pendant le restart AUCUNE OSD du nœud ne sert d'IO : les réplicas
des autres nœuds maintiennent le service, min_size ≥ 2 requis).
Le test du sharding RocksDB par OSD (piège META du wiki — il exige
l'arrêt INDIVIDUEL de chaque OSD) est un OPT-IN explicite :
« --force-detection-sharding » redémarre les OSDs UNE PAR UNE (arrêt
→ show-sharding → démarrage), sans exemption de version ; la date
de création des répertoires (préflight) n'est qu'une HEURISTIQUE,
la vérité terrain est ce test.

Mode dry-run (--dry-run) : n'exécute RIEN qui modifie le cluster.
L'inventaire et les gates de l'ÉTAPE 0 sont de pures lectures (API +
SSH), tout le reste est simulé ligne par ligne, avec la commande EXACTE
qui serait exécutée, et un bilan d'estimation final.

ROBUSTESSE / DIAGNOSTIC :
- Connexion SSH PERSISTANTE par nœud : un seul handshake par nœud et
  par run (réutilisée pour toutes les commandes) — évite les rejets
  fail2ban/sshd lors des dizaines de lectures d'un run. Retentatives
  (PVE_SSH_RETRIES, défaut 3) avec délais progressifs 15/30/45 s.
- Tout ce qui arrive sur stderr (tracebacks, diagnostics bibliothèques)
  est AUSSI écrit dans le fichier de log — plus rien de perdu.
- En cas d'échec, l'erreur est loggée (RUN INTERROMPU) AVANT le bilan,
  et le bilan signale explicitement le run interrompu (les compteurs
  ne sont PAS ceux d'un run complet) ; les flags de maintenance sont
  retirés par le bloc finally et le run est relançable (reprise).

Usage :
    python3 proxmox_ceph_rolling_update.py --dry-run
    python3 proxmox_ceph_rolling_update.py --execute
    python3 proxmox_ceph_rolling_update.py --execute --node pve-node2
    python3 proxmox_ceph_rolling_update.py --dry-run  --major tentacle
    python3 proxmox_ceph_rolling_update.py --execute --major tentacle
    python3 proxmox_ceph_rolling_update.py --execute --rotate-keys

NB : --node n'est supporté qu'en mode mineur (le mode majeur exige de
traiter TOUS les nœuds avant les redémarrages, et --rotate-keys est
une procédure cluster-wide).
"""

import argparse
import json
import logging
import os
import re
import shlex
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# CONFIGURATION — à adapter à votre plateforme
# ---------------------------------------------------------------------------
# Les valeurs sensibles sont surchargées par (dans l'ordre de priorité) :
#   1) la variable d'environnement correspondante,
#   2) le fichier d'environnement passé via --env-file, chargé au démarrage,
#   3) les valeurs par défaut ci-dessous.


def _env(name: str, default: str) -> str:
    # Une variable DÉFINIE MAIS VIDE compte comme absente (sinon
    # PVE_CEPH_STATE_FILE= (ligne vide d'un env) donne un chemin ''
    # et float(_env("PVE_EST_*", …)) lève ValueError).
    return os.environ.get(name) or default


# --- Connexion (mêmes variables que proxmox_rolling_update.py) -------------
API_HOST = _env("PVE_API_HOST", "pve-node1.example.com")   # nœud « graine »
API_HOSTS = [h.strip() for h in _env("PVE_API_HOSTS", "").split(",") if h.strip()]
API_USER = _env("PVE_API_USER", "automation@pam")
API_TOKEN_NAME = _env("PVE_API_TOKEN_NAME", "rolling-update")
API_TOKEN_VALUE = _env("PVE_API_TOKEN_VALUE", "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
VERIFY_SSL = _env("PVE_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

SSH_USER = _env("PVE_SSH_USER", "root")
SSH_PRIVATE_KEY = _env("PVE_SSH_KEY", "/etc/proxmox-updater/id_ed25519")
SSH_PORT = int(_env("PVE_SSH_PORT", "22"))
SSH_KEY_PASSPHRASE = _env("PVE_SSH_PASSPHRASE", "")
# Retentatives SSH par commande (PVE_SSH_RETRIES+1 tentatives), délais
# progressifs 15/30/45 s (plafond 60) — pour traverser un ban fail2ban
# temporaire ; la connexion persistante par nœud limite de toute façon
# drastiquement le nombre de handshakes.
SSH_RETRIES = int(_env("PVE_SSH_RETRIES", "3"))

# --- Gates / attentes Ceph -------------------------------------------------
# Timeout global d'attente de stabilisation (santé OK + quorum + PGs
# ACTIVES — cf. wait_ceph_stable : « clean » n'est exigé qu'après le
# retrait des flags, via la convergence finale) après chaque
# redémarrage de daemon / nœud.
CEPH_STABLE_TIMEOUT = int(_env("PVE_CEPH_STABLE_TIMEOUT", "1800"))
# Convergence FINALE (active+clean) après le retrait des flags : le
# backfill/recovery gelé pendant la fenêtre reprend — il peut être
# long sur un cluster chargé ; au timeout le run a de toute façon
# RÉUSSI (simple avertissement, le cluster converge tout seul).
FINAL_CONVERGE_TIMEOUT = int(_env("PVE_CEPH_FINAL_CONVERGE_TIMEOUT",
                                  str(CEPH_STABLE_TIMEOUT)))
# Période de poll des gates (s).
CEPH_POLL_S = int(_env("PVE_CEPH_POLL_S", "15"))
# Attente des vérifications post-restart qui dépendent du CONSENSUS :
# mise à jour AUTOMATIQUE de la monmap (min_mon_release) après le
# retour du dernier MON, élection du MGR actif. Ces mises à jour
# prennent quelques secondes — un check immédiat lirait l'ancien
# état et avorterait le run à tort (vécu : mons tous en tentacle,
# monmap encore à l'epoch précédente une seconde après le restart).
ELECTION_TIMEOUT_S = float(_env("PVE_CEPH_ELECTION_TIMEOUT_S", "300"))
# Attente des vérifications « check AUTH_INSECURE_* disparu » de
# --rotate-keys : le health check est RECALCULÉ ASYNCHRONEMENT par
# les mons — une lecture immédiate peut relire l'état d'AVANT la
# dernière rotation (vécu 11:02 : FATAL « mds.v-testprox03-C » 7 s
# après SON restart, alors que le check avait disparu à la lecture
# SUIVANTE, une seconde plus tard). On POLL donc avant de déclarer
# FATAL (le message d'échec reste ce qu'il était : run relançable,
# reprise au prochain run).
ROTATE_CHECK_TIMEOUT_S = float(_env("PVE_CEPH_ROTATE_CHECK_TIMEOUT_S",
                                   "120"))
# Utilisation globale du cluster (%) au-delà de laquelle on ne fait RIEN :
# un upgrade qui tourne mal sur un cluster presque plein = recovery très long.
CEPH_UTIL_MAX_PCT = float(_env("PVE_CEPH_UTIL_MAX_PCT", "85"))
# Tolérance des avis AUTH_INSECURE_* (CVE-2025-30156) : héritée du script PVE.
# PVE_CEPH_ALLOW_AUTH_INSECURE=1 filtre UNIQUEMENT ces codes aux gates ;
# toute dégradation réelle (PG, OSD, MON…) reste bloquante. Après --rotate-keys
# réussi, RETIRER cette variable : la santé doit être OK sans tolérance.

# --- Flags de maintenance (identiques au script PVE) -----------------------
# NB : 'noup'/'nodown' volontairement EXCLUS (ils masquent les pannes réelles).
CEPH_MAINT_FLAGS = ("noout", "norecover", "norebalance",
                    "nobackfill", "noscrub", "nodeep-scrub")

# --- Checks PG gelés par les flags de maintenance ---------------------------
# Checks WARN générés par le GEL du recovery/backfill/scrub PENDANT la
# fenêtre de maintenance : une PG « active+degraded » ou
# « active+undersized » (ex. vécu : PG « stuck peering » de longue date
# ressortie dégradée au retour d'une OSD) ne PEUT PAS guérir tant que
# norecover/nobackfill sont posés, et noscrub/nodeep-scrub gèlent aussi
# les checks de scrubs en retard. Les compter dans la santé effective
# aux gates = attente GARANTIE jusqu'au timeout (vécu : osd.16, 14 min
# de polls « 0 PG non active » alors que tout était opérationnel).
# Comme « non clean », ces checks sont donc attendus PENDANT la fenêtre
# uniquement (cf. ProxmoxClient.ceph_set_maintenance_window) ; la
# convergence finale, APRÈS le retrait des flags, les vérifie réellement.
CEPH_PG_FROZEN_CHECKS = ("PG_DEGRADED", "PG_UNDERSIZED",
                         "PG_NOT_SCRUBBED", "PG_NOT_DEEP_SCRUBBED")

# --- Fichier d'état (reprise après interruption) ---------------------------
STATE_FILE = _env("PVE_CEPH_STATE_FILE", "/var/lib/proxmox-ceph-updater/state.json")

# --- Sauvegarde des clés (mode --rotate-keys) ------------------------------
# Répertoire local (sur le worker) où sont archivées les keyrings régénérées
# (mon.keyring, client.admin.keyring…) — chmod 700, fichiers 0600. Le défaut
# est horodaté pour ne JAMAIS écraser une sauvegarde précédente.
KEY_BACKUP_DIR = _env("PVE_CEPH_KEY_BACKUP_DIR", "")

# --- Estimations (bilan dry-run, ajustables) -------------------------------
EST_APT_MIN = float(_env("PVE_EST_APT_MIN", "2"))
EST_UPGRADE_MIN = float(_env("PVE_EST_UPGRADE_MIN", "6"))
EST_RESTART_MON_S = float(_env("PVE_EST_RESTART_MON_S", "15"))
EST_RESTART_MGR_S = float(_env("PVE_EST_RESTART_MGR_S", "15"))
EST_RESTART_OSD_S = float(_env("PVE_EST_RESTART_OSD_S", "180"))
EST_RESTART_MDS_S = float(_env("PVE_EST_RESTART_MDS_S", "20"))
EST_KEY_ENTITY_S = float(_env("PVE_EST_KEY_ENTITY_S", "40"))
EST_STABILIZE_S = float(_env("PVE_EST_STABILIZE_S", "60"))

# Releases Ceph connues de Proxmox (pour la validation de --major).
KNOWN_RELEASES = {
    "squid": 19, "tentacle": 20, "reef": 18, "quincy": 17,
}

# Prérequis de la release CIBLE d'une montée majeure (wiki officiel
# Proxmox Ceph_Squid_to_Tentacle : PVE ≥ 9.1 avec pve-manager ≥ 9.1.4
# et ceph ≥ 19.2.3). Vérifiés nœud par nœud en préflight.
MAJOR_PREREQS = {
    "tentacle": {"pve": (9, 1, 4), "ceph": (19, 2, 3)},
}

# Version Ceph MINIMALE qui corrige CVE-2025-30156, par branche.
CVE_FIXED = {"19": (19, 2, 6), "20": (20, 2, 4)}

# Sharding RocksDB par défaut depuis Pacific (v16, GA avril 2021) : les
# OSDs créées AVANT (Octopus v15 et antérieures) sont NON shardées →
# piège META du wiki Squid→Tentacle (hausse d'usage RocksDB après la
# montée, jusqu'à 20.2.4). Le sharding réel ne se vérifie qu'OSD
# ARRÊTÉE (ceph-bluestore-tool show-sharding) : la préflight utilise
# l'heuristique non invasive de la date de création des répertoires.
PACIFIC_DEFAULT_SHARDING_TS = 1617235200  # 2021-04-01 00:00:00 UTC

# Noyau Linux minimum pour les clients noyau (CephFS/RBD in-guest) :
# support des clés aes256k depuis Linux 7.0 (clients utilisateurs : vérifiez
# vos VMs séparément — le script ne peut pas sonder les guests).
KERNEL_AES256K = (7, 0)


class SshTransportLost(Exception):
    """Perte de la connexion SSH (établissement ou mi-exécution) :
    retentable — l'enveloppe _ssh() reconnecte et rejoue la commande."""


# ---------------------------------------------------------------------------
# LOGS COLORÉS (identiques au script PVE)
# ---------------------------------------------------------------------------
class ColorFormatter(logging.Formatter):
    ENABLED = sys.stdout.isatty()
    COLORS = {
        logging.DEBUG:    "\033[90m",
        logging.INFO:    "\033[0m",
        logging.WARNING: "\033[93m",
        logging.ERROR:   "\033[91m",
        logging.CRITICAL:"\033[91;1m",
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
    PREFIX = {
        logging.DEBUG:    "··· DEBUG",
        logging.INFO:    "✔",
        logging.WARNING: "⚠ ATTENTION",
        logging.ERROR:   "✘ ERREUR",
        logging.CRITICAL:"⛔ FATAL",
    }

    def format(self, record):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        return (f"{stamp} [{record.levelname:<8}] "
                f"{self.PREFIX.get(record.levelno, '')} "
                f"{record.getMessage()}").rstrip()


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
    stderr (idempotent, installable avant le chargement de l'env)."""
    tee = sys.stderr
    if not isinstance(tee, _StderrTee):
        tee = _StderrTee(tee)
        sys.stderr = tee
    tee.attach(log_stream)


def setup_logger(verbose: bool, log_file: Optional[str] = None,
                 no_color: bool = False, force_color: bool = False) -> logging.Logger:
    logger = logging.getLogger("pve-ceph-update")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    ColorFormatter.ENABLED = (not no_color) and (force_color or sys.stdout.isatty())
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter())
    handlers = [handler]
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


def _est_hms(sec: float) -> str:
    sec = int(round(sec))
    if sec >= 3600:
        h, rem = divmod(sec, 3600)
        return f"{h}h{rem // 60:02d}min"
    if sec >= 60:
        return f"{sec // 60}min{sec % 60:02d}s"
    return f"{sec}s"


# ---------------------------------------------------------------------------
# CLIENT PROXMOX (API REST + SSH) — adapté du script PVE
# ---------------------------------------------------------------------------
class ProxmoxClient:
    """API REST (token) pour l'inventaire + SSH (clé) pour toutes les
    commandes ceph / systemctl / apt. Chaque méthode lève RuntimeError
    si échec. En mode dry-run, seules les méthodes de LECTURE sont
    appelées (l'Updater garantit qu'aucune action d'écriture n'est
    exécutée)."""

    CEPH_AUTH_INSECURE_PREFIX = "AUTH_INSECURE_"

    def __init__(self, logger: logging.Logger):
        self.log = logger
        self._ssh_pkey = None
        # Connexions SSH PERSISTANTES par nœud (un seul handshake par
        # nœud et par run, réutilisé pour toutes les commandes).
        self._ssh_cli: Dict[str, object] = {}
        try:
            from proxmoxer import ProxmoxAPI as _PxmApiClass
        except ImportError:
            from proxmoxer import Proxmox as _PxmApiClass
        self._Proxmox = _PxmApiClass
        self.api_hosts = list(API_HOSTS) if API_HOSTS else [API_HOST]
        self.api_host_idx = 0
        self.node_addr: Dict[str, str] = {}
        self._no_ceph = False
        self._connect_api()
        if not API_HOSTS:
            self._discover_hosts()

    # ---------- Découverte du cluster (identique au script PVE) ----------
    def _resolve_seed_ip(self, host: str) -> Optional[str]:
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def _resolve_node_ip(self, name: str, seed_ip: Optional[str]) -> Optional[str]:
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
                return same_subnet
            if first_ip:
                return first_ip
        except Exception as e:
            self.log.debug(f"API network illisible pour {name} : {e}")
        try:
            return socket.gethostbyname(name)
        except socket.gaierror:
            pass
        try:
            out = self._ssh(self.api_hosts[self.api_host_idx], f"getent hosts {name}")
            return out.split()[0]
        except Exception:
            return None

    def _discover_hosts(self):
        try:
            nodes = [n["node"] for n in self.api.nodes.get()]
        except Exception as e:
            self.log.warning(f"Découverte des nœuds impossible ({e}) — "
                             f"l'hôte graine {API_HOST} sera utilisé seul.")
            return
        if not nodes:
            self.log.warning("Aucun nœud renvoyé par l'API — graine conservée seule.")
            return
        current = self.api_hosts[self.api_host_idx]
        current_ip = self._resolve_seed_ip(current) or current
        addrs: Dict[str, str] = {}
        hosts: List[str] = []
        seed_name = None
        for name in sorted(nodes):
            ip = self._resolve_node_ip(name, current_ip) or name
            addrs[name] = ip
            if ip not in hosts:
                hosts.append(ip)
            if ip == current_ip and seed_name is None:
                seed_name = name
        self.api_hosts = hosts
        self.node_addr = addrs
        if seed_name is None:
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

    def _rotate_api_host(self, avoid: Optional[str] = None) -> bool:
        if len(self.api_hosts) < 2:
            return False
        for _ in range(len(self.api_hosts)):
            self.api_host_idx = (self.api_host_idx + 1) % len(self.api_hosts)
            if self.api_hosts[self.api_host_idx] != avoid:
                break
        self.log.warning(f"Bascule de l'hôte API vers "
                         f"{self.api_hosts[self.api_host_idx]}")
        self._connect_api()
        return True

    def with_api(self, fn, retries: int = 1, quiet: bool = False):
        """Exécute fn(prox) en gérant le failover entre hôtes API.
        Seules les erreurs de CONNEXION justifient une bascule."""
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
                deterministic = ("500 Request failed" not in msg
                                 and (" 595 " in msg or "Connection" in msg
                                      or "refused" in msg.lower()
                                      or "timed out" in msg.lower()))
                if not quiet:
                    self.log.debug(f"Appel API échoué ({attempts}/{max_attempts}) : {e}")
                if "guest agent is not running" in msg:
                    raise
                if not deterministic or attempts >= max_attempts:
                    raise RuntimeError(f"Appel API impossible après {attempts} "
                                       f"tentative(s) : {last_exc}") from last_exc
                self._rotate_api_host()
        raise RuntimeError(str(last_exc))

    def node_names(self) -> List[str]:
        try:
            return sorted(n["node"] for n in self.api.nodes.get())
        except Exception as e:
            raise RuntimeError(f"Impossible de lister les nœuds du cluster : {e}")

    # ---------- SSH (identique au script PVE) ----------
    def _get_ssh_pkey(self):
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
                    raise
                except (paramiko.SSHException, OSError):
                    continue
            return None

        passphrase = SSH_KEY_PASSPHRASE or None
        pkey = None
        try:
            pkey = _try_load(passphrase)
        except paramiko.PasswordRequiredException:
            if passphrase is not None:
                raise RuntimeError(
                    "La passphrase PVE_SSH_PASSPHRASE ne permet pas de "
                    f"déverrouiller la clé {SSH_PRIVATE_KEY} — vérifiez sa valeur.")
            if not sys.stdin.isatty():
                raise RuntimeError(
                    "La clé SSH est protégée par une passphrase mais le script "
                    "tourne sans terminal. Définissez PVE_SSH_PASSPHRASE dans "
                    "le fichier d'environnement.")
            passphrase = getpass.getpass(
                f"Passphrase de la clé SSH {SSH_PRIVATE_KEY} : ")
            pkey = _try_load(passphrase)
        if pkey is None:
            raise RuntimeError(f"Impossible de charger la clé SSH {SSH_PRIVATE_KEY} "
                               "(type non supporté ou passphrase incorrecte).")
        self._ssh_pkey = pkey
        return self._ssh_pkey

    def _ssh(self, node: str, cmd: str, stream: bool = False,
             retries: Optional[int] = None) -> str:
        if retries is None:
            retries = SSH_RETRIES
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            if attempt:
                wait = min(60, 15 * attempt)
                self.log.warning(f"Perte de connexion SSH avec {node} — nouvelle "
                                 f"tentative {attempt + 1}/{retries + 1} dans {wait}s…")
                time.sleep(wait)
            try:
                return self._ssh_once(node, cmd, stream)
            except SshTransportLost as e:
                last_exc = e
        raise RuntimeError(f"{node} est resté injoignable en SSH après "
                            f"{retries + 1} tentatives ({last_exc}) — si le "
                            f"nœud rejette les connexions en rafale, "
                            f"vérifiez fail2ban/sshguard ou la limite "
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
        addr = self.node_addr.get(node, node)
        # Connexion PERSISTANTE : réutilisée si vivante, sinon recréée.
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
                self._ssh_drop(node)
                raise SshTransportLost(f"connexion SSH à {addr} impossible ({e})")
            cli.get_transport().set_keepalive(15)
            self._ssh_cli[node] = cli
        try:
            stdin, stdout, stderr = cli.exec_command(cmd, get_pty=True)
            stdin.close()
            buf = ""
            if stream:
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
                        while chan.recv_ready():
                            pending += chan.recv(4096).decode("utf-8", "replace")
                        break
                    if not transport.is_active():
                        raise SshTransportLost(
                            f"connexion perdue pendant '{cmd}' sur {node}")
                    time.sleep(0.2)
                if pending.strip():
                    self.log.info(f"    │ {pending.rstrip()}")
                    buf += pending
                rc = chan.recv_exit_status()
            else:
                buf = stdout.read().decode()
                err = stderr.read().decode().strip()
                rc = stdout.channel.recv_exit_status()
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

    def ssh_any(self, cmd: str, prefer: Optional[str] = None,
                nodes: Optional[List[str]] = None) -> Tuple[str, str]:
        """Exécute une commande Ceph CLUSTER-WIDE (« toutes les commandes
        commençant par ceph ne sont à lancer qu'une fois, sur n'importe
        quel nœud » — wiki PVE). Essaie `prefer` puis tous les nœuds ;
        retourne (node, sortie)."""
        order = []
        if prefer:
            order.append(prefer)
        for n in (nodes or self.node_names()):
            if n not in order:
                order.append(n)
        last: Optional[Exception] = None
        for n in order:
            try:
                return n, self._ssh(n, cmd)
            except RuntimeError as e:
                last = e
                continue
        raise RuntimeError(f"Commande '{cmd}' impossible sur tous les nœuds "
                            f"({last})")

    def apt_update(self, node: str):
        """apt update avec auto-réparation dpkg (identique au script PVE).
        Lecture/rafraîchissement : exécuté aussi en dry-run (précédent
        du script PVE — rafraîchir les listes n'installe rien)."""
        self.log.info(f"{node}: apt update (rafraîchissement des listes)…")
        try:
            audit = self._ssh(node, "dpkg --audit 2>/dev/null")
            if audit.strip():
                self.log.warning(f"{node}: dpkg INCOMPLET détecté — fin de "
                                 f"la configuration (dpkg --configure -a)…")
                self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                          "dpkg --configure -a", stream=True)
        except Exception as e:
            self.log.warning(f"{node}: audit dpkg impossible ({e}) — poursuite.")
        self._ssh(node, "apt-get update -q")

    def apt_upgrade(self, node: str):
        """apt full-upgrade en streaming (identique au script PVE)."""
        self.log.info(f"{node}: apt full-upgrade (streaming)…")
        self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                       "NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1 "
                       "apt-get full-upgrade -y -q "
                       "-o DPkg::Lock::Timeout=600 "
                       "-o Dpkg::Options::=--force-confdef "
                       "-o Dpkg::Options::=--force-confold",
                  stream=True)

    def apt_sim_all(self, node: str) -> Optional[Tuple[List[Tuple[str, str]],
                                                       List[str]]]:
        """Simulation « apt-get -s full-upgrade » (lecture pure —
        rien n'est installé ni retiré). Retourne (paquets Ceph
        [(nom, version_cible)], autres paquets [noms]) ou None si la
        sortie apt est ILLISIBLE (échec ssh/apt) : l'appelant peut
        distinguer « rien à faire » de « je ne sais pas »."""
        try:
            out = self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                                  "apt-get -s full-upgrade -q")
        except Exception:
            return None
        ceph: List[Tuple[str, str]] = []
        others: List[str] = []
        for m in re.finditer(r"^Inst (\S+) \((\S+)", out, re.M):
            name = m.group(1)
            if re.search(r"^(ceph|rados|librbd|libcephfs|librados|"
                         r"python3-rbd|python3-cephfs|rbd-nbd)", name):
                ceph.append((name, m.group(2)))
            else:
                others.append(name)
        return (ceph, others)

    def ceph_pkg_pending(self, node: str,
                         others: Optional[List[str]] = None
                         ) -> List[Tuple[str, str]]:
        """Paquets Ceph en attente de mise à jour sur un nœud (simulation
        apt -s, lecture pure) : [(nom, version_cible)]. Si `others` est
        fourni (liste à remplir), il reçoit les paquets NON-Ceph que le
        « apt-get full-upgrade » du script mettrait AUSSI à jour
        (full-upgrade est global, pas limité à Ceph)."""
        res = self.apt_sim_all(node)
        if res is None:
            return []
        ceph, oth = res
        if others is not None:
            others.extend(oth)
        return ceph

    # ---------- Santé Ceph (adapté du script PVE) ----------
    def ceph_status(self) -> Optional[Dict]:
        """Santé Ceph via GET /cluster/ceph/status ; None si pas de Ceph."""
        if self._no_ceph:
            return None
        try:
            return self.with_api(lambda p: p.cluster.ceph.status.get())
        except Exception as e:
            msg = str(e)
            if ("binary not installed" in msg
                    or "pveceph configuration not initialized" in msg
                    or "501" in msg):
                self._no_ceph = True
            return None

    @staticmethod
    def _ceph_allow_auth_insecure() -> bool:
        return str(_env("PVE_CEPH_ALLOW_AUTH_INSECURE", "0")) == "1"

    @staticmethod
    def _osdmap_flags_all_maintenance(chk: Dict) -> bool:
        """True si le check OSDMAP_FLAGS signale EXCLUSIVEMENT des
        flags de maintenance (CEPH_MAINT_FLAGS) — posés par ce run ou
        par un administrateur pour une fenêtre de maintenance
        volontaire. Le WARN correspondant n'est PAS une dégradation
        réelle : pendant tout le run ces flags sont posés, et la
        santé ne peut JAMAIS revenir à HEALTH_OK avant leur retrait —
        sans ce filtrage, chaque gate attendrait son timeout (30 min)
        puis échouerait. Un flag NON-maintenance (pause, full, noup,
        nodown, in…) reste compté comme dégradation."""
        try:
            msg = str((chk.get("summary") or {}).get("message") or "")
        except Exception:
            return False
        m = re.match(r"(.*?)\s*flag\(s\)\s*set", msg.strip())
        if not m:
            return False
        flags = [f.strip() for f in m.group(1).split(",") if f.strip()]
        return bool(flags) and all(f in CEPH_MAINT_FLAGS for f in flags)

    def _osd_upgrade_finished_expected(self, chk: Dict) -> bool:
        """True si le check OSD_UPGRADE_FINISHED (« all OSDs are
        running tentacle or later but require_osd_release <
        tentacle ») signale la release CIBLE du run en cours. C'est
        le signal du monitor que la mise à jour des OSDs est
        TERMINÉE — il ne disparaît QUE quand « require_osd_release »
        est relevé, ce que CE run fait en Phase G (après les MDS,
        ordre du wiki). L'exiger HEALTH_OK à la gate de la Phase E
        condamnait le run à un timeout GARANTI : le check ne PEUT
        PAS disparaître avant la commande que le run n'exécute
        qu'à la FIN (vécu 09:12 : restart ceph-osd.target, OSDs
        up/quorum complet/PGs actives tous OK, > 5 min de polls
        sur ce SEUL check restant, run tué au Ctrl-C avant la
        phase MDS). Toléré si et seulement si la release nommée est
        la CIBLE du run (--major) : pas de cible (modes mineur /
        rotate-keys) ou release différente (montée précédente
        inachevée) → reste BLOQUANT (diagnostic affiché, preflight
        refusé). La Phase G pose require-osd-release → le check
        disparaît → la convergence finale le vérifie pour de vrai."""
        target = getattr(self, "_osd_require_target", "") or ""
        if not target:
            return False
        try:
            msg = str((chk.get("summary") or {}).get("message") or "")
        except Exception:
            return False
        return f"running {target} or later" in msg

    def ceph_set_maintenance_window(self, on: bool) -> None:
        """Marque l'ouverture/fermeture de la fenêtre de maintenance de
        CE run (nos flags à nous) : PENDANT la fenêtre, les checks PG
        gelés par norecover/nobackfill/noscrub
        (CEPH_PG_FROZEN_CHECKS — PG dégradée/undersized qui ne PEUT
        PAS guérir avant le retrait des flags) sont attendus et
        comptés hors dégradation, comme « non clean ». NB : depuis la
        reprise 09:01 (2 PG « active+recovery_wait+degraded » + flags
        déjà posés sur le cluster → preflight REFUSÉ alors que rien
        n'était guérissable), la tolérance s'applique aussi HORS
        fenêtre dès que le statut porte un OSDMAP_FLAGS
        exclusivement-maintenance (flags posés, quel que soit l'auteur)
        — cf. _health_parts ; la convergence finale re-vérifie après
        le retrait."""
        self._maint_window = bool(on)

    def _health_parts(self, st: Optional[Dict]) -> Tuple[str, Tuple[str, ...],
                                                        Set[str], Dict]:
        """Classification commune des checks de santé — utilisée par la
        santé effective, le diagnostic et les gates (une seule source
        de vérité). Retourne (status, ignored_AUTH, skipped_attendus,
        blocking) :
        - ignored : AUTH_INSECURE_* si (et seulement si)
          PVE_CEPH_ALLOW_AUTH_INSECURE=1 (avertissement cephx dédié) ;
        - skipped (sans ignored, ajoutés en plus) : OSDMAP_FLAGS
          exclusivement-maintenance, les checks PG gelés par les
          flags (CEPH_PG_FROZEN_CHECKS) DÈS QUE des flags de
          maintenance sont posés — par ce run (fenêtre) OU déjà
          présents sur le cluster (admin/run interrompu : le check
          OSDMAP_FLAGS du même statut en est la preuve) : tant que
          norecover/nobackfill gèlent le recovery, une PG
          « active+recovery_wait+degraded » NE PEUT PAS guérir, et
          l'exiger condamne preflight et gates à un refus/timeout
          éternels (vécu : reprise 09:01, 2 PG recovery_wait + flags
          posés → REFUSÉ au preflight alors que rien n'est guérissable
          avant leur retrait) ; et OSD_UPGRADE_FINISHED quand il
          signale la release CIBLE du run (--major :
          _osd_upgrade_finished_expected) : toutes les OSDs
          tournent déjà en cible mais « require_osd_release » n'est
          relevé qu'en Phase G (après les MDS) — l'exiger aux gates
          de la Phase E attendait une condition que le run
          lui-même ne crée qu'à la fin (vécu 09:12 : > 5 min de
          polls, run tué au Ctrl-C avant la phase MDS) ;
        - blocking : tout le reste, qui compte dans la santé effective
          et doit être résolu avant de poursuivre. La convergence
          finale, APRÈS retrait des flags, re-vérifie les checks PG
          pour de vrai (hors flags ils redeviennent bloquants)."""
        h = (st.get("health") or {})
        status = h.get("status", "?")
        checks = h.get("checks") or {}
        ignored = tuple(sorted(
            c for c in checks
            if c.startswith(self.CEPH_AUTH_INSECURE_PREFIX)))
        if ignored and not self._ceph_allow_auth_insecure():
            ignored = ()
        skipped = set(ignored)
        maint_flags_set = False
        for c in checks:
            if (c == "OSDMAP_FLAGS"
                    and self._osdmap_flags_all_maintenance(checks[c])):
                skipped.add(c)
                maint_flags_set = True
            if (c == "OSD_UPGRADE_FINISHED"
                    and self._osd_upgrade_finished_expected(checks[c])):
                skipped.add(c)
        if maint_flags_set or getattr(self, "_maint_window", False):
            for c in checks:
                if c in CEPH_PG_FROZEN_CHECKS:
                    skipped.add(c)
        blocking = {c: v for c, v in checks.items() if c not in skipped}
        return status, ignored, skipped, blocking

    def ceph_effective_health(self, st: Optional[Dict]) -> Tuple[str, Tuple[str, ...]]:
        """(santé effective, codes AUTH tolérés) : recompte la santé
        après filtrage des checks « attendus » (cf. _health_parts) :
        AUTH_INSECURE_* si PVE_CEPH_ALLOW_AUTH_INSECURE=1 — retournés
        dans `ignored` (le log cephx les affiche) ; OSDMAP_FLAGS
        silencieusement quand il signale EXCLUSIVEMENT des flags de
        maintenance ; les checks PG gelés par le recovery/backfill/scrub
        dès que des flags de maintenance sont posés (fenêtre de ce run
        OU déjà présents sur le cluster) ; et OSD_UPGRADE_FINISHED
        quand il nomme la release CIBLE du run --major (toutes les
        OSDs en cible, require-osd-release relevé plus tard par ce
        même run). HORS flags, une PG dégradée
        reste bloquante : le preflight doit la voir, et la convergence
        finale la re-vérifie après le retrait."""
        if st is None:
            return "?", ()
        _, ignored, skipped, blocking = self._health_parts(st)
        if not skipped:
            return (st.get("health") or {}).get("status", "?"), ()
        sevs = [str((c or {}).get("severity", "")) for c in blocking.values()]
        if any("ERR" in sev for sev in sevs):
            return "HEALTH_ERR", ignored
        if any("WARN" in sev for sev in sevs):
            return "HEALTH_WARN", ignored
        return "HEALTH_OK", ignored

    def ceph_log_auth_insecure(self, ignored: Tuple[str, ...]) -> None:
        """Avertissement cephx (CVE-2025-30156) — imprimé SEULEMENT
        quand l'ensemble des codes tolérés CHANGE : ces codes sont
        identiques à CHAQUE interrogation de santé (preflight, chaque
        gate, chaque poll de 15 s) ; les répéter à chaque arrêt /
        redémarrage d'OSD noyait les messages de convergence."""
        sig = tuple(ignored)
        if sig == getattr(self, "_auth_insecure_sig", None):
            return
        self._auth_insecure_sig = sig
        self.log.warning(
            f"[Ceph] PVE_CEPH_ALLOW_AUTH_INSECURE=1 : {len(ignored)} "
            f"check(s) de sécurité cephx toléré(s) ({', '.join(ignored)}) — "
            f"avis cryptographique (CVE-2025-30156, clés « aes »), sans "
            f"impact IO/daemons. Remédiation définitive : --rotate-keys "
            f"(migration des clés vers « aes256k »).")

    def ceph_diagnose(self, st: Optional[Dict],
                      force: bool = False) -> None:
        """Dump des dégradations BLOQUANTES, sans le bruit attendu :
        les checks AUTH_INSECURE_* tolérés (avertissement cephx dédié,
        imprimé une seule fois), OSDMAP_FLAGS exclusivement de
        maintenance (posés par le run lui-même) et — pendant la
        fenêtre — les checks PG gelés par les flags sont MASQUÉS ; les
        redumper ~40 lignes à chaque gate de la Phase E (une par OSD,
        polls de 15 s) noyait l'information principale (OSD down, PG
        non active…). Un diagnostic IDENTIQUE au précédent n'est PAS
        réimprimé ; appelé à CHAQUE poll, il ne réapparaît que si les
        dégradations CHANGENT (`force=True` : contexte complet forcé
        sur les chemins d'échec/abort)."""
        if st is None:
            return
        status, _ignored, skipped, blocking = self._health_parts(st)
        if status == "HEALTH_OK" and not blocking:
            return
        sig: List[tuple] = []
        for code, c in sorted(blocking.items()):
            sig.append((code, str(c.get("severity", "?")),
                        str(((c.get("summary") or {}).get("message")
                             or "")).strip(),
                        tuple(str((d.get("message") or "")).strip()
                              .replace("\n", " ")[:200]
                              for d in (c.get("detail") or [])[:6])))
        sig = tuple(sig)
        if sig == getattr(self, "_diag_sig", None) and not force:
            return
        self._diag_sig = sig
        header = f"[Ceph] Diagnostic ({status}"
        if skipped:
            header += f" — hors {len(skipped)} check(s) toléré(s)/attendu(s)"
        self.log.warning(header + " :")
        if not blocking:
            if skipped:
                self.log.warning(
                    "    aucune dégradation BLOQUANTE — les check(s) "
                    "présents sont tolérés (AUTH_INSECURE_*) ou "
                    "attendus (flags de maintenance / PG gelées par "
                    "le recovery) ; cause de l'attente ci-dessous "
                    "(quorum, PGs, OSDs).")
            else:
                self.log.warning(
                    "    santé dégradée sans détail de check — consultez "
                    "« ceph -s » / « ceph health detail » sur un nœud ; "
                    "cause de l'attente ci-dessous (quorum, PGs, OSDs).")
            return
        for code, c in sorted(blocking.items()):
            sev = c.get("severity", "?")
            msg = ((c.get("summary") or {}).get("message") or "").strip()
            self.log.warning(f"    {code} [{sev}] : {msg}")
            for d in (c.get("detail") or [])[:6]:
                dm = ((d.get("message") or "").strip().replace("\n", " "))
                if dm:
                    self.log.warning(f"        {dm[:200]}")

    # ---------- Commandes Ceph via SSH ----------
    @staticmethod
    def _json_lenient(out: str) -> Optional[object]:
        """Décode le PREMIER objet JSON d'une sortie qui comporte du
        texte APRÈS lui. Cas vécu (cluster réel, 09:35) : « ceph fs
        dump -f json » imprime le JSON compact sur SA première ligne,
        puis une ligne vide, puis « dumped fsmap epoch N » — le
        json.loads() intégral échouait avec « Extra data: line 3
        column 1 (char …) » et le run --execute avortait en Phase F
        (« MDS actives illisibles », refus d'arrêter les MDS à
        l'aveugle) alors que le JSON était parfaitement valide.
        raw_decode lit le PREMIER objet et ignore le reste ; None si
        la sortie ne commence pas par du JSON."""
        try:
            return json.loads(out)
        except ValueError:
            pass
        try:
            obj, _end = json.JSONDecoder().raw_decode(out.lstrip())
            return obj
        except ValueError:
            return None

    def ceph_json(self, cmd: str, node: Optional[str] = None) -> Dict:
        """Exécute une commande ceph --format json (lecture pure) et
        décode le JSON (tolérant aux lignes traînées après l'objet,
        cf. _json_lenient). `node` facultatif : sinon premier nœud
        joignable."""
        cmdj = cmd if "--format" in cmd else f"{cmd} --format json"
        if node:
            out = self._ssh(node, cmdj)
        else:
            _, out = self.ssh_any(cmdj)
        data = self._json_lenient(out)
        if data is None:
            raise RuntimeError(f"Sortie non-JSON de « {cmd} » : "
                               f"{out.strip()[:200]}")
        return data

    def ceph_run(self, cmd: str, node: Optional[str] = None,
                 stream: bool = False) -> str:
        """Exécute une commande ceph MUTANTE (hors dry-run uniquement —
        l'Updater logge [SIMULATION] et n'appelle pas cette méthode)."""
        if node:
            return self._ssh(node, cmd, stream=stream)
        _, out = self.ssh_any(cmd)
        return out

    # ---------- Flags de maintenance (adapté du script PVE) ----------
    def ceph_flags_current(self, node: Optional[str] = None) -> Optional[Dict[str, bool]]:
        try:
            if node:
                out = self._ssh(node, "ceph osd dump --format json")
            else:
                _, out = self.ssh_any("ceph osd dump --format json")
            dump = json.loads(out)
            fl = dump.get("flags") or ""
            return {f.strip(): True for f in fl.split(",")
                    if f.strip() and f.strip() != "hash-"}
        except Exception:
            return None

    def ceph_maintenance_on(self,
                            adopted: Optional[List[str]] = None
                            ) -> Dict[str, bool]:
        """Pose les flags de maintenance (globaux au cluster). Retourne
        UNIQUEMENT les flags NOUVELLEMENT posés par CE RUN ; les flags
        déjà posés ne sont ni reposés ni retirés ICI — leur revente
        en fin de run est portée par l'appelant via `flags_we_set`
        (flags adoptés d'un run précédent + flags posés ici). Un
        flag déjà posé et signalé dans `adopted` (orphelin d'un run
        précédent interrompu) est loggé comme ADOPTÉ — les autres
        sont considérés posés par un administrateur et laissés
        intacts."""
        adopted = set(adopted or ())
        cur = self.ceph_flags_current()
        if cur is None:
            raise RuntimeError("Impossible de lire les flags Ceph — "
                               "refus de continuer sans visibilité.")
        changed: Dict[str, bool] = {}
        for f in CEPH_MAINT_FLAGS:
            if f in cur:
                if f in adopted:
                    self.log.info(f"[Ceph] flag {f} déjà posé — ADOPTÉ "
                                  f"(run précédent interrompu), sera "
                                  f"retiré à la fin de celui-ci.")
                else:
                    self.log.info(f"[Ceph] flag {f} déjà posé (admin) — "
                                  f"conservé.")
                continue
            self.ceph_run(f"ceph osd set {f}")
            changed[f] = True
        if changed:
            self.log.info(f"[Ceph] Maintenance Ceph : flags posés "
                          f"({', '.join(sorted(changed))}) — le cluster ne "
                          f"reconstruit RIEN pendant la fenêtre.")
        return changed

    def ceph_maintenance_off(self, changed: Dict[str, bool]) -> None:
        """Retire UNIQUEMENT les flags posés par le run (les vôtres
        restent). Essaie tous les nœuds jusqu'à un SSH qui répond."""
        if not changed:
            return
        removed: List[str] = []
        reachable = False
        for n in self.node_names():
            try:
                self._ssh(n, "ceph osd dump >/dev/null 2>&1")
                reachable = True
                for f in sorted(changed):
                    try:
                        self._ssh(n, f"ceph osd unset {f}")
                        removed.append(f)
                    except Exception as e:
                        self.log.warning(f"[Ceph] flag {f} non retiré ({e}) — "
                                         f"retrait manuel requis.")
                break
            except Exception:
                continue
        if removed:
            self.log.info(f"[Ceph] Maintenance Ceph : flags retirés "
                          f"({', '.join(removed)}) — le cluster reprend son "
                          f"fonctionnement nominal.")
        if not reachable:
            self.log.error(f"[Ceph] IMPOSSIBLE de contacter Ceph : flags "
                           f"{', '.join(sorted(changed))} NON retirés — "
                           f"retrait manuel : « ceph osd unset <flag> ».")

    # ---------- Inventaire Ceph ----------
    def node_daemons(self, node: str) -> Dict[str, List[str]]:
        """Daemons Ceph hébergés par un nœud, lus depuis son filesystem
        (source de vérité : /var/lib/ceph) + systemd. Retourne
        {'mon': [ids], 'mgr': [ids], 'osd': [ids], 'mds': [ids]}.
        Lecture pure : dry-run OK."""
        out = self._ssh(node, (
            "for t in mon mgr osd mds bootstrap-osd bootstrap-mds "
            "bootstrap-mgr bootstrap-rgw bootstrap-rbd; do "
            f"for d in /var/lib/ceph/$t/; do "
            "[ -d \"$d\" ] || continue; "
            "for i in \"$d\"*; do "
            "[ -e \"$i\" ] || continue; "
            "b=$(basename \"$i\"); "
            "case \"$b\" in ceph-*) echo \"$t ${b#ceph-}\";; esac; "
            "done; done; done"))
        res: Dict[str, List[str]] = {"mon": [], "mgr": [], "osd": [],
                                     "mds": []}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] in res:
                if parts[1] not in res[parts[0]]:
                    res[parts[0]].append(parts[1])
        for t in res:
            res[t] = sorted(res[t], key=lambda x: (int(x) if x.isdigit()
                                                   else 0, x))
        return res

    def osds_of_node_tree(self) -> Dict[str, List[int]]:
        """Carte nœud → ids d'OSD via « ceph osd tree » (CRUSH : les
        hosts y portent le NOM Proxmox du nœud). Lecture pure."""
        tree = self.ceph_json("ceph osd tree")
        by_id = {n.get("id"): n for n in (tree.get("nodes") or [])}
        hosts: Dict[str, List[int]] = {}
        for n in tree.get("nodes") or []:
            if n.get("type") == "host":
                hname = n.get("name", "?")
                hosts.setdefault(hname, [])
                for cid in n.get("children") or []:
                    child = by_id.get(cid)
                    if child is not None and child.get("type") == "osd":
                        hosts[hname].append(int(cid))
        return {h: sorted(set(v)) for h, v in hosts.items()}

    def osd_up_status(self) -> Dict[int, Dict]:
        """{osd_id: {'up': bool, 'in': bool}} via « ceph osd dump ».
        Format RÉEL du dump (vérifié sur cluster vivant, squid ET
        tentacle) : chaque OSD est identifiée par le champ « osd »
        (PAS « id » — une lecture par « id » rangeait TOUTES les OSDs
        sous la seule clé -1 : la gate OSD n'apercevait alors JAMAIS
        les ids attendues et attendait indéfiniment des OSDs pourtant
        'up', santé HEALTH_OK). L'état vient de « state » (liste
        ["exists", "up"] ou chaîne « exists,up ») avec secours sur
        les entiers legacy « up »/« in » (0/1). Lecture pure."""
        dump = self.ceph_json("ceph osd dump")
        res: Dict[int, Dict] = {}
        for o in dump.get("osds", []):
            oid = int(o.get("osd", o.get("id", -1)))
            raw = o.get("state", "")
            states = (raw if isinstance(raw, list)
                      else str(raw).replace(",", " ").split())
            up_i = o.get("up")
            in_i = o.get("in")
            res[oid] = {
                "up": ("up" in states
                       or (up_i is not None and int(up_i) == 1)),
                "in": (("exists" in states and "out" not in states)
                       or (in_i is not None and int(in_i) == 1)),
            }
        return res

    def mon_quorum_complete(self, st: Optional[Dict] = None) -> bool:
        """Tous les mons déclarés sont-ils dans le quorum ?"""
        if st is None:
            st = self.ceph_status()
        if st is None:
            return False
        mm = (st.get("monmap") or {})
        quorum = mm.get("quorum") or []
        num = mm.get("num_mons", len(mm.get("mons", [])))
        return len(quorum) >= int(num or 0)

    def mon_names(self) -> List[str]:
        """Noms des mons (l'identifiant PVE = nom du nœud hôte)."""
        try:
            dump = self.ceph_json("ceph mon dump")
        except Exception:
            return []
        return [m.get("name", "?") for m in dump.get("mons", [])]

    def ceph_versions(self) -> Dict[str, Dict[str, int]]:
        """« ceph versions » : {type_daemon: {version: nb}}. Lecture pure."""
        try:
            return self.ceph_json("ceph versions")
        except Exception:
            return {}

    def osd_running_versions(self) -> Dict[int, Tuple[int, str]]:
        """Versions COURANTES des daemons OSD (« ceph osd metadata ») :
        {osd_id: (majeur, release)}. Un daemon qui TOURNE déjà sur la
        release cible a nécessairement été redémarré APRÈS l'upgrade
        des paquets (le processus ne change pas de binaire tout seul)
        — c'est la preuve de reprise idempotente de la Phase E : cette
        OSD n'a plus rien à gagner d'un nouveau cycle stop/start.
        Échec de lecture → {} : échec SÛR, aucune OSD n'est sautée."""
        try:
            arr = self.ceph_json("ceph osd metadata")
        except Exception:
            return {}
        out: Dict[int, Tuple[int, str]] = {}
        if not isinstance(arr, list):
            return out
        for m in arr:
            try:
                oid = int(str(m.get("id")))
                ver = str(m.get("ceph_version") or "")
                rel = str(m.get("ceph_release") or "").strip()
                mm = re.search(r"(\d+)\.", ver)
                if mm:
                    maj = int(mm.group(1))
                else:
                    maj = KNOWN_RELEASES.get(rel, 0)
                if maj:
                    out[oid] = (maj, rel)
            except (TypeError, ValueError):
                continue
        return out

    def tell_running_version(self, dtype: str, did: str) -> Tuple[int, str]:
        """Version COURANTE du PROCESSUS d'un daemon mon/mgr/mds.

        Source 1 : « ceph tell <type>.<id> version » (lecture pure,
        routée par les mons — exécutable depuis n'importe quel nœud).
        Sortie réelle : {"version": "ceph version 20.2.5 (hash)
        tentacle (stable)"} sur sa propre ligne. Limite VÉCUE 10:34 :
        les mgrs STANDBY ne répondent pas tous au tell — 2 mgrs sur 3
        déjà en tentacle étaient annoncés « à redémarrer » alors que
        « ceph versions » les montrait en tentacle — d'où la source 2.

        Source 2 (repli) : « ceph <type> metadata » — JSON listé par
        le mon pour TOUS les daemons du type, standbys compris
        (champs « ceph_version_short » ex. 20.2.5 + « ceph_release »
        ex. tentacle) ; tolérant aux lignes traînées (cf.
        _json_lenient).

        C'est la contrepartie mons/mgrs/mds de « ceph osd metadata »
        pour les OSDs : un daemon qui TOURNE déjà sur la release
        cible a nécessairement été redémarré APRÈS l'upgrade des
        paquets (le processus ne change pas de binaire tout seul) —
        le redémarrer de nouveau ne lui apporte RIEN (vécu 09:34 : 3
        mons et 3 mgrs déjà en tentacle re-redémarrés pour rien à
        CHAQUE reprise). Retour (0, "") si les DEUX sources restent
        illisibles (daemon down, sortie inattendue) : l'appelant NE
        saute PAS le daemon — échec SÛR, on le redémarre
        (comportement historique du wiki) en le disant dans le log."""
        # Source 1 : le daemon lui-même répond-il au tell ?
        try:
            _, out = self.ssh_any(f"ceph tell {dtype}.{did} version")
            data = self._json_lenient(out)
            if isinstance(data, dict):
                ver, rel = self._parse_daemon_version(
                    str(data.get("version") or ""))
                if ver:
                    return (ver, rel)
        except Exception:
            pass
        # Source 2 (repli) : le mon liste les daemons du type et
        # leurs versions — répond même quand le tell est ignoré.
        try:
            ents = self.ceph_json(f"ceph {dtype} metadata")
        except Exception:
            return (0, "")
        if not isinstance(ents, list):
            return (0, "")
        for ent in ents:
            if not isinstance(ent, dict):
                continue
            # identifiant polymorphe : mon/mgr/mds ne rangent pas
            # le nom au même endroit (« name » vs « id »).
            if did not in (str(ent.get("id") or ""),
                           str(ent.get("name") or "")):
                continue
            short = str(ent.get("ceph_version_short") or "")
            m = re.match(r"(\d+)\.", short)
            if m:
                return (int(m.group(1)), str(ent.get("ceph_release") or ""))
            ver, rel = self._parse_daemon_version(
                str(ent.get("ceph_version") or ""))
            if ver:
                return (ver, rel)
        return (0, "")

    @staticmethod
    def _parse_daemon_version(ver: str) -> Tuple[int, str]:
        """(majeure, release) d'une chaîne « ceph version 20.2.5
        (hash) tentacle (stable) » ; (0, "") si illisible."""
        m = re.search(r"(\d+)\.", ver)
        if not m:
            return (0, "")
        rm = re.search(r"\)\s+([a-z]+)\s+\(", ver)
        return (int(m.group(1)), rm.group(1) if rm else "")

    def pkg_ceph_version(self, node: str) -> str:
        """Version du paquet Ceph installé sur un nœud (dpkg)."""
        try:
            out = self._ssh(node,
                            "dpkg-query -W -f='${Version}' ceph-common 2>/dev/null")
            return out.strip() or "?"
        except Exception:
            return "?"

    def pve_manager_version(self, node: str) -> Tuple[int, ...]:
        """Version de pve-manager sur un nœud (ex. (9, 2, 20)). ()
        si indéterminée — ne bloque jamais le run par principe."""
        try:
            out = self._ssh(node, "pveversion")
            m = re.search(r"pve-manager/(\d+(?:\.\d+)*)", out)
            if m:
                return tuple(int(x) for x in m.group(1).split("."))
        except Exception:
            pass
        return ()

    def osd_dirs_info(self, node: str) -> Dict[int, Tuple[str, float]]:
        """Répertoire de données + date de naissance (birth, fallback
        mtime) de chaque OSD du nœud : {osd_id: (path, ts)}. Le path
        sert au test RÉEL du sharding RocksDB (ceph-bluestore-tool
        show-sharding, OSD arrêtée), la date à l'heuristique du piège
        META du wiki. Lecture pure, sans risque."""
        out = self._ssh(
            node, "stat -c '%n|%W|%Y' /var/lib/ceph/osd/* 2>/dev/null")
        res: Dict[int, Tuple[str, float]] = {}
        for ln in out.splitlines():
            parts = ln.strip().split("|")
            if len(parts) != 3:
                continue
            m = re.search(r"(\d+)$", parts[0])
            if not m:
                continue
            try:
                birth = float(parts[1])
                mtime = float(parts[2])
            except ValueError:
                continue
            # %W = 0 quand le FS ne fournit pas le birth time (ex. ZFS)
            res[int(m.group(1))] = (parts[0], birth or mtime)
        return res

    def osd_dir_birthdays(self, node: str) -> Dict[int, float]:
        """Date de naissance de chaque OSD du nœud, en secondes epoch :
        {osd_id: ts}. Heuristique non invasive pour le piège META du
        wiki : le sharding RocksDB réel ne se vérifie qu'OSD ARRÊTÉE
        (ceph-bluestore-tool show-sharding)."""
        return {oid: ts for oid, (_p, ts)
                in self.osd_dirs_info(node).items()}

    def ceph_repo_branch(self, node: str) -> str:
        """Branche du dépôt Ceph configurée sur le nœud (ex. squid)."""
        try:
            out = self._ssh(
                node,
                "grep -rhoE 'ceph-[a-z]+' /etc/apt/sources.list.d/ "
                "/etc/apt/sources.list 2>/dev/null | head -1")
            m = re.search(r"ceph-([a-z]+)", out.strip())
            return m.group(1) if m else "?"
        except Exception:
            return "?"

    def ceph_repo_files(self, node: str, branch: str) -> List[str]:
        """Fichiers qui déclarent le dépôt ceph-<branch> sur le nœud
        (chemins réels). Le nom n'est PAS standardisé (ceph.list,
        ceph.sources, pveceph.list, /etc/apt/sources.list…) : un sed
        sur des chemins codés en dur échoue avec le code 2 quand le
        fichier n'existe pas. Lecture pure, dry-run OK.

        PIÈGE (vécu RHOSPDC, dry-run --major tentacle) : grep sort 2
        dès qu'UN des chemins passés en ARGUMENT est en erreur (ex.
        /etc/apt/sources.list ABSENT — c'est le cas d'un nœud migré
        100 % en .sources deb822), MÊME s'il a trouvé des
        correspondances : les fichiers trouvés sont déjà imprimés
        sur stdout, mais _ssh lève sur rc≠0 et l'appelant
        transformait l'échec en « aucun fichier trouvé » — bascule
        MANUELLE réclamée alors que ceph.sources était bien là
        (d'où le log contradictoire : preflight « dépôt ceph-squid »
        — la détection de branche pipe dans head -1, qui MASQUE le
        code retour de grep — puis Phase A « aucun fichier
        déclarant le dépôt trouvé »). D'où le « || true » : le code
        retour est forcé à 0 et les correspondances sont conservées
        — un chemin en erreur ne masque plus jamais les fichiers
        trouvés de l'autre chemin."""
        out = self._ssh(
            node,
            f"grep -rls 'ceph-{branch}' /etc/apt/sources.list.d/ "
            f"/etc/apt/sources.list 2>/dev/null || true")
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

    def kernel_version(self, node: str) -> Tuple[int, int]:
        try:
            out = self._ssh(node, "uname -r")
            m = re.match(r"(\d+)\.(\d+)", out.strip())
            return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        except Exception:
            return (0, 0)

    def ceph_utilization_pct(self) -> Optional[float]:
        """Utilisation globale du stockage (%) via « ceph df »."""
        try:
            df = self.ceph_json("ceph df")
            stats = (df.get("stats") or {})
            total = stats.get("total_bytes", 0)
            used = stats.get("total_used_bytes", 0)
            if total:
                return round(100.0 * used / total, 1)
        except Exception:
            return None
        return None

    def insecure_entities(self) -> Dict[str, List[str]]:
        """Entités encore en clé « aes », par check AUTH_INSECURE_*
        (source de vérité : « ceph health detail »). Lecture pure.
        Retourne {check: [entity, ...]}."""
        res: Dict[str, List[str]] = {}
        try:
            det = self.ceph_json("ceph health detail")
        except Exception:
            return res
        for code, c in (det.get("checks") or {}).items():
            if not code.startswith(self.CEPH_AUTH_INSECURE_PREFIX):
                continue
            ents: List[str] = []
            for d in c.get("detail") or []:
                msg = (d.get("message") or "")
                m = re.search(r"entity (\S+)", msg)
                if m:
                    ents.append(m.group(1).rstrip(":"))
                else:
                    m2 = re.search(r"rotating service keys for (\S+)", msg)
                    if m2:
                        ents.append(f"({m2.group(1)})")
            res[code] = ents
        return res

    def fs_list(self) -> List[str]:
        """Systèmes CephFS (mode MDS requis si non vide)."""
        try:
            out = self.ceph_json("ceph fs ls")
        except Exception:
            return []
        if isinstance(out, dict):
            out = out.get("", out)
        if isinstance(out, list):
            return [f.get("name", "?") for f in out if isinstance(f, dict)]
        return []

    def fs_dump_actives(self) -> Tuple[List[str], List[str], int]:
        """Carte des MDS via « ceph fs dump -f json » (commande MON
        native, fiable en MULTI-FS — le « mdsmap » global de « ceph
        status » ne reflète qu'un seul FS et peut être vide/absent).
        Retourne (noms des MDS ACTIVES, noms des standbys, nombre de
        ranks up). Lecture pure, dry-run OK. Sortie RÉELLE (vécu
        09:35) : le JSON est suivi d'une ligne vide puis « dumped
        fsmap epoch N » — décodage via _json_lenient, PAS un
        json.loads() intégral qui avorte le run à tort."""
        out = self.ceph_run("ceph fs dump -f json")
        data = self._json_lenient(out)
        if not isinstance(data, dict):
            raise RuntimeError(f"Sortie non-JSON de « ceph fs dump » : "
                               f"{out.strip()[:200]}")
        actives: List[str] = []
        standbys: List[str] = []
        up_ranks = 0
        for fs in data.get("filesystems") or []:
            mdsmap = fs.get("mdsmap") or fs
            info = mdsmap.get("info") or {}
            for _rank, gid in (mdsmap.get("up") or {}).items():
                up_ranks += 1
                ent = info.get(str(gid)) or {}
                name = str(ent.get("name", "")).replace("mds.", "")
                if name and name not in actives:
                    actives.append(name)
        for ent in data.get("standbys") or []:
            name = str(ent.get("name", "")).replace("mds.", "")
            if name and name not in standbys:
                standbys.append(name)
        return actives, standbys, up_ranks

    # ---------- Gates de stabilisation ----------
    def wait_ceph_stable(self, action: str,
                         node: Optional[str] = None,
                         timeout: Optional[int] = None,
                         require_clean: bool = False) -> bool:
        """LA gate centrale : attend que le cluster soit de nouveau
        OPÉRATIONNEL après un redémarrage de daemon :
          1. santé effective HEALTH_OK (AUTH_INSECURE_* tolérés si
             PVE_CEPH_ALLOW_AUTH_INSECURE=1 — toute autre dégradation
             compte) ;
          2. quorum mon COMPLET ;
          3. PGs ACTIVES : aucune PG en peering/down/incomplete… —
             une PG non active ne sert PAS ses données, on bloque ;
          4. si `node` est fourni : tous les OSDs de ce nœud sont 'up'.
        « clean » N'est PAS exigé pendant la fenêtre de maintenance
        (`require_clean=False`, le défaut des gates du run) : nos
        propres flags nobackfill/norebalance/norecover GÈLENT le
        backfill — une PG « active+remapped » (ex. vécu : retour
        d'osd.0 après son restart, la PG doit backfiller POUR
        RETOURNER sur osd.0) reste non clean PENDANT TOUTE la
        fenêtre, et l'exiger causait une attente infinie alors que
        santé, quorum, PGs actives et OSDs up étaient tous OK. La
        convergence complète (active+clean) est vérifiée par la
        CONVERGENCE FINALE, APRÈS le retrait des flags
        (CephUpdater._final_converge) — le seul endroit où le
        recovery n'est plus gelé par le run lui-même.
        `require_clean=True` : exige en plus 0 PG non clean
        (convergence finale uniquement). Retourne False si timeout
        atteint (le message de timeout NOMME ce qui bloque : états
        PGs bloquantes, OSDs jamais revenues 'up').

        PENDANT la fenêtre de maintenance (flags posés via
        ceph_set_maintenance_window) les checks PG gelés par le
        recovery/backfill/scrub (CEPH_PG_FROZEN_CHECKS — PG
        dégradée/undersized, scrubs en retard) sont attendus et ne
        comptent PAS dans la santé effective : ils ne peuvent PAS se
        résorber avant le retrait des flags (vécu : osd.16, PG
        « stuck peering » de longue date ressortie dégradée — 14 min
        de polls « 0 PG non active », gate condamnée au timeout alors
        que santé réelle, quorum, PGs actives et OSDs up étaient OK).
        Le diagnostic est interrogé à CHAQUE poll : un état IDENTIQUE
        n'est pas redumpé (déduplication par signature), mais un
        CHANGEMENT de dégradations réapparaît — et le message de
        convergence NOMME les checks qui bloquent encore, pour ne
        plus jamais attendre « pour rien » sans savoir pourquoi."""
        t0 = time.time()
        timeout = timeout or CEPH_STABLE_TIMEOUT
        osd_ids: List[int] = []
        if node:
            try:
                tree = self.osds_of_node_tree()
                osd_ids = tree.get(node, [])
            except Exception:
                osd_ids = []
        last_pgs = ""
        while True:
            st = self.ceph_status()
            if st is None:
                raise RuntimeError("Ceph devenu injoignable — abort.")
            status, ignored, skipped, blocking_checks = self._health_parts(st)
            if not skipped:
                health = status
            else:
                sevs = [str((c or {}).get("severity", ""))
                        for c in blocking_checks.values()]
                if any("ERR" in sev for sev in sevs):
                    health = "HEALTH_ERR"
                elif any("WARN" in sev for sev in sevs):
                    health = "HEALTH_WARN"
                else:
                    health = "HEALTH_OK"
            if ignored:
                self.ceph_log_auth_insecure(ignored)
            frozen = sorted(c for c in skipped
                            if c in CEPH_PG_FROZEN_CHECKS)
            quorum_ok = self.mon_quorum_complete(st)
            # --- PGs : distinguer « non ACTIVE » (bloquant : pas d'IO)
            # de « non CLEAN » (mouvement de données DIFFÉRÉ par les
            # flags de maintenance — non bloquant pendant la fenêtre) ;
            # pgs_by_state agrège : [{"state_name": "active+clean",
            # "count": N}, {"state_name": "active+remapped", …}, …].
            pgmap = st.get("pgmap") or {}
            states = pgmap.get("pgs_by_state") or []
            non_active = sum(int(s.get("count", 0)) for s in states
                             if "active" not in str(s.get("state_name",
                                                          "")))
            non_clean = sum(int(s.get("count", 0)) for s in states
                            if "active" in str(s.get("state_name", ""))
                            and "clean" not in str(s.get("state_name",
                                                         "")))
            blocking = non_active + (non_clean if require_clean else 0)
            deferred = 0 if require_clean else non_clean
            if require_clean:
                pg_desc = f"{blocking} PG(s) non active+clean"
            else:
                pg_desc = f"{non_active} PG(s) non active"
                if deferred:
                    pg_desc += (f" (+{deferred} non clean — recovery "
                                f"gélé par les flags)")
            last_pgs = ", ".join(
                f"{s.get('count')}×{s.get('state_name')}" for s in states
                if ("active" not in str(s.get("state_name", "")))
                or (require_clean
                    and str(s.get("state_name")) != "active+clean"))
            osd_ok = True
            osd_down: List[str] = []
            if node and osd_ids:
                try:
                    ups = self.osd_up_status()
                    osd_down = [f"{node}/osd.{i}" for i in osd_ids
                                if not ups.get(i, {}).get("up")]
                    osd_ok = not osd_down
                except Exception:
                    osd_ok = False
            if (health == "HEALTH_OK" and quorum_ok
                    and blocking == 0 and osd_ok):
                frozen_txt = ""
                if frozen:
                    frozen_txt = (f" [hors {', '.join(frozen)} gelé(s) "
                                  f"par les flags — vérifié(s) à la "
                                  f"convergence finale]")
                if "OSD_UPGRADE_FINISHED" in skipped:
                    frozen_txt += (" [hors OSD_UPGRADE_FINISHED — "
                                   "attendu : toutes les OSDs sont "
                                   "déjà en cible, « require-osd-"
                                   "release » sera posé par ce run "
                                   "après la phase MDS et la "
                                   "convergence finale re-vérifiera]")
                self.log.info(f"Ceph stable après « {action} » "
                              f"(HEALTH_OK, quorum complet, "
                              + ("PGs actives + propres ✔"
                                 if require_clean else "PGs actives ✔")
                              + (f" [{deferred} non clean — recovery "
                                 f"gelé par les flags, convergence "
                                 f"prévue après leur retrait]"
                                 if deferred else "")
                              + frozen_txt
                              + (f", OSDs de {node} 'up' ✔" if node
                                 and osd_ids else "") + ")")
                return True
            if time.time() - t0 > timeout:
                self.ceph_diagnose(st, force=True)
                if last_pgs:
                    self.log.error(f"PGs non stabilisées : {last_pgs}")
                if osd_down:
                    self.log.error("OSDs jamais revenues 'up' : "
                                   + ", ".join(osd_down))
                self.log.error(f"Ceph non stabilisé après {timeout}s "
                               f"(action « {action} »).")
                return False
            if health != "HEALTH_OK":
                # Dédupliqué par ceph_diagnose : n'apparaît qu'au
                # CHANGEMENT de dégradations — plus jamais de dump
                # identique répété, mais plus jamais de silence non
                # expliqué non plus.
                self.ceph_diagnose(st)
            wait_txt = ""
            if blocking_checks:
                codes = "/".join(sorted(blocking_checks)[:4])
                if len(blocking_checks) > 4:
                    codes += "…"
                wait_txt = f", check(s) en attente : {codes}"
            osd_wait = ""
            if node and osd_ids and not osd_ok:
                osd_wait = (f", OSDs {node} en attente"
                            + (f" ({', '.join(osd_down[:8])})"
                               if osd_down
                               else " (état illisible : « ceph osd "
                                     "dump --format json »)"))
            self.log.warning(f"Ceph en convergence après « {action} » "
                             f"(santé {health}"
                             + wait_txt
                             + f", quorum "
                             f"{'OK' if quorum_ok else 'INCOMPLET'}"
                             + (f", {pg_desc}" if pg_desc else "")
                             + osd_wait
                             + f") — recheck toutes les {CEPH_POLL_S}s…")
            time.sleep(CEPH_POLL_S)


# ---------------------------------------------------------------------------
# UPDATER CEPH — orchestration des actions
# ---------------------------------------------------------------------------
class CephUpdater:
    """Pilote une des trois actions (mineur / majeur / rotate-keys) avec :
    - preflight : gates de santé + inventaire complet ;
    - flags de maintenance globaux posés en début et retirés en finally ;
    - gates de stabilisation entre chaque unité redémarrée ;
    - fichier d'état pour la reprise après interruption ;
    - mode dry-run : chaque commande mutante est loggée [SIMULATION]
      avec la ligne EXACTE qui serait exécutée, et un bilan d'estimation."""

    def __init__(self, logger: logging.Logger, dry: bool,
                 client: ProxmoxClient, args):
        self.log = logger
        self.dry = dry
        self.client = client
        self.action = args["action"]
        self.major_release = args.get("major")
        # Release CIBLE du run, exposée au client pour la tolérance
        # OSD_UPGRADE_FINISHED (cf. ProxmoxClient._osd_upgrade
        # _finished_expected) : les gates de la Phase E voient ce
        # check dès la dernière OSD redémarrée en cible, alors que
        # require-osd-release n'est posé qu'en Phase G (après les
        # MDS) — l'exiger entre les deux attend une condition que
        # ce run lui-même ne crée qu'à la fin.
        self.client._osd_require_target = (
            self.major_release or "") if self.action == "major" else ""
        self.only_node = args.get("node")
        # rotate-keys : clients métier dont la rotation est DIFFÉRÉE
        # (--skip-client, répétable). Normalisation : préfixe « client. »
        # ajouté s'il manque (« rhospdc » ≡ « client.rhospdc »).
        self.skip_clients: set = set()
        for sc in (args.get("skip_clients") or []):
            ent = sc.strip()
            if not ent:
                continue
            if not ent.startswith("client."):
                ent = "client." + ent
            self.skip_clients.add(ent)
        self.nodes: List[str] = []
        self.flags_we_set: Dict[str, bool] = {}
        self.t_start = time.time()
        # message d'erreur si le run a été INTERROMPU (bilan final)
        self.aborted: Optional[str] = None
        # compteurs du bilan
        self.counts = {"pkg_nodes": 0, "restarts": 0, "keys_rotated": 0,
                       "gates": 0}
        self.est_s = 0.0
        self._insecure: Dict[str, List[str]] = {}
        # suivi de la progression SIMULÉE (dry-run de --rotate-keys) :
        # entités « rotationnées » et codes de check « disparus » simulés.
        self._sim_rotated: List[str] = []
        self._sim_cleared_codes: List[str] = []
        # CRUSH tree (nœud → ids OSD réelles) : source de vérité du
        # PLACEMENT et du NOMBRE d'OSD — le scan filesystem compte aussi
        # les répertoires vestiges d'OSD retirées (ex. réel : 87
        # répertoires pour 53 OSD). Nœuds déjà signalés (anti-doublon).
        self._osd_tree: Dict[str, List[int]] = {}
        self._stale_warned: set = set()
        # Vérité terrain du sharding RocksDB (Phase E de --major) :
        # OSDs détectées NON shardées (show-sharding pendant l'arrêt)
        # et nombre de tests réussis — récapitulés au bilan final.
        self._nonsharded: List[str] = []
        self._shard_probed: int = 0
        # Phase E : mode par défaut (version-check + ceph-osd.target)
        # ou opt-in --force-detection-sharding (OSDs une par une) —
        # récapitulé au bilan final.
        self._osd_skipped: int = 0
        self._osd_target_used: bool = False
        self.force_sharding = bool(args.get("force_sharding_detection"))

    # ---------------- Fichier d'état ----------------
    def _state_read(self) -> Dict:
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return {}

    def _state_write(self, phase: str) -> None:
        if self.dry:
            return
        try:
            d = os.path.dirname(STATE_FILE)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(STATE_FILE, "w", encoding="utf-8") as fh:
                json.dump({
                    "action": self.action,
                    "phase": phase,
                    "flags": sorted(self.flags_we_set),
                    "started": datetime.now().isoformat(timespec="seconds"),
                }, fh, indent=2)
        except OSError as e:
            self.log.warning(f"Fichier d'état non écrivable ({e}) — "
                             f"reprise après interruption dégradée.")

    def _state_clear(self) -> None:
        try:
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
        except OSError:
            pass

    # ---------------- Helpers exécution/simulation ----------------
    def _sim(self, txt: str) -> None:
        self.log.info(f"[SIMULATION] {txt}")

    def _mut(self, cmd: str, node: Optional[str] = None, desc: str = "") -> str:
        """Commande MUTANTE : exécutée (ou simulée en dry-run)."""
        where = f"sur {node}" if node else "cluster-wide"
        if self.dry:
            self.log.info(f"[SIMULATION] {desc or ''} {where} : {cmd}".strip())
            return ""
        self.log.debug(f"EXÉCUTION {where} : {cmd}")
        return self.client.ceph_run(cmd, node=node)

    def _gate(self, action: str, node: Optional[str] = None,
              require_clean: bool = False) -> None:
        """Gate de stabilisation entre deux unités redémarrées.
        Pendant la fenêtre de maintenance, nos flags gelent le
        backfill/recovery : une PG « active+remapped » (donc non
        clean) est NORMALE et ne doit PAS bloquer — la gate exige
        santé effective OK + quorum complet + PGs ACTIVES + (si
        `node`) OSDs du nœud 'up'. La convergence complète
        (active+clean) est vérifiée par _final_converge APRÈS le
        retrait des flags."""
        self.counts["gates"] += 1
        if self.dry:
            self.log.info(f"[SIMULATION] Gate santé après « {action} » : "
                          f"HEALTH_OK + quorum complet + PGs actives "
                          f"(clean différé par les flags de maintenance) "
                          f"(hypothèse simulation)")
            self.est_s += EST_STABILIZE_S
            return
        if not self.client.wait_ceph_stable(action, node=node,
                                            require_clean=require_clean):
            raise RuntimeError(
                f"Gate santé échouée après « {action} » — abort propre "
                f"(flags de maintenance retirés par le bloc finally).")

    def _est(self, sec: float) -> None:
        self.est_s += sec

    def _stale_osd_dirs_of(self, node: str, fs_osds: List[str]) -> Optional[List[int]]:
        """Ids des répertoires OSD VESTIGES du nœud : présents dans son
        scan filesystem mais absents du CRUSH tree (OSD déplacées ou
        retirées). None si le nœud est absent du tree (source de
        vérité indisponible pour lui)."""
        if node not in self._osd_tree:
            return None
        fs_ids = {int(o) for o in fs_osds if str(o).lstrip("-").isdigit()}
        return sorted(fs_ids - set(self._osd_tree[node]))

    def _warn_stale_osd_dirs(self, node: str, stale: Optional[List[int]]) -> None:
        """Signale une seule fois par run et par nœud les répertoires
        OSD vestiges (inventaire du preflight puis étape 5 de
        --rotate-keys partagent cet avertissement)."""
        if not stale or node in self._stale_warned:
            return
        self._stale_warned.add(node)
        self.log.warning(
            f"  {node} : {len(stale)} répertoire(s) de données OSD "
            f"obsolète(s) détecté(s) : "
            f"{', '.join('osd.' + str(o) for o in stale)} "
            f"(présents sous /var/lib/ceph/osd mais absents du "
            f"CRUSH tree — vestiges d'OSD déplacés ou retirés ; à "
            f"vérifier puis nettoyer hors run).")

    # ---------------- Preflight ----------------
    def preflight(self) -> bool:
        banner(self.log, "ÉTAPE 0 — Pré-vérifications du cluster Ceph")
        self.nodes = self.client.node_names()
        if self.only_node:
            if self.only_node not in self.nodes:
                raise RuntimeError(
                    f"Nœud --node '{self.only_node}' inconnu du cluster "
                    f"(nœuds : {', '.join(self.nodes)}).")
            if self.action != "minor":
                raise RuntimeError(
                    "--node n'est supporté qu'en mode mineur : le mode "
                    "majeur exige de traiter TOUS les nœuds avant les "
                    "redémarrages, et --rotate-keys est cluster-wide.")
            self.nodes = [self.only_node]
        st = self.client.ceph_status()
        if st is None:
            raise RuntimeError(
                "Ce cluster n'a pas de Ceph (ou l'API Ceph est injoignable) "
                "— ce script est pour les clusters hyperconvergés PVE+Ceph.")
        # Santé effective : les checks AUTH_INSECURE_* sont l'OBJET même
        # du mode --rotate-keys : tolérés SANS PVE_CEPH_ALLOW_AUTH_INSECURE
        # pour ce mode (toute autre dégradation reste bloquante). Pour les
        # modes mineur/majeur, la tolérance habituelle s'applique (var env).
        health, ignored = self.client.ceph_effective_health(st)
        if self.action == "rotate-keys":
            h = (st.get("health") or {})
            checks = h.get("checks") or {}
            non_ai = {c: v for c, v in checks.items()
                      if not c.startswith("AUTH_INSECURE_")
                      and not (c == "OSDMAP_FLAGS"
                               and self.client._osdmap_flags_all_maintenance(
                                   v))}
            if non_ai:
                self.client.ceph_diagnose(st, force=True)
                raise RuntimeError(
                    "Le cluster présente des dégradations RÉELLES (hors "
                    "AUTH_INSECURE_*) — remédiation CVE refusée. Corrigez "
                    "Ceph d'abord, relancez ensuite.")
            health = "HEALTH_OK"
            self.log.info("[rotate-keys] Santé : checks AUTH_INSECURE_* "
                          "présents = OBJET du run ; aucune autre dégradation ✔")
        self.log.info(f"Ceph : santé effective {health}"
                      + (f" ({len(ignored)} check(s) AUTH_INSECURE toléré(s))"
                         if ignored else ""))
        if ignored:
            self.client.ceph_log_auth_insecure(ignored)
        if health != "HEALTH_OK":
            self.client.ceph_diagnose(st, force=True)
            raise RuntimeError(
                f"Ceph est en {health} — action {self.action} REFUSÉE : "
                f"un cluster dégradé ne se met pas à jour.")
        # Checks PG gelés par des flags de maintenance DÉJÀ posés sur le
        # cluster (hors de ce run — admin ou run précédemment interrompu
        # brutalement) : tant que norecover/nobackfill gèlent le
        # recovery, ces PG ne PEUVENT PAS guérir (ex. vécu :
        # « active+recovery_wait+degraded »), et les exiger ici
        # condamnait le preflight à refuser éternellement. Ils sont
        # listés pour rester VISIBLES (ce ne sont pas des checks
        # sains) : ils devront disparaître après le retrait des flags
        # — la convergence finale les vérifie pour de vrai.
        _st_h = (st.get("health") or {})
        frozen_pre = sorted(
            c for c in (self.client._health_parts(st)[2] or ())
            if c in CEPH_PG_FROZEN_CHECKS)
        if frozen_pre and not getattr(self.client, "_maint_window", False):
            self.log.warning(
                f"[Ceph] {len(frozen_pre)} check(s) PG gelé(s) par des "
                f"flags de maintenance DÉJÀ posés sur le cluster :")
            for c in frozen_pre:
                chk = (_st_h.get("checks") or {}).get(c) or {}
                msg = str(((chk.get("summary") or {}).get("message"))
                          or "").strip()
                self.log.warning(f"    {c} : {msg}")
                for d in (chk.get("detail") or [])[:3]:
                    dm = ((d.get("message") or "").strip()
                          .replace("\n", " "))
                    if dm:
                        self.log.warning(f"        {dm[:200]}")
            self.log.warning(
                "    → attendu(s) tant que les flags gèlent le "
                "recovery ; à vérifier après leur retrait (convergence "
                "finale). Si ces flags ne sont PAS de vous : « ceph osd "
                "dump | grep flags » pour décider.")
        # OSD_UPGRADE_FINISHED déjà présent au preflight (reprise d'un
        # run majeur interrompu AVANT la phase require-osd-release, ou
        # montée terminée à la main sans l'avoir relevé) : toutes les
        # OSDs tournent déjà en cible mais require_osd_release est
        # resté en retrait — toléré (ce run le posera après la phase
        # MDS), listé pour rester VISIBLE, et la convergence finale
        # re-vérifiera la santé réelle une fois le check disparu.
        if (self.action == "major"
                and "OSD_UPGRADE_FINISHED"
                in (self.client._health_parts(st)[2] or ())):
            _uchk = ((_st_h.get("checks") or {})
                     .get("OSD_UPGRADE_FINISHED") or {})
            _umsg = str(((_uchk.get("summary") or {})
                         .get("message")) or "").strip()
            self.log.warning(
                f"[Ceph] Check OSD_UPGRADE_FINISHED déjà présent : "
                f"{_umsg}")
            self.log.warning(
                f"    → attendu : toutes les OSDs tournent en "
                f"{self.major_release} mais « require_osd_release » "
                f"n'est pas encore relevé ; ce run le posera (après "
                f"la phase MDS) et la convergence finale re-vérifiera "
                f"la santé réelle.")
        # Utilisation globale : un upgrade raté sur un cluster presque
        # plein = recovery interminable.
        util = self.client.ceph_utilization_pct()
        if util is not None:
            self.log.info(f"Ceph : utilisation globale du stockage : {util}% "
                          f"(max autorisé : {CEPH_UTIL_MAX_PCT}%)")
            if util > CEPH_UTIL_MAX_PCT:
                raise RuntimeError(
                    f"Utilisation Ceph {util}% > {CEPH_UTIL_MAX_PCT}% — "
                    f"action REFUSÉE (pas de marge pour un recovery long).")
        # Inventaire par nœud
        self.log.info("Inventaire des daemons Ceph :")
        # CRUSH tree : source de vérité du NOMBRE d'OSD par nœud (le
        # scan filesystem compte aussi les répertoires vestiges).
        try:
            self._osd_tree = self.client.osds_of_node_tree()
        except Exception as e:
            self._osd_tree = {}
            self.log.warning(f"CRUSH tree indisponible ({e}) — comptage "
                             f"OSD par scan filesystem : il peut inclure "
                             f"des répertoires vestiges d'OSD retirées.")
        daemons_by_node: Dict[str, Dict[str, List[str]]] = {}
        for node in self.nodes:
            d = self.client.node_daemons(node)
            daemons_by_node[node] = d
            pkg = self.client.pkg_ceph_version(node)
            branch = self.client.ceph_repo_branch(node)
            kv = self.client.kernel_version(node)
            ktxt = ".".join(str(x) for x in kv)
            warn = ""
            if kv and kv < KERNEL_AES256K:
                warn = (f" — noyau < {KERNEL_AES256K[0]}.{KERNEL_AES256K[1]} : "
                        f"les clients noyau (CephFS/RBD in-guest) ne "
                        f"comprendront PAS les clés aes256k")
            # OSD réelles du nœud d'après le CRUSH tree (fallback : scan
            # filesystem, gonflé par les répertoires vestiges).
            if node in self._osd_tree:
                osd_n = len(self._osd_tree[node])
            else:
                osd_n = len(d["osd"])
            self.log.info(f"  {node} : paquet ceph {pkg} | dépôt ceph-{branch} "
                          f"| noyau {ktxt}{warn} | "
                          f"mon={len(d['mon'])} mgr={len(d['mgr'])} "
                          f"osd={osd_n} mds={len(d['mds'])}")
            self._warn_stale_osd_dirs(node, self._stale_osd_dirs_of(node,
                                                                    d["osd"]))
            if warn and self.action == "rotate-keys":
                self.log.warning(f"  {node}:{warn} — vérifiez vos VMs avant "
                                 f"de restreindre les ciphers (étape finale).")
        # Matrice des versions des daemons
        versions = self.client.ceph_versions()
        if versions:
            self.log.info("Versions des daemons (« ceph versions ») :")
            for t in ("mon", "mgr", "osd", "mds"):
                if t in versions:
                    for ver, nb in sorted(versions[t].items()):
                        self.log.info(f"  {t}: {nb}× {ver}")
        # Flags de maintenance : orphelins d'un run précédent ?
        cur_flags = self.client.ceph_flags_current() or {}
        state = self._state_read()
        if state.get("flags"):
            recorded = set(state["flags"])
            still = recorded & set(cur_flags)
            if still:
                self.log.warning(f"Flags de maintenance posés par un run "
                                 f"précédent ({state.get('action')}, phase "
                                 f"« {state.get('phase')} », "
                                 f"{state.get('started')}) encore présents : "
                                 f"{', '.join(sorted(still))} — ils sont "
                                 f"ADOPTÉS par ce run et seront retirés à la "
                                 f"fin.")
                self.flags_we_set = {f: True for f in still}
            else:
                self.log.info(f"Fichier d'état d'un run précédent trouvé "
                              f"({state.get('action')}) — flags déjà retirés, "
                              f"rien à adopter.")
        else:
            admin_flags = [f for f in CEPH_MAINT_FLAGS if f in cur_flags]
            if admin_flags:
                self.log.warning(f"Flags de maintenance déjà posés par un "
                                 f"administrateur : {', '.join(admin_flags)} "
                                 f"— conservés tels quels (ils ne seront "
                                 f"PAS retirés par ce run).")
        # Vérifications propres à chaque action
        if self.action == "major":
            rel = self.major_release
            if rel not in KNOWN_RELEASES:
                raise RuntimeError(
                    f"Release « {rel} » inconnue (releases supportées : "
                    f"{', '.join(sorted(KNOWN_RELEASES))}).")
            num = KNOWN_RELEASES[rel]
            # Garde 1 — montée d'EXACTEMENT une release majeure (Ceph ne
            # supporte NI la descente NI le saut de release) :
            self._major_target_sanity(rel, num)
            # Garde 2 — prérequis de la release cible (wiki officiel) :
            self._major_prereqs(rel, num)
            # Piège META du wiki (Known Issues) : WARNING ciblé seulement
            # si des OSDs datent d'avant Pacific (v16, sharding par
            # défaut) — pas d'avertissement générique.
            self._major_octopus_check()
            self.log.info(f"Action MAJEURE : bascule vers Ceph {rel} "
                          f"(major {num}). Procédure officielle Proxmox : "
                          f"dépôt sur tous les nœuds → paquets sur tous "
                          f"les nœuds → mons → mgrs → OSDs → MDS → "
                          f"require-osd-release.")
        if self.action == "rotate-keys":
            return self._rotate_keys_preflight(st)
        return True

    def _major_releases_running(self) -> List[Tuple[int, str]]:
        """Releases majeures courantes des MONs (« ceph versions ») :
        [(num, nom)] trié, [] si indéterminable."""
        versions = self.client.ceph_versions()
        found = set()
        for ver in (versions.get("mon") or {}):
            for name, num in KNOWN_RELEASES.items():
                if re.search(rf"\b{name}\b", ver):
                    found.add((num, name))
        return sorted(found)

    def _major_target_sanity(self, rel: str, num: int) -> None:
        """Refuse les descentes et les sauts de release majeure (Ceph ne
        supporte que les montées N → N+1) ; autorise la REPRISE d'une
        montée interrompue (versions mixtes → cible = release haute)."""
        running = self._major_releases_running()
        if not running:
            self.log.warning(
                "Release courante indéterminable (« ceph versions » vide) "
                f"— vérifiez manuellement que {rel} est bien la release "
                f"SUIVANTE de celle qui tourne.")
            return
        names = " + ".join(n for _, n in running)
        if len(running) > 1:
            hi_num, hi = running[-1]
            if num == hi_num:
                self.log.info(
                    f"Mons en versions MIXTES ({names}) : reprise d'une "
                    f"montée interrompue vers {rel} — poursuite.")
                return
            raise RuntimeError(
                f"Mons en versions MIXTES ({names}) : une montée vers "
                f"{hi} est interrompue en cours — terminez d'abord la "
                f"reprise (--major {hi}), visez {rel} ensuite.")
        cur_num, cur = running[0]
        if num < cur_num:
            raise RuntimeError(
                f"Descente refusée : le cluster tourne déjà {cur} "
                f"(major {cur_num}) — cibler {rel} (major {num}) n'est "
                f"pas une montée.")
        if num > cur_num + 1:
            raise RuntimeError(
                f"Saut de release refusé : Ceph ne supporte que les "
                f"montées N → N+1. Le cluster tourne {cur} (major "
                f"{cur_num}) — montez d'abord vers la release suivante.")
        if num == cur_num:
            self.log.info(
                f"Cluster déjà sur {cur} — le run bascule/sécurise les "
                f"éléments restants (dépôt, paquets, min_mon_release…).")
        else:
            self.log.info(f"Montée {cur} (major {cur_num}) → {rel} "
                          f"(major {num}) : exactement une release majeure "
                          f"(N+1) ✔")

    def _major_prereqs(self, rel: str, num: int) -> None:
        """Prérequis de la release cible (wiki officiel), par nœud :
        version minimale du paquet ceph ET de pve-manager."""
        req = MAJOR_PREREQS.get(rel) or {}
        pv: Tuple[int, ...] = req.get("pve", ())
        cv: Tuple[int, ...] = req.get("ceph", ())
        if not req:
            return
        if not self.nodes:
            raise RuntimeError("Inventaire des nœuds vide — impossible de "
                               "vérifier les prérequis de la montée.")
        cv_txt = ".".join(str(x) for x in cv)
        pv_txt = ".".join(str(x) for x in pv)
        for node in self.nodes:
            pkg = self.client.pkg_ceph_version(node)
            m = re.match(r"(\d+)\.(\d+)\.(\d+)", pkg or "")
            if m:
                got = tuple(int(x) for x in m.groups())
                if cv and got < cv:
                    raise RuntimeError(
                        f"{node} : paquet ceph {pkg} < minimum requis "
                        f"{cv_txt} pour la montée vers {rel} (wiki) — "
                        f"faites d'abord une passe MINEURE (mise à jour "
                        f"des paquets).")
            else:
                self.log.warning(
                    f"{node} : version du paquet ceph indéchiffrable "
                    f"({pkg}) — vérifiez manuellement le prérequis "
                    f">= {cv_txt}.")
            if pv:
                pve = self.client.pve_manager_version(node)
                if not pve:
                    self.log.warning(
                        f"{node} : version de pve-manager indéterminée — "
                        f"vérifiez manuellement le prérequis >= {pv_txt}.")
                elif pve < pv:
                    pve_txt = ".".join(str(x) for x in pve)
                    raise RuntimeError(
                        f"{node} : pve-manager {pve_txt} < minimum requis "
                        f"{pv_txt} pour la montée vers {rel} (wiki) — "
                        f"terminez d'abord le rolling update PVE.")

    def _major_octopus_check(self) -> None:
        """Piège META du wiki (Known Issues, Squid→Tentacle) : les OSDs
        créées sous Octopus (v15) ou avant ont un RocksDB NON shardé
        (sharding par défaut seulement depuis Pacific, v16) et voient
        leur usage META augmenter après la montée (jusqu'à 20.2.4).
        Le sharding réel ne se vérifie qu'OSD ARRÊTÉE : heuristique non
        invasive = date de création du répertoire de données de l'OSD.
        WARNING ciblé seulement dans ce cas ; INFO discret sinon."""
        old: List[str] = []
        probed = 0
        for node in self.nodes:
            ids = self._osd_tree.get(node)
            if ids is None:
                ids = [int(o) for o in self.client.node_daemons(node)["osd"]
                       if str(o).lstrip("-").isdigit()]
            if not ids:
                continue
            try:
                bdays = self.client.osd_dir_birthdays(node)
            except Exception:
                bdays = {}
            probed += len(bdays)
            for oid in ids:
                ts = bdays.get(int(oid))
                if ts and ts < PACIFIC_DEFAULT_SHARDING_TS:
                    when = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                    old.append(f"osd.{oid} ({node}, {when})")
        if old:
            shown = ", ".join(old[:10]) + ("…" if len(old) > 10 else "")
            self.log.warning(
                f"Piège du wiki (Known Issues) : {len(old)} OSD(s) "
                f"datent d'avant Pacific (v16) — RocksDB probablement "
                f"NON shardé : {shown}. Après la montée, surveillez "
                f"« ceph osd df » (colonne META ; un Total Space en "
                f"baisse dans l'UI PVE est un autre symptôme) ; "
                f"contournement : « ceph daemon osd.N compact » un par "
                f"un (I/O intensif, heures creuses). Vérité terrain : "
                f"« --force-detection-sharding » teste le sharding "
                f"réel de chaque OSD (arrêt → show-sharding → "
                f"démarrage), sinon surveillez « ceph osd df » "
                f"(colonne META) après la montée.")
        elif probed:
            self.log.info(
                f"Aucune OSD antérieure à Pacific (v16) détectée (date "
                f"de création des répertoires de {probed} OSD(s)) — le "
                f"piège META du wiki ne s'applique PROBABLEMENT pas "
                f"(heuristique indicative, non infaillible ; vérité "
                f"terrain : --force-detection-sharding).")
        else:
            self.log.warning(
                "Dates de création des OSDs illisibles — impossible "
                "d'exclure le piège META du wiki (OSDs créées sous "
                "Octopus v15 ou avant, RocksDB non shardé) : vérifiez "
                "« ceph osd df » (colonne META) après la montée ; "
                "contournement : « ceph daemon osd.N compact ». "
                "Vérité terrain : « --force-detection-sharding » "
                "teste le sharding réel de chaque OSD en Phase E.")

    def _rotate_keys_preflight(self, st: Dict) -> bool:
        """Gates propres à la remédiation CVE-2025-30156. Retourne False
        si le cluster est déjà entièrement remédié (rien à faire)."""
        self._insecure = self.client.insecure_entities()
        if not self._insecure:
            self.log.info("Aucun check AUTH_INSECURE_* présent — le cluster "
                          "est déjà entièrement remédié (clés aes256k). "
                          "Rien à faire ✔")
            return False
        for code, ents in sorted(self._insecure.items()):
            self.log.info(f"  à remédier : {code} → "
                          f"{', '.join(ents) if ents else 'n/a (config mon)'}")
        # Tous les daemons doivent tourner sur des paquets corrigés :
        # une clé aes256k donnée à un daemon ANCien = daemon lockout.
        versions = self.client.ceph_versions()
        bad: List[str] = []
        for t in ("mon", "mgr", "osd", "mds"):
            for ver in (versions.get(t) or {}):
                m = re.search(r"ceph version (\d+)\.(\d+)\.(\d+)", ver)
                if not m:
                    continue
                tup = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
                fixed = CVE_FIXED.get(str(tup[0]))
                if fixed and tup < fixed:
                    bad.append(f"{t}: {ver}")
        if bad:
            raise RuntimeError(
                "Des daemons tournent encore sur des paquets ANTÉRIEURS au "
                f"correctif CVE-2025-30156 : {'; '.join(bad)}. La rotation "
                "verrouillerait ces daemons hors du cluster — mettez "
                "d'abord tous les paquets Ceph à jour (mode mineur, ou "
                "rolling update PVE) et relancez --rotate-keys.")
        self.log.info("Tous les daemons tournent sur des paquets ≥ "
                      "correctif CVE-2025-30156 ✔ (prérequis de rotation)")
        # Noyau des nœuds : les clients noyau aes256k exigent Linux 7.0 ;
        # les VMs ne sont pas sondables — rappel explicite.
        for node in self.nodes:
            kv = self.client.kernel_version(node)
            if kv and kv < KERNEL_AES256K:
                self.log.warning(f"  {node} : noyau "
                                 f"{kv[0]}.{kv[1]} < 7.0 — les VMs "
                                 f"montant CephFS/RBD via le client noyau "
                                 f"doivent être vérifiées avant l'étape "
                                 f"finale (retrait de « aes »).")
        return True

    # ---------------- Flags ----------------
    def _flags_on(self) -> None:
        banner(self.log, "Pose des flags de maintenance Ceph", ColorFormatter.GREEN)
        # Fenêtre de maintenance OUVERTE : les checks PG gelés par le
        # recovery/backfill/scrub deviennent « attendus » aux gates
        # (cf. CEPH_PG_FROZEN_CHECKS) — ils ne peuvent pas se résorber
        # avant le retrait des flags.
        self.client.ceph_set_maintenance_window(True)
        if self.dry:
            flags = [f for f in CEPH_MAINT_FLAGS
                     if f not in (self.client.ceph_flags_current() or {})]
            # MERGE : conserver les flags ADOPTÉS d'un run précédent
            # (preflight) — un simple remplacement les perdait et le
            # finally ne retirait alors que nos 2 flags, laissant
            # les 4 adoptés orphelins (plus de fichier d'état →
            # reclassés « admin » au run suivant, JAMAIS retirés).
            self.flags_we_set.update({f: True for f in flags})
            self._sim(f"Pose des flags de maintenance : "
                      f"{', '.join(sorted(flags))} (les flags déjà posés "
                      f"par l'admin sont conservés)")
            return
        # MERGE, même raison : flags adoptés + flags nouvellement posés.
        changed = self.client.ceph_maintenance_on(
            adopted=sorted(self.flags_we_set))
        self.flags_we_set.update(changed)
        self._state_write("démarrage")

    def _flags_off(self) -> None:
        # Fenêtre de maintenance FERMÉE (avant tout early-return) :
        # un check PG dégradé/undersized redevient BLOQUANT — la
        # convergence finale, qui suit, le vérifie pour de vrai.
        self.client.ceph_set_maintenance_window(False)
        if not self.flags_we_set:
            return
        if self.dry:
            self._sim(f"Retrait des flags posés par le run : "
                      f"{', '.join(sorted(self.flags_we_set))} — le cluster "
                      f"reprend son fonctionnement nominal")
            return
        self.client.ceph_maintenance_off(self.flags_we_set)
        self._state_clear()

    def _final_converge(self) -> None:
        """Dernière vérification, APRÈS le retrait des flags : le
        backfill/recovery gelé pendant la fenêtre reprend, et les
        PGs restées non clean (ex. « active+remapped » au retour
        d'une OSD) doivent converger MAINTENANT — c'est ici, et
        seulement ici, que « active+clean » est exigé. Des flags
        posés hors de ce run (admin) gèlent encore le mouvement :
        impossible d'exiger clean — le run les signale avec les
        commandes de retrait exactes. Un timeout n'échoue PAS le
        run : le cluster continue de converger tout seul."""
        try:
            remaining = sorted(
                f for f in CEPH_MAINT_FLAGS
                if f in (self.client.ceph_flags_current() or {}))
        except Exception:
            remaining = []
        if remaining:
            self.log.warning(
                "Flags de maintenance toujours posés (hors de ce run) : "
                f"{', '.join(remaining)} — recovery/backfill GELÉS "
                "jusqu'à leur retrait : convergence complète différée. "
                "Retrait manuel : "
                + " ; ".join(f"ceph osd unset {f}" for f in remaining))
            if not self.client.wait_ceph_stable(
                    "convergence finale (flags restants)",
                    require_clean=False):
                self.log.warning("Santé/quorum/PGs actives pas encore "
                                 "tous rétablis à la fin du run — "
                                 "vérifiez « ceph -s ».")
            return
        self.log.info("Flags retirés — le recovery/backfill reprend : "
                      "attente de la convergence finale (PGs "
                      "active+clean)…")
        if self.client.wait_ceph_stable(
                "convergence finale (recovery + backfill)",
                timeout=FINAL_CONVERGE_TIMEOUT,
                require_clean=True):
            self.log.info("Convergence finale ✔ (HEALTH_OK, quorum "
                          "complet, PGs active+clean) — fenêtre de "
                          "maintenance terminée.")
        else:
            self.log.warning(
                f"Backfill/recovery pas encore terminé au bout de "
                f"{FINAL_CONVERGE_TIMEOUT}s — le run a RÉUSSI ; le "
                f"cluster continue de converger seul. Surveillez "
                f"« ceph -s » jusqu'à « active+clean » (aucune action "
                f"requise).")

    # ---------------- Action 1 : mise à jour MINEURE ----------------
    def minor_scan(self) -> Dict[str, List]:
        """Rafraîchit les listes apt de chaque nœud et collecte les
        paquets Ceph en attente (lecture seule — AVANT toute pose de
        flag). Retourne {nœud: [(paquet, version), …]}.

        « apt-get update -q » est SANS RISQUE (cache des paquets
        uniquement) : il est exécuté RÉELLEMENT même en dry-run, pour
        que la liste des paquets en attente soit authentique
        (« apt-get -s full-upgrade » reste une simulation pure)."""
        pending_by_node: Dict[str, List] = {}
        for node in self.nodes:
            if self.dry:
                try:
                    self.client.apt_update(node)
                    self.log.info(
                        f"{node} : apt-get update -q exécuté "
                        f"RÉELLEMENT (dry-run : sans risque — cache "
                        f"des paquets uniquement)")
                except Exception as e:
                    self.log.warning(
                        f"{node} : apt-get update -q impossible ({e}) — "
                        f"la simulation apt qui suit peut sous-estimer "
                        f"les paquets en attente.")
            else:
                self.client.apt_update(node)
            pending_by_node[node] = self.client.ceph_pkg_pending(node)
        return pending_by_node

    def minor_run(self, scan: Optional[Dict[str, List]] = None) -> None:
        if scan is None:
            scan = self.minor_scan()
        total = len(self.nodes)
        for i, node in enumerate(self.nodes, 1):
            banner(self.log, f"ÉTAPE {i}/{total} — Mise à jour Ceph de {node} "
                             f"(mineur, sans reboot)")
            pending = scan.get(node) or []
            if not pending:
                # Rien à faire sur ce nœud : aucune mise à jour, aucun
                # redémarrage de daemon — on se contente de l'indiquer.
                self.log.info(f"{node} : aucun paquet Ceph en attente — "
                              f"rien à faire sur ce nœud (daemons non "
                              f"redémarrés).")
                continue
            self.log.info(f"{node} : {len(pending)} paquet(s) Ceph à "
                          f"mettre à jour :")
            for name, ver in pending[:25]:
                self.log.info(f"    {name} → {ver}")
            self._est((EST_APT_MIN + EST_UPGRADE_MIN) * 60)
            cmd = ("DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a "
                   "NEEDRESTART_SUSPEND=1 apt-get full-upgrade -y -q "
                   "-o DPkg::Lock::Timeout=600 "
                   "-o Dpkg::Options::=--force-confdef "
                   "-o Dpkg::Options::=--force-confold")
            if self.dry:
                self._sim(f"{node} : {cmd}")
            else:
                self.log.info(f"{node} : apt full-upgrade (paquets "
                              f"Ceph) — streaming…")
                self.client.apt_upgrade(node)
            self.counts["pkg_nodes"] += 1
            # 2) Redémarrage ORDONNÉ des daemons du nœud (mon → mgr →
            #    osd → mds), gates de santé entre chaque type.
            d = self.client.node_daemons(node)
            for mid in d["mon"]:
                self._mut(f"systemctl restart ceph-mon@{mid}", node=node,
                          desc=f"redémarrage du mon {mid}")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_MON_S)
                self._gate(f"restart mon {mid} ({node})", node=None)
            for mid in d["mgr"]:
                self._mut(f"systemctl restart ceph-mgr@{mid}", node=node,
                          desc=f"redémarrage du mgr {mid}")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_MGR_S)
                self._gate(f"restart mgr {mid} ({node})")
            if d["osd"]:
                # Nombre d'OSD RÉELLES du nœud (CRUSH tree) — le scan fs
                # compterait aussi les répertoires vestiges.
                if node in self._osd_tree:
                    n_osd = len(self._osd_tree[node])
                else:
                    n_osd = len(d["osd"])
                self._mut("systemctl restart ceph-osd.target", node=node,
                          desc=f"redémarrage des {n_osd} OSD(s) du "
                               f"nœud (tous ensemble, nœud isolé)")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_OSD_S)
                self._gate(f"restart des OSDs de {node}", node=node)
            for mid in d["mds"]:
                self._mut(f"systemctl restart ceph-mds@{mid}", node=node,
                          desc=f"redémarrage du mds {mid}")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_MDS_S)
                self._gate(f"restart mds {mid} ({node})")
            if not (d["mon"] or d["mgr"] or d["osd"] or d["mds"]):
                self.log.info(f"{node} n'héberge aucun daemon Ceph — "
                              f"rien à redémarrer.")

    # ---------------- Action 2 : mise à jour MAJEURE ----------------
    def _mon_release_check(self, rel: str, num: int) -> None:
        """Vérifie « ceph mon dump | grep min_mon_release ». Les mons
        mettent la monmap à jour vers la nouvelle release quand ils
        ont TOUS rejoint en version nouvelle : le bump prend
        quelques secondes après le dernier restart (vécu : check
        immédiat → monmap encore à l'epoch précédente → abort à
        tort). Poll jusqu'à ELECTION_TIMEOUT_S :
        - des mons tournent encore l'ancienne version → abort
          immédiat (un restart a réellement échoué) ;
        - tous en nouvelle version → attente de la monmap, abort au
          timeout seulement si elle ne se met pas à jour."""
        want = f"min_mon_release {num} "
        t0 = time.time()
        while True:
            out = self.client.ceph_run("ceph mon dump | grep "
                                       "min_mon_release")
            got = " ".join(out.split())
            if want in got + " ":
                self.log.info(f"min_mon_release OK : {got} ✔")
                return
            versions = self.client.ceph_versions()
            mons = versions.get("mon") or {}
            late = [f"{nb}× {ver}" for ver, nb in sorted(mons.items())
                    if not re.match(rf"ceph version {num}\.", ver)]
            if late:
                raise RuntimeError(
                    f"min_mon_release attendu {num} ({rel}) non atteint "
                    f"({got}) et des mons tournent encore l'ancienne "
                    f"version ({'; '.join(late)}) — un restart a échoué. "
                    f"« ceph versions » / « ceph mon dump » pour "
                    f"diagnostiquer, puis relancez (reprise).")
            if time.time() - t0 > ELECTION_TIMEOUT_S:
                raise RuntimeError(
                    f"min_mon_release attendu {num} ({rel}) toujours non "
                    f"atteint après {int(ELECTION_TIMEOUT_S)} s ({got}) "
                    f"alors que tous les mons tournent en {rel} — la "
                    f"monmap ne se met pas à jour. « ceph mon dump » / "
                    f"« ceph versions » pour diagnostiquer, puis "
                    f"relancez (reprise).")
            self.log.warning(
                f"Tous les mons tournent en {rel} — attente de la mise "
                f"à jour AUTOMATIQUE de la monmap (min_mon_release "
                f"{num}, recheck toutes les {CEPH_POLL_S} s)…")
            time.sleep(CEPH_POLL_S)

    def major_run(self) -> None:
        rel = self.major_release
        num = KNOWN_RELEASES[rel]
        # ---- Phase A : dépôt apt sur TOUS les nœuds ----
        banner(self.log, f"PHASE A — Bascule du dépôt Ceph vers « {rel} » "
                         f"(tous les nœuds)")
        for node in self.nodes:
            branch = self.client.ceph_repo_branch(node)
            if branch in ("?", "none"):
                self.log.warning(f"{node} : dépôt Ceph introuvable — "
                                 f"à basculer MANUELLEMENT avant de "
                                 f"relancer (ex. /etc/apt/sources.list.d/"
                                 f"ceph.list).")
                continue
            if branch == rel:
                self.log.info(f"{node} : dépôt déjà sur ceph-{rel} — "
                               f"rien à faire.")
                continue
            # fichiers RÉELS déclarant le dépôt : le nom n'est pas
            # standardisé (ceph.list, ceph.sources, pveceph.list,
            # sources.list…) et un sed sur des chemins codés en dur
            # échoue avec le code 2 quand ils n'existent pas.
            try:
                files = self.client.ceph_repo_files(node, branch)
            except Exception:
                files = []
            if not files:
                msg = (f"{node} : aucun fichier déclarant le dépôt "
                       f"ceph-{branch} trouvé (ni /etc/apt/sources.list.d/ "
                       f"ni /etc/apt/sources.list) — bascule à faire "
                       f"MANUELLEMENT, puis relancez (reprise là où "
                       f"le run s'est arrêté).")
                if self.dry:
                    self.log.warning(msg + " (simulation : le run "
                                     "continuerait, l'exécution réelle "
                                     "s'arrêterait ici.)")
                    continue
                raise RuntimeError(msg)
            for path in files:
                self._mut(f"sed -i 's/ceph-{branch}/ceph-{rel}/g' "
                          f"\"{path}\"",
                          node=node,
                          desc=f"bascule du dépôt ceph-{branch} → "
                               f"ceph-{rel} ({path})")
            if not self.dry:
                out = self.client._ssh(
                    node, "grep -rh 'ceph-' /etc/apt/sources.list.d/ "
                          "2>/dev/null | grep -E '^(deb|URIs|Components)' "
                          "| head -3")
                for ln in out.splitlines():
                    if ln.strip():
                        self.log.info(f"    {ln.strip()}")
        # ---- Phase B : paquets sur TOUS les nœuds (binaires d'abord) ----
        banner(self.log, f"PHASE B — Upgrade des paquets Ceph vers {rel} "
                         f"(tous les nœuds, AVANT tout redémarrage)")
        for node in self.nodes:
            if self.dry:
                # « apt-get update -q » ne modifie que le CACHE des
                # paquets disponibles (rien n'est installé ni
                # supprimé) : SANS RISQUE — exécuté RÉELLEMENT en
                # dry-run, suivi de « apt-get -s full-upgrade »
                # (simulation pure, lecture seule) pour AFFICHER ce
                # qu'il y aurait à faire (vécu 10:34 : un dry-run
                # 100 % [SIMULATION] ne renseignait pas sur les
                # paquets réellement en attente).
                try:
                    self.client.apt_update(node)
                    self.log.info(
                        f"{node} : apt-get update -q exécuté "
                        f"RÉELLEMENT (dry-run : sans risque — cache "
                        f"des paquets uniquement)")
                except Exception as e:
                    self.log.warning(
                        f"{node} : apt-get update -q impossible ({e}) — "
                        f"la simulation apt qui suit peut sous-estimer "
                        f"les paquets en attente.")
                others: List[str] = []
                pend = self.client.ceph_pkg_pending(node, others=others)
                if pend:
                    self.log.info(
                        f"{node} : « apt-get full-upgrade » mettrait à "
                        f"jour {len(pend)} paquet(s) Ceph :")
                    for name, pver in pend[:25]:
                        self.log.info(f"    {name} → {pver}")
                else:
                    self.log.info(
                        f"{node} : aucun paquet Ceph en attente — "
                        f"« apt-get full-upgrade » n'aurait rien à "
                        f"faire pour Ceph.")
                if others:
                    self.log.info(
                        f"{node} : (et {len(others)} autre(s) paquet(s) "
                        f"non-Ceph — full-upgrade est GLOBAL, il les "
                        f"mettrait à jour aussi)")
                self._sim(f"{node} : apt-get full-upgrade -y (binaires {rel} "
                          f"installés, les anciens daemons tournent encore)")
            else:
                self.client.apt_update(node)
                # « apt-get update -q » a rafraîchi le cache : la
                # simulation « apt-get -s full-upgrade » (lecture
                # pure) dit s'il reste QUELQUE CHOSE à faire. Rien
                # à faire → full-upgrade inutile (vécu 10:50 : 3
                # « 0 upgraded, 0 newly installed » streamés pour
                # rien). Simulation ILLISIBLE → full-upgrade quand
                # même (échec sûr, comportement historique).
                sim = self.client.apt_sim_all(node)
                if sim is not None and not sim[0] and not sim[1]:
                    self.log.info(
                        f"{node} : aucun paquet en attente après "
                        f"« apt-get update -q » (simulation « apt-get -s "
                        f"full-upgrade » vide) — « apt-get full-upgrade » "
                        f"n'est PAS lancé : rien à faire, les binaires "
                        f"sont déjà en place.")
                    continue
                if sim is None:
                    self.log.warning(
                        f"{node} : simulation « apt-get -s full-upgrade » "
                        f"illisible — « apt-get full-upgrade » lancé quand "
                        f"même (échec sûr).")
                else:
                    self.log.info(f"{node} : apt full-upgrade "
                                  f"({len(sim[0])} paquet(s) Ceph, "
                                  f"{len(sim[1])} autre(s), en attente) — "
                                  f"streaming…")
                self.client.apt_upgrade(node)
            self.counts["pkg_nodes"] += 1
            self._est((EST_APT_MIN + EST_UPGRADE_MIN) * 60)
            self._gate(f"upgrade des paquets {rel} ({node})")
        # ---- Phase C : mons un par un ----
        banner(self.log, "PHASE C — Redémarrage des MONS un par un "
                         "(quorum maintenu à chaque étape)")
        restarted_mon = False
        for node in self.nodes:
            for mid in self.client.node_daemons(node)["mon"]:
                # Version COURANTE du processus (« ceph tell mon.X
                # version », lecture pure — cf. tell_running_version) :
                # un mon qui TOURNE déjà sur la release cible a déjà
                # été redémarré après l'upgrade des paquets, le
                # redémarrer de nouveau ne lui apporte rien (vécu
                # 09:34 : reprises successives, 3 mons déjà en
                # tentacle re-redémarrés à chaque run). Lecture
                # illisible → restart (échec sûr, wiki).
                ver, _r = self.client.tell_running_version("mon", mid)
                if ver == num:
                    self.log.info(f"{node} : mon {mid} tourne déjà en "
                                  f"{rel} — rien à faire.")
                    continue
                if ver == 0:
                    self.log.warning(
                        f"{node} : version courante du mon {mid} "
                        f"ILLISIBLE (« ceph tell » ET « ceph mon "
                        f"metadata ») — redémarrage par sécurité "
                        f"(échec sûr).")
                self._mut(f"systemctl restart ceph-mon@{mid}", node=node,
                          desc=f"redémarrage du mon {mid}")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_MON_S)
                self._gate(f"restart mon {mid} ({node})")
                restarted_mon = True
        if restarted_mon:
            if self.dry:
                self._sim(f"vérification : « ceph mon dump | grep "
                          f"min_mon_release » → attendu : "
                          f"min_mon_release {num} ({rel})")
            else:
                self._mon_release_check(rel, num)
        # ---- Phase D : mgrs ----
        banner(self.log, "PHASE D — Redémarrage des MGRS (tous les nœuds)")
        restarted_mgr = False
        for node in self.nodes:
            for mid in self.client.node_daemons(node)["mgr"]:
                # Version COURANTE du processus (même logique que les
                # mons en Phase C et les OSDs en Phase E) : un mgr
                # qui tourne déjà sur la cible est SAUTÉ ; lecture
                # illisible → restart (échec sûr, wiki).
                ver, _r = self.client.tell_running_version("mgr", mid)
                if ver == num:
                    self.log.info(f"{node} : mgr {mid} tourne déjà en "
                                  f"{rel} — rien à faire.")
                    continue
                if ver == 0:
                    self.log.warning(
                        f"{node} : version courante du mgr {mid} "
                        f"ILLISIBLE (« ceph tell » ET « ceph mgr "
                        f"metadata ») — redémarrage par sécurité "
                        f"(échec sûr). NB : les mgrs standby "
                        f"n'ignorent plus le tell depuis le repli "
                        f"« ceph mgr metadata » (vécu 10:34 : 2 mgrs "
                        f"déjà en cible annoncés à tort « à "
                        f"redémarrer »).")
                self._mut(f"systemctl restart ceph-mgr@{mid}", node=node,
                          desc=f"redémarrage du mgr {mid}")
                self.counts["restarts"] += 1
                self._est(EST_RESTART_MGR_S)
                self._gate(f"restart mgr {mid} ({node})")
                restarted_mgr = True
        if restarted_mgr:
            if self.dry:
                self._sim("vérification : un mgr actif est présent "
                          "(« ceph mgr dump » → active_name)")
            else:
                t0 = time.time()
                while True:
                    dump = self.client.ceph_json("ceph mgr dump")
                    active = dump.get("active_name")
                    if active:
                        self.log.info(f"mgr actif : {active} ✔")
                        break
                    # L'élection du mgr actif prend quelques secondes
                    # après les restarts : un check immédiat lirait
                    # « active_name » vide et avorterait à tort.
                    if time.time() - t0 > ELECTION_TIMEOUT_S:
                        raise RuntimeError(
                            "Aucun mgr actif après les redémarrages "
                            f"(attente {int(ELECTION_TIMEOUT_S)} s) — "
                            "« ceph mgr dump » pour diagnostiquer.")
                    self.log.warning("Attente de l'élection du mgr "
                                     f"actif (recheck toutes les "
                                     f"{CEPH_POLL_S} s)…")
                    time.sleep(CEPH_POLL_S)
        # ---- Phase E : OSDs, nœud par nœud ----
        # PAR DÉFAUT : versions courantes des daemons OSD (« ceph osd
        # metadata ») lues avant la passe — un nœud dont TOUTES les
        # OSDs tournent déjà sur {rel} est SAUTÉ (un daemon qui TOURNE
        # sur la release cible a nécessairement été redémarré APRÈS
        # l'upgrade des paquets : c'est une preuve, pas une hypothèse ;
        # vécu : reprise 16:45, 12 OSDs déjà en tentacle re-stopées
        # une par une pour rien) ; sinon ses OSDs sont redémarrées
        # d'un coup via ceph-osd.target (une gate par nœud). Le test
        # du sharding RocksDB par OSD (arrêt individuel obligatoire)
        # est l'OPT-IN --force-detection-sharding : OSDs une par
        # une, SANS exemption de version — la date de création des
        # répertoires n'est qu'une heuristique, la vérité terrain
        # est ce test.
        if self.force_sharding:
            banner(self.log, "PHASE E — Mise à jour des OSDs UNE PAR UNE "
                             "(--force-detection-sharding ; arrêt → test "
                             "du sharding réel → démarrage)")
        else:
            banner(self.log, "PHASE E — Mise à jour des OSDs (nœud par "
                             "nœud : versions courantes vérifiées, puis "
                             "« systemctl restart ceph-osd.target » — "
                             "une gate par nœud)")
        osd_versions: Dict[int, Tuple[int, str]] = {}
        if self.force_sharding:
            if self.dry:
                self._sim("chaque OSD est arrêtée une par une (test du "
                          "sharding réel via « ceph-bluestore-tool "
                          "show-sharding ») puis redémarrée — SANS "
                          "exemption de version")
        else:
            osd_versions = self.client.osd_running_versions()
            if osd_versions:
                by_rel: Dict[str, int] = {}
                for _oid, (maj, r) in osd_versions.items():
                    lab = r or f"v{maj}"
                    by_rel[lab] = by_rel.get(lab, 0) + 1
                self.log.info(
                    "Versions courantes des OSDs : "
                    + ", ".join(f"{nb}× {lab}"
                                for lab, nb in sorted(by_rel.items()))
                    + f" — les nœuds dont toutes les OSDs sont déjà en "
                      f"{rel} sont sautés.")
            else:
                self.log.warning(
                    "Versions courantes des OSDs illisibles "
                    "(« ceph osd metadata ») — les OSDs seraient toutes "
                    "redémarrées (échec sûr).")
            if self.dry:
                self._sim(f"les nœuds dont TOUTES les OSDs sont déjà "
                          f"en {rel} seraient sautés ; les autres : "
                          f"« systemctl restart ceph-osd.target » "
                          f"(une gate par nœud)")
        for node in self.nodes:
            ids = self._osd_tree.get(node)
            if ids is None:
                ids = [int(o) for o in self.client.node_daemons(node)["osd"]
                       if str(o).lstrip("-").isdigit()]
            if not ids:
                continue
            if not self.force_sharding:
                self._osd_upgrade_node_target(node, ids, num,
                                               osd_versions)
                continue
            try:
                dirs = {oid: p for oid, (p, _ts)
                        in self.client.osd_dirs_info(node).items()}
            except Exception:
                dirs = {}
            for oid in sorted(int(i) for i in ids):
                self._osd_upgrade_one(node, oid, dirs.get(oid),
                                       len(ids))
        # ---- Phase F : MDS (AVANT require-osd-release, comme le wiki) ----
        self._major_mds()
        # ---- Phase G : version minimale des OSDs ----
        banner(self.log, f"PHASE G — Interdiction des OSDs antérieurs à "
                         f"{rel} (« require-osd-release »)")
        if self.dry:
            self._sim(f"hypothèse : toutes les OSDs tournent en {rel} "
                      f"après la Phase E (vérification réelle : "
                      f"« ceph versions » → osd)")
        else:
            versions = self.client.ceph_versions()
            osds = versions.get("osd") or {}
            if not osds:
                raise RuntimeError(
                    f"Versions des OSDs illisibles (« ceph versions ») — "
                    f"require-osd-release DIFFÉRÉ : sans preuve que "
                    f"TOUTES les OSDs sont en {rel}, un daemon ancien ne "
                    f"pourrait plus redémarrer ensuite. Diagnostiquez, "
                    f"puis relancez (reprise).")
            late = [f"{nb}× {ver}" for ver, nb in sorted(osds.items())
                    if not re.match(rf"ceph version {num}\.", ver)]
            if late:
                raise RuntimeError(
                    f"OSD(s) pas toutes en {rel} ({'; '.join(late)}) — "
                    f"require-osd-release DIFFÉRÉ : un daemon ancien ne "
                    f"pourrait plus redémarrer ensuite. Diagnostiquez "
                    f"(« ceph versions », « ceph osd tree »), puis "
                    f"relancez (reprise là où le run s'est arrêté).")
            self.log.info(f"Toutes les OSDs tournent en {rel} ✔ — "
                          f"require-osd-release posable sans risque.")
        self._mut(f"ceph osd require-osd-release {rel}",
                  desc="version minimale des OSDs")

    def _osd_upgrade_one(self, node: str, oid: int, path: Optional[str],
                         per_node: int) -> None:
        """Cycle d'UNE OSD (mode --force-detection-sharding) : arrêt →
        lecture du sharding RocksDB RÉEL pendant l'arrêt (piège META
        du wiki, ceph-bluestore-tool show-sharding — lecture pure) →
        démarrage sur les nouveaux binaires → gate. Plus progressif
        que le « systemctl restart ceph-osd.target » du mode par
        défaut : une seule OSD down à la fois, et la vérité terrain
        du sharding en prime — SANS exemption de version (chaque
        OSD est testée, même déjà sur la release cible)."""
        try:
            self._mut(f"systemctl stop ceph-osd@{oid}", node=node,
                      desc=f"arrêt de {node}/osd.{oid}")
        except Exception:
            # Arrêt incertain : démarrage de secours best-effort, puis
            # abort propre (gate jamais passée → finally retire les flags).
            try:
                self._mut(f"systemctl start ceph-osd@{oid}", node=node,
                          desc=f"démarrage de secours de {node}/osd.{oid}")
            except Exception:
                pass
            raise
        self._shard_probe(node, oid, path)
        self._mut(f"systemctl start ceph-osd@{oid}", node=node,
                  desc=f"démarrage de {node}/osd.{oid} sur les nouveaux "
                       f"binaires")
        self.counts["restarts"] += 1
        self._est(EST_RESTART_OSD_S / max(1, per_node))
        self._gate(f"restart {node}/osd.{oid}", node=node)

    def _osd_upgrade_node_target(self, node: str, ids: List[int],
                                  num: int,
                                  osd_versions: Dict[int, Tuple[int, str]]
                                  ) -> None:
        """Phase E PAR DÉFAUT : versions courantes des OSDs du nœud
        (« ceph osd metadata »), puis « systemctl restart
        ceph-osd.target » si (et seulement si) au moins une OSD
        n'est PAS encore sur la release cible — un nœud déjà à jour
        est sauté (reprise idempotente). Impact plus large : pendant
        le restart, AUCUNE OSD du nœud ne sert d'IO — les réplicas
        des autres nœuds maintiennent le service (min_size ≥ 2, ou
        min_size_inactive/erasure selon le pool, requis). Le test du
        sharding RocksDB par OSD y est IMPOSSIBLE (il exige l'arrêt
        individuel de chaque OSD) : la vérité terrain est l'OPT-IN
        --force-detection-sharding ; la date de création des
        répertoires (préflight) n'est qu'une heuristique."""
        stale = [int(o) for o in ids
                 if osd_versions.get(int(o), (0, ""))[0] != num]
        if not stale:
            self._osd_skipped += len(ids)
            self.log.info(f"{node} : toutes les OSDs tournent déjà en "
                          f"{self.major_release} — rien à faire.")
            return
        self.log.info(
            f"{node} : {len(stale)} OSD(s) à redémarrer ("
            + ", ".join(f"osd.{o}" for o in sorted(stale))
            + ") — redémarrage de TOUTES les OSDs du nœud via "
            f"ceph-osd.target (une seule gate pour le nœud) ; sharding "
            f"RocksDB NON testé dans ce mode (vérité terrain : "
            f"--force-detection-sharding).")
        self._mut("systemctl restart ceph-osd.target", node=node,
                  desc=f"redémarrage de toutes les OSDs de {node}")
        self.counts["restarts"] += len(ids)
        self._est(EST_RESTART_OSD_S)
        self._gate(f"restart ceph-osd.target ({node})", node=node)
        self._osd_target_used = True

    def _shard_probe(self, node: str, oid: int,
                     path: Optional[str]) -> None:
        """Test du sharding RocksDB réel pendant l'arrêt de l'OSD :
        « ceph-bluestore-tool show-sharding --path <dir> ». OSD NON
        shardée (créée sous Octopus v15 ou avant) → « failed to
        retrieve sharding def » ; shardée → un sharding-def (m(3)
        p(3,0-12) …). Lecture pure : un échec quelconque (outil
        absent, chemin introuvable, sortie illisible) ne bloque
        JAMAIS la montée — l'OSD redémarre toujours."""
        label = path or f"<répertoire de {node}/osd.{oid}>"
        if self.dry:
            self._sim(f"test du sharding réel de {node}/osd.{oid} pendant "
                      f"l'arrêt : « ceph-bluestore-tool show-sharding "
                      f"--path {label} » (lecture pure)")
            return
        if not path:
            self.log.info(f"{node}/osd.{oid} : répertoire de données "
                          f"introuvable — test du sharding sauté "
                          f"(pas bloquant).")
            return
        try:
            out = self.client.ceph_run(
                f"ceph-bluestore-tool show-sharding --path {path}",
                node=node)
        except Exception as exc:
            self.log.warning(f"{node}/osd.{oid} : test du sharding impossible "
                             f"({exc}) — pas bloquant.")
            return
        txt = (out or "").strip()
        self._shard_probed += 1
        if "failed to retrieve sharding def" in txt.lower():
            self._nonsharded.append(f"{node}/osd.{oid}")
            self.log.warning(
                f"{node}/osd.{oid} : RocksDB NON shardé (show-sharding) — "
                f"usage META à surveiller après la montée "
                f"(récapitulatif au bilan).")
        elif txt:
            self.log.info(f"{node}/osd.{oid} : RocksDB shardé ✔ "
                          f"(show-sharding)")

    def _major_mds(self) -> None:
        """Procédure MDS du wiki Proxmox : standby_replay off, max_mds→1,
        attente des ranks, arrêt des standbys (unité par unité), restart
        des actives EN DERNIER (une par FS, identifiées via « ceph fs
        dump » — fiable en multi-FS, contrairement au mdsmap global de
        « ceph status »), retour des standbys, restauration."""
        rel = self.major_release
        num = KNOWN_RELEASES[rel]
        fs_list = self.client.fs_list()
        mds_nodes = [n for n in self.nodes
                     if self.client.node_daemons(n)["mds"]]
        if not fs_list or not mds_nodes:
            self.log.info("Aucun CephFS / aucun MDS — phase MDS sans objet.")
            return
        banner(self.log, f"PHASE F — Upgrade des MDS ({', '.join(fs_list)})")
        # 1) réglages d'origine + réduction à 1 rank actif
        orig: Dict[str, Tuple[int, str]] = {}
        for fs in fs_list:
            max_mds, asr = 1, "false"
            try:
                # Lecture PURE : faite aussi en dry-run pour une
                # simulation fidèle (réduction/restauration montrées
                # si max_mds > 1 ou standby_replay actif).
                out = self.client.ceph_run(f"ceph fs get {fs}")
            except Exception as e:
                if not self.dry:
                    raise
                self.log.warning(
                    f"{fs} : réglages MDS illisibles ({e}) — hypothèse "
                    f"max_mds=1 / standby_replay=off pour la simulation.")
                out = ""
            m = re.search(r"max_mds\s+(\d+)", out)
            max_mds = int(m.group(1)) if m else 1
            asr = "true" if re.search(r"allow_standby_replay\s+true",
                                      out) else "false"
            orig[fs] = (max_mds, asr)
            if asr == "true":
                self._mut(f"ceph fs set {fs} allow_standby_replay false",
                          desc=f"{fs} : standby_replay off (temporaire)")
            if max_mds > 1:
                self._mut(f"ceph fs set {fs} max_mds 1",
                          desc=f"{fs} : max_mds 1 (temporaire, "
                               f"origine {max_mds})")
        # 2) attente de la réduction des ranks + 3) identification
        #    des MDS ACTIVES par nom — tout via « ceph fs dump -f
        #    json » (commande MON native, fiable en MULTI-FS ; le
        #    mdsmap global de « ceph status » ne reflète qu'un seul
        #    FS et peut être vide). Lecture pure, aussi en dry-run
        #    pour une simulation fidèle : l'active est la DERNIÈRE à
        #    redémarrer (wiki). En exécution, un échec de lecture
        #    ABORT : refus d'arrêter des MDS sans savoir lesquelles
        #    sont actives.
        active_names: List[str] = []
        if self.dry:
            self._sim("attente : les ranks non nuls se désactivent "
                      "(« ceph fs dump » → 1 rank actif par FS)")
            try:
                active_names, _stb, _up = self.client.fs_dump_actives()
            except Exception as exc:
                self.log.warning(f"MDS actives illisibles ({exc}) — "
                                 f"simulation générique.")
        else:
            t0 = time.time()
            while True:
                try:
                    active_names, _stb, up_ranks = \
                        self.client.fs_dump_actives()
                except Exception as exc:
                    raise RuntimeError(
                        f"MDS actives illisibles (« ceph fs dump » : "
                        f"{exc}) — refus d'arrêter les MDS à l'aveugle : "
                        f"la procédure wiki exige de redémarrer l'active "
                        f"EN DERNIER. Diagnostiquez puis relancez "
                        f"(reprise).") from exc
                if up_ranks <= len(fs_list):
                    self.log.info(f"Ranks réduits : {up_ranks} MDS "
                                  f"active(s) au total (1 par FS) ✔")
                    break
                if time.time() - t0 > CEPH_STABLE_TIMEOUT:
                    raise RuntimeError("Les ranks MDS ne se désactivent "
                                       "pas — « ceph fs dump » pour "
                                       "diagnostiquer.")
                self.log.warning("Attente de la désactivation des ranks "
                                 "MDS supplémentaires…")
                time.sleep(CEPH_POLL_S)
        daemon_node: Dict[str, str] = {}
        for node in mds_nodes:
            for d in self.client.node_daemons(node)["mds"]:
                daemon_node[str(d)] = node
        missing = [a for a in active_names if a not in daemon_node]
        if missing:
            if self.dry:
                self.log.warning(
                    f"MDS active(s) hors inventaire : {', '.join(missing)}"
                    f" — hypothèse simulation (restart générique).")
            else:
                raise RuntimeError(
                    f"MDS active(s) hors inventaire des daemons : "
                    f"{', '.join(missing)} — unités systemd introuvables, "
                    f"refus d'arrêter les MDS à l'aveugle.")
        # 4) arrêt des STANDBYS unité par unité (jamais le target : son
        #    stop atteindrait AUSSI les MDS actives du nœud, et son
        #    start ne relance que les unités « enabled » — asymétrie),
        #    restart des actives EN DERNIER, retour des standbys.
        standby_daemons = [(d, daemon_node[d]) for d in sorted(daemon_node)
                           if d not in active_names]
        mds_skipped: Set[str] = set()
        for name, node in standby_daemons:
            # Idempotence de reprise (même logique que mons/mgrs/OSDs) :
            # une standby qui TOURNE déjà sur la cible n'a plus rien
            # à gagner d'un cycle stop/start (vécu : run interrompu
            # APRÈS le retour des standbys, redémarrées pour rien).
            # Lecture illisible (daemon down) → stop/start quand même
            # (échec sûr : le start la ramène).
            ver, _r = self.client.tell_running_version("mds", name)
            if ver == num:
                self.log.info(f"MDS standby {name} ({node}) tourne déjà "
                              f"en {rel} — rien à faire.")
                mds_skipped.add(name)
                continue
            if ver == 0:
                self.log.warning(
                    f"version courante de la MDS standby {name} ({node}) "
                    f"ILLISIBLE (« ceph tell » ET « ceph mds metadata ») "
                    f"— stop/start quand même (échec sûr : le start la "
                    f"ramène).")
            self._mut(f"systemctl stop ceph-mds@{name}", node=node,
                      desc=f"arrêt de la MDS standby {name} ({node})")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_MDS_S)
        for name in active_names:
            if name not in daemon_node:
                continue    # signalé plus haut (dry uniquement)
            node = daemon_node[name]
            # Idem pour l'active : déjà sur la cible → skip (elle a
            # déjà été redémarrée EN DERNIER par un run précédent).
            ver, _r = self.client.tell_running_version("mds", name)
            if ver == num:
                self.log.info(f"MDS active {name} ({node}) tourne déjà "
                              f"en {rel} — rien à faire.")
                continue
            if ver == 0:
                self.log.warning(
                    f"version courante de la MDS active {name} ({node}) "
                    f"ILLISIBLE (« ceph tell » ET « ceph mds metadata ») "
                    f"— restart quand même (échec sûr : elle repart sur "
                    f"les nouveaux binaires).")
            self._mut(f"systemctl restart ceph-mds@{name}", node=node,
                      desc=f"redémarrage de la MDS active {name} — la "
                           f"dernière à tourner sur {rel}")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_MDS_S)
            self._gate(f"restart MDS active {name} ({node})")
        if self.dry and not active_names:
            # simulation fidèle même sans actif lisible : l'étape du
            # restart de l'actif (le DERNIER, wiki) doit apparaître.
            self._sim(f"redémarrage du MDS actif — le DERNIER à tourner "
                      f"sur {rel} (noms réels lus via « ceph fs dump »)")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_MDS_S)
        for name, node in standby_daemons:
            if name in mds_skipped:
                continue    # jamais arrêtée : déjà en cible, rien à faire
            self._mut(f"systemctl start ceph-mds@{name}", node=node,
                      desc=f"retour de la MDS standby {name} ({node})")
        # 5) restauration des réglages d'origine
        for fs, (max_mds, asr) in orig.items():
            if max_mds > 1:
                self._mut(f"ceph fs set {fs} max_mds {max_mds}",
                          desc=f"{fs} : restauration max_mds {max_mds}")
            if asr == "true":
                self._mut(f"ceph fs set {fs} allow_standby_replay true",
                          desc=f"{fs} : restauration standby_replay")

    # ---------------- Action 3 : rotation des clés (CVE-2025-30156) ----
    def _backup_keyring(self, bdir: str, name: str,
                        content: str) -> Optional[str]:
        """Archive localement une keyring régénérée (chmod 700/0600).
        Retourne le chemin, None si contenu vide."""
        if not content or not content.strip():
            return None
        path = os.path.join(bdir, name)
        try:
            os.makedirs(bdir, exist_ok=True)
            os.chmod(bdir, 0o700)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.chmod(path, 0o600)
            self.log.info(f"    keyring archivée : {name} (backup local "
                          f"du worker)")
            return path
        except OSError as e:
            self.log.warning(f"    keyring {name} NON archivée ({e}) — "
                             f"elle reste disponible dans l'auth DB Ceph.")
            return None

    def _refresh_insecure(self) -> Dict[str, List[str]]:
        """État courant des entités/clés faibles. En dry-run : la liste
        réelle ne peut pas changer (rien n'est exécuté) — on simule la
        progression en retirant ce qui a été (simulé comme) traité."""
        if not self.dry:
            self._insecure = self.client.insecure_entities()
            return self._insecure
        # codes portés par des ENTITÉS : disparaissent quand toutes
        # leurs entités ont été (simulées comme) migrées.
        entity_codes = ("AUTH_INSECURE_CLIENT_KEY_TYPE",
                        "AUTH_INSECURE_SERVICE_KEY_TYPE",
                        "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE")
        res: Dict[str, List[str]] = {}
        for code, ents in self._insecure.items():
            if code in self._sim_cleared_codes:
                continue
            keep = [e for e in ents if e not in self._sim_rotated]
            if code in entity_codes and not keep:
                continue
            res[code] = keep
        return res

    def _rotate_keys_run(self, bdir: str) -> None:
        # --- Étape 1 : ciphers autorisés (aes256k doit y figurer) ---
        banner(self.log, "ÉTAPE 1 — Ciphers d'authentification autorisés "
                         "(« aes256k » doit être présent)")
        allowed: List[str] = []
        if not self.dry:
            dump = self.client.ceph_json("ceph mon dump")
            for c in dump.get("auth_allowed_ciphers") or []:
                allowed.append(c.get("name", "") if isinstance(c, dict)
                               else str(c))
            self.log.info(f"Ciphers autorisés : {', '.join(allowed)}")
        if "aes256k" not in allowed:
            self._mut("ceph mon set auth_allowed_ciphers aes,aes256k",
                      desc="ajout de aes256k aux ciphers autorisés "
                           "(aes conservé le temps de la migration)")
        else:
            self.log.info("aes256k déjà autorisé ✔")
        # --- Étape 2 : cipher préféré pour les NOUVELLES clés ---
        banner(self.log, "ÉTAPE 2 — Cipher préféré pour les nouvelles clés")
        preferred = ""
        if not self.dry:
            dump = self.client.ceph_json("ceph mon dump")
            pc = dump.get("auth_preferred_cipher") or {}
            preferred = (pc.get("name", "") if isinstance(pc, dict)
                         else str(pc))
            self.log.info(f"Cipher préféré actuel : {preferred}")
        if preferred != "aes256k":
            self._mut("ceph mon set auth_preferred_cipher aes256k",
                      desc="nouvelles clés en aes256k par défaut")
        else:
            self.log.info("Cipher préféré déjà aes256k ✔")
        # --- Étape 3 : clé « mon. » + redémarrage des mons ---
        banner(self.log, "ÉTAPE 3 — Rotation de la clé « mon. » puis "
                         "redémarrage des mons un par un")
        inc = self._refresh_insecure()
        if "(mon)" in [e for v in inc.values() for e in v]:
            out = self._mut("ceph auth rotate --key-type=aes256k mon.",
                            desc="rotation de la clé mon. (la nouvelle clé "
                                 "vit désormais dans l'auth DB)")
            if not self.dry:
                self._backup_keyring(bdir, "mon.keyring", out)
            self.counts["keys_rotated"] += 1
            self._est(EST_KEY_ENTITY_S)
            if self.dry:
                self._sim_rotated.append("(mon)")
            for node in self.nodes:
                for mid in self.client.node_daemons(node)["mon"]:
                    self._mut(f"systemctl restart ceph-mon@{mid}",
                              node=node,
                              desc=f"redémarrage du mon {mid} (nouvelle clé)")
                    self.counts["restarts"] += 1
                    self._est(EST_RESTART_MON_S)
                    self._gate(f"restart mon {mid} (clé mon. renouvelée)")
        else:
            self.log.info("Clé « mon. » déjà en aes256k — reprise, "
                          "rien à faire ✔")
        self._state_write("clé mon. rotationnée")
        # --- Étape 4 : clés des MGR (daemon par daemon) ---
        banner(self.log, "ÉTAPE 4 — Rotation des clés MGR (daemon par "
                         "daemon, gate entre chacun)")
        for node in self.nodes:
            for mid in self.client.node_daemons(node)["mgr"]:
                entity = f"mgr.{mid}"
                if not self._needs_key(entity):
                    self.log.info(f"  {entity} : déjà en aes256k — repris ✔")
                    continue
                self._rotate_daemon_key("mgr", mid, node, entity, bdir)
        self._state_write("clés mgr rotationnées")
        # --- Étape 5 : clés des OSD (une par une, label bluestore compris) ---
        banner(self.log, "ÉTAPE 5 — Rotation des clés OSD (une par une : "
                         "stop → rotation → keyring local → label "
                         "bluestore → start → gate)")
        # Source de vérité du PLACEMENT des OSD : le CRUSH tree (le scan
        # filesystem /var/lib/ceph/osd peut lister des répertoires
        # vestiges d'OSD retirés — vus sur un cluster réel : osd.4/5
        # présents sur deux nœuds, dont un seul est l'hébergeur réel).
        # Le tree a été récupéré au preflight : on le réutilise.
        tree_map = self._osd_tree
        if not tree_map:
            try:
                tree_map = self.client.osds_of_node_tree()
                self._osd_tree = tree_map
            except Exception as e:
                self.log.warning(f"CRUSH tree indisponible ({e}) — étape 5 "
                                 f"basée sur le scan filesystem : méfiez-vous "
                                 f"des répertoires OSD vestiges.")
        for node in self.nodes:
            fs_osds = self.client.node_daemons(node)["osd"]
            if node in tree_map:
                osds = tree_map[node]
                self._warn_stale_osd_dirs(
                    node, self._stale_osd_dirs_of(node, fs_osds))
            else:
                osds = fs_osds
            for oid in osds:
                entity = f"osd.{oid}"
                if not self._needs_key(entity):
                    self.log.info(f"  {node}/{entity} : déjà en aes256k — "
                                  f"repris ✔")
                    continue
                self._rotate_osd_key(node, oid, entity)
        self._state_write("clés osd rotationnées")
        # --- Étape 6 : clés des MDS ---
        banner(self.log, "ÉTAPE 6 — Rotation des clés MDS (daemon par daemon)")
        for node in self.nodes:
            for mid in self.client.node_daemons(node)["mds"]:
                entity = f"mds.{mid}"
                if not self._needs_key(entity):
                    self.log.info(f"  {entity} : déjà en aes256k — repris ✔")
                    continue
                self._rotate_daemon_key("mds", mid, node, entity, bdir)
        self._state_write("clés mds rotationnées")
        # --- Étape 7 : les clés de service doivent être propres ---
        banner(self.log, "ÉTAPE 7 — Vérification : AUTH_INSECURE_SERVICE_"
                         "KEY_TYPE doit avoir disparu")
        self._check_cleared("AUTH_INSECURE_SERVICE_KEY_TYPE",
                            "des clés de service sont encore en « aes » : "
                            "des daemons n'ont pas été traités (reprise "
                            "ci-dessus au prochain run)")
        # --- Étape 8 : cipher des tickets de service ---
        banner(self.log, "ÉTAPE 8 — Tickets de service en aes256k "
                         "(« auth_service_cipher »)")
        self._mut("ceph mon set auth_service_cipher aes256k",
                  desc="les tickets de service émis par les mons passent "
                       "en aes256k")
        self._sim_cleared_codes.append("AUTH_INSECURE_SERVICE_TICKETS")
        self._check_cleared("AUTH_INSECURE_SERVICE_TICKETS",
                            "les tickets de service sont encore émis en aes")
        # --- Étape 9 : interdire la création de nouvelles clés faibles ---
        banner(self.log, "ÉTAPE 9 — Interdiction de créer de nouvelles "
                         "clés « aes »")
        self._mut("ceph config set mon 'mon auth allow insecure key' false",
                  desc="les mons refusent les nouvelles clés aes")
        self._sim_cleared_codes.append("AUTH_INSECURE_KEYS_CREATABLE")
        self._check_cleared("AUTH_INSECURE_KEYS_CREATABLE",
                            "les mons peuvent encore créer des clés aes")
        # --- Étape 10 : clé client.admin (+ clé de secours) ---
        banner(self.log, "ÉTAPE 10 — Rotation de la clé client.admin "
                         "(avec clé de secours)")
        self._rotate_admin_key(bdir)
        self._state_write("clé client.admin rotationnée")
        # --- Étape 11 : autres clients (bootstrap-*, clients métier) ---
        banner(self.log, "ÉTAPE 11 — Rotation des clés clients restantes")
        self._rotate_client_keys(bdir)
        # --- Étape 12 : retrait définitif de « aes » ---
        banner(self.log, "ÉTAPE 12 — Retrait de « aes » des ciphers "
                         "autorisés (point de non-retour)")
        # Même course asynchrone que _check_cleared (health check
        # recalculé par les mons) : poller avant de REFUSER le retrait.
        t0 = time.time()
        while True:
            inc = self._refresh_insecure()
            leftover = [e for e in
                        inc.get("AUTH_INSECURE_CLIENT_KEY_TYPE", [])
                        if e and e != "client.admin"
                        and e not in self.skip_clients]
            leftover += inc.get("AUTH_INSECURE_SERVICE_KEY_TYPE", [])
            if not leftover or time.time() - t0 > ROTATE_CHECK_TIMEOUT_S:
                break
            self.log.warning(
                f"clés encore signalées en « aes » ({', '.join(leftover)})"
                " — le health check des mons se recalcule toutes les "
                f"quelques secondes, attente (recheck toutes les "
                f"{CEPH_POLL_S} s, max {int(ROTATE_CHECK_TIMEOUT_S)} s)…")
            time.sleep(CEPH_POLL_S)
        skipped_now = sorted(set(inc.get("AUTH_INSECURE_CLIENT_KEY_TYPE", []))
                             & self.skip_clients)
        if leftover:
            raise RuntimeError(
                f"Refus de retirer « aes » : des clés faibles restent "
                f"({', '.join(leftover)}). Terminez leur rotation puis "
                f"relancez --rotate-keys (la reprise sautera ce qui est "
                f"déjà traité ; seule cette étape finale restera).")
        if skipped_now:
            self.log.warning(
                f"Retrait de « aes » DIFFÉRÉ : client(s) volontairement "
                f"non migré(s) via --skip-client : "
                f"{', '.join(skipped_now)}. Leur clé reste en « aes » ; "
                f"« aes » reste donc autorisé (aucun point de non-retour "
                f"n'est franchi). Relancez --rotate-keys sans "
                f"--skip-client une fois leurs consommateurs capables "
                f"d'aes256k : la reprise ne traitera que ce qui reste.")
            self._sim("retrait de « aes » DIFFÉRÉ (clients --skip-client) — "
                      "pas de mutation à cette étape")
        else:
            self._mut("ceph mon set auth_allowed_ciphers aes256k",
                      desc="« aes » n'est plus accepté pour "
                           "l'authentification")
            self._sim_cleared_codes.append("AUTH_INSECURE_KEYS_ALLOWED")
            self._check_cleared("AUTH_INSECURE_KEYS_ALLOWED",
                                "« aes » est encore autorisé")
        # --- Santé finale : HEALTH_OK SANS tolérance (sauf clés
        #     rotatives, qui expirent d'elles-mêmes en quelques heures) ---
        if not self.dry:
            st = self.client.ceph_status() or {}
            raw = (st.get("health") or {}).get("status", "?")
            checks = (st.get("health") or {}).get("checks") or {}
            ai = sorted(c for c in checks
                        if c.startswith("AUTH_INSECURE_"))
            expected = ["AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE"]
            if skipped_now:
                # des clients métier restent volontairement en « aes »
                # (--skip-client) : leur check reste présent, et « aes »
                # reste AUTORISÉ (retrait différé) — c'est ATTENDU
                expected = expected + [
                    "AUTH_INSECURE_CLIENT_KEY_TYPE",
                    "AUTH_INSECURE_KEYS_ALLOWED"]
            self.log.info(f"Santé Ceph brute après rotation : {raw}")
            if raw != "HEALTH_OK" and sorted(ai) != sorted(expected):
                self.client.ceph_diagnose(st, force=True)
                raise RuntimeError(
                    f"Santé brute {raw} après la rotation — diagnostics "
                    f"ci-dessus. Les clés sont migrées ; corrigez le "
                    f"problème résiduel (il n'est pas lié à la rotation).")
            if ai and sorted(ai) != sorted(expected):
                raise RuntimeError(f"Checks AUTH_INSECURE résiduels : "
                                  f"{', '.join(ai)} — inattendu.")
            if "AUTH_INSECURE_ROTATING_SERVICE_KEY_TYPE" in ai:
                self.log.info("Seul résidu : les clés de service ROTATIVES "
                              "en « aes » (normal) — elles expirent d'elles-"
                              "mêmes en quelques heures (TTL), la santé "
                              "passera HEALTH_OK sans action. Optionnel : "
                              "« ceph auth wipe-rotating-service-keys » "
                              "(non recommandé par les docs Ceph).")
            if skipped_now:
                self.log.info("✔ Phase « sans clients différés » TERMINÉE : "
                              "tous les daemons et les clés non différées "
                              "sont en aes256k. « aes » reste autorisé le "
                              "temps de migrer les consommateurs des "
                              "clients différés.")
                self.log.warning("CONSERVEZ PVE_CEPH_ALLOW_AUTH_INSECURE=1 "
                                 "dans le fichier env tant que les clients "
                                 "différés ne sont pas migrés (phase 2).")
            else:
                self.log.info("✔ Remédiation CVE-2025-30156 TERMINÉE : toutes "
                              "les clés sont en aes256k, « aes » est retiré, la "
                              "santé est HEALTH_OK (à TTL près).")
                self.log.warning("RETIREZ maintenant PVE_CEPH_ALLOW_AUTH_"
                                 "INSECURE=1 du fichier env : il n'a plus "
                                 "d'objet et masquerait une future régression.")
        else:
            if skipped_now:
                self._sim("Santé finale attendue : HEALTH_OK hors "
                          "AUTH_INSECURE_CLIENT_KEY_TYPE (clients différés "
                          "volontairement) ; « aes » reste autorisé — "
                          "conservez PVE_CEPH_ALLOW_AUTH_INSECURE=1 le "
                          "temps de la phase 2.")
            else:
                self._sim("Santé finale attendue : HEALTH_OK brut (au TTL des "
                          "clés rotatives près), plus aucun check AUTH_INSECURE_"
                          "* bloquant — retirez ensuite PVE_CEPH_ALLOW_AUTH_"
                          "INSECURE=1 du fichier env.")

    def _needs_key(self, entity: str) -> bool:
        """L'entité figure-t-elle encore dans les checks AUTH_INSECURE_* ?
        (base de la reprise : une clé déjà migrée n'y figure plus)."""
        inc = self._refresh_insecure()
        return entity in [e for v in inc.values() for e in v]

    def _rotate_daemon_key(self, dtype: str, did: str, node: str,
                           entity: str, bdir: str) -> None:
        """Rotation de la clé d'un daemon non-OSD (mgr/mds) SUR SON NŒUD :
        stop → rotation + import en une chaîne → start → gate."""
        self._mut(f"systemctl stop ceph-{dtype}@{did}", node=node,
                  desc=f"arrêt du daemon {entity}")
        chain = (f"ceph auth rotate --key-type=aes256k {entity} "
                 f"> /tmp/pru-rot.keyring && "
                 f"ceph-authtool --import-keyring /tmp/pru-rot.keyring "
                 f"/var/lib/ceph/{dtype}/ceph-{did}/keyring && "
                 f"rm -f /tmp/pru-rot.keyring")
        self._mut(chain, node=node,
                  desc=f"rotation + import de la clé {entity} (pas de "
                       f"backup local : la clé reste récupérable via "
                       f"« ceph auth get {entity} »)")
        if self.dry:
            self._sim_rotated.append(entity)
        self._mut(f"systemctl start ceph-{dtype}@{did}", node=node,
                  desc=f"démarrage du daemon {entity}")
        self.counts["restarts"] += 1
        self.counts["keys_rotated"] += 1
        self._est(EST_RESTART_MGR_S + EST_KEY_ENTITY_S)
        self._gate(f"restart {entity} ({node})")

    def _rotate_osd_key(self, node: str, oid: str, entity: str) -> None:
        """Rotation de la clé d'UN OSD, procédure officielle : stop →
        « ceph osd down » → rotation + import keyring local → MISE À JOUR
        DU LABEL BLUESTORE (OSDs ceph-volume : la clé est dupliquée dans
        le label du disque) → start → gate (OSD 'up', PGs propres)."""
        self._mut(f"systemctl stop ceph-osd@{oid}", node=node,
                  desc=f"arrêt de {node}/{entity}")
        self._mut(f"ceph osd down {oid}",
                  desc=f"{node}/{entity} marqué 'down' explicitement")
        # device des OSDs ceph-volume (lecture pure) : LV lvm, sinon raw
        lv_path = self._osd_device_path(node, oid)
        chain = (f"ceph auth rotate --key-type=aes256k {entity} "
                 f"> /tmp/pru-rot.keyring && "
                 f"ceph-authtool --import-keyring /tmp/pru-rot.keyring "
                 f"/var/lib/ceph/osd/ceph-{oid}/keyring")
        if lv_path:
            chain += (f" && ceph-bluestore-tool --dev {lv_path} "
                      f"set-label-key --key osd_key -v "
                      f"/tmp/pru-rot.keyring")
        chain += " && rm -f /tmp/pru-rot.keyring"
        self._mut(chain, node=node,
                  desc=f"rotation + import de la clé {node}/{entity}"
                       + (f" + label bluestore ({lv_path})"
                          if lv_path else ""))
        if self.dry:
            self._sim_rotated.append(entity)
        self._mut(f"systemctl start ceph-osd@{oid}", node=node,
                  desc=f"démarrage de {node}/{entity}")
        self.counts["restarts"] += 1
        self.counts["keys_rotated"] += 1
        self._est(EST_KEY_ENTITY_S + EST_RESTART_OSD_S / 4)
        self._gate(f"restart {node}/{entity}", node=node)

    def _osd_device_path(self, node: str, oid: str) -> Optional[str]:
        """Chemin du device de DONNÉES d'un OSD ceph-volume (LV du « block »
        lvm, sinon device raw), pour la mise à jour du label bluestore.
        Lecture pure — exécutée aussi en dry-run (aucun changement d'état).
        Retourne None si l'OSD n'est pas géré par ceph-volume : dans ce cas
        il n'y a PAS de label bluestore à mettre à jour (info, pas panne)."""
        # 1) OSD lvm : « ceph-volume lvm list <id> --format json »
        #    { "<id>": [ {"type": "block", "lv_path": "..."}, … ] } —
        #    une LISTE d'entrées par OSD (block + db/wal éventuels) ;
        #    l'entrée utile au label est celle de type « block ».
        err: List[str] = []
        try:
            out = self.client._ssh(
                node, f"ceph-volume lvm list {oid} --format json")
            entries: List[Dict] = []
            for _k, v in (json.loads(out) or {}).items():
                if isinstance(v, list):
                    entries.extend(e for e in v if isinstance(e, dict))
                elif isinstance(v, dict):
                    entries.append(v)  # anciens formats : dict direct
            blocks = [e for e in entries if e.get("type") == "block"]
            for e in (blocks or entries):
                if e.get("lv_path"):
                    return str(e["lv_path"])
            if entries:
                self.log.debug(f"    {node}/osd.{oid} : entrées ceph-volume lvm "
                               f"sans lv_path : {entries[0].get('lv_name')}")
        except Exception as e:
            err.append(f"lvm list : {e}")
        # 2) OSD raw : « ceph-volume raw list --format json »
        #    { "<id>": {"osd_id": "<id>", "device": "/dev/…"} }
        try:
            out = self.client._ssh(
                node, "ceph-volume raw list --format json")
            for k, v in (json.loads(out) or {}).items():
                if (isinstance(v, dict)
                        and str(v.get("osd_id", k)) == str(oid)
                        and v.get("device")):
                    return str(v["device"])
        except Exception as e:
            err.append(f"raw list : {e}")
        # 3) Pas trouvé : distinguer « pas un OSD ceph-volume » (label
        #    sans objet) d'un échec de lecture (à vérifier manuellement).
        if err:
            self.log.warning(f"  {node}/osd.{oid} : lecture ceph-volume impossible "
                             f"({' ; '.join(err)}) — device introuvable, "
                             f"label bluestore NON mis à jour : vérifiez "
                             f"manuellement si l'OSD refuse de redémarrer.")
        else:
            self.log.info(f"  {node}/osd.{oid} : OSD non géré par ceph-volume — "
                          f"pas de label bluestore à mettre à jour.")
        return None

    def _rotate_admin_key(self, bdir: str) -> None:
        """Rotation de client.admin avec clé de secours, distribution sur
        TOUS les chemins de keyring admin détectés, vérification sur
        chaque nœud, puis suppression de la clé de secours. Toutes les
        opérations /tmp sont épinglées au MÊME nœud d'exécution.

        PIÈGE (vécu 11:40) : dès que « ceph auth rotate » remplace la clé
        client.admin dans l'auth DB, l'ANCIENNE clé des keyrings LOCAUX
        (/etc/ceph/…, /etc/pve/priv/ceph/… — répliqué pmxcfs, donc TOUS
        les nœuds) est INVALIDÉE : « ceph auth get client.admin » avec
        la CLI du nœud échoue en « [errno 13] RADOS permission denied
        », et la CLI ceph de tout le cluster est hors service (le
        retrait des flags du bloc finally aussi). C'est PRÉCISÉMENT
        pour ça que la clé de secours client.admin-backup (mon
        « allow * ») est créée AVANT : l'import de la nouvelle clé
        passe par « ceph -n client.admin-backup -k …keyring auth get
        client.admin », la CLI locale ne re-fonctionne qu'APRÈS son
        import ; le keyring de secours est diffusé vers les nœuds qui
        ne l'ont pas (il n'existe que sur le nœud d'exécution).

        PIÈGE (vécu 12:29) : importer la nouvelle clé dans /etc/ceph et
        les keyrings des storages ne suffit PAS — sur Proxmox VE la
        CLI root lit le keyring AUTHORITATIF
        /etc/pve/priv/ceph.client.admin.keyring (et ceph.mon.keyring
        contient aussi une section client.admin). Tant qu'il garde
        l'ancienne clé, « ceph -s » échoue en « monclient(hunting):
        handle_auth_bad_method … (13) Permission denied » — d'où la
        liste de chemins élargie de _admin_keyring_paths et la
        vérification « ceph -s » sur CHAQUE nœud après les imports."""
        if not self._needs_key("client.admin"):
            self.log.info("client.admin déjà en aes256k — repris ✔")
            self._admin_backup_cleanup()
            self._admin_keyring_sync()
            return
        exec_node = self.nodes[0]
        # 1) clé de secours client.admin-backup (mon "allow *")
        self._mut("ceph auth get-or-create client.admin-backup mon 'allow *' "
                  "> /tmp/pru-admin-backup.keyring",
                  node=exec_node,
                  desc="création de la clé de secours client.admin-backup")
        self._mut("ceph -n client.admin-backup -k /tmp/pru-admin-backup."
                  "keyring auth ls >/dev/null",
                  node=exec_node,
                  desc="vérification de la clé de secours")
        backup_content = ""
        if not self.dry:
            backup_content = self.client._ssh(
                exec_node, "cat /tmp/pru-admin-backup.keyring")
            self._backup_keyring(bdir, "client.admin-backup.keyring",
                                 backup_content)
            if not backup_content.strip():
                raise RuntimeError(
                    "keyring de secours client.admin-backup illisible — "
                    "rotation de client.admin REFUSÉE (elle couperait la "
                    "CLI ceph de tout le cluster sans clé de secours "
                    "utilisable).")
        # 2) rotation (la NOUVELLE clé vit dans l'auth DB : chaque nœud la
        #    récupère via « ceph -n client.admin-backup … auth get
        #    client.admin » — la CLI locale ne marche PLUS ici)
        self._mut("ceph auth rotate --key-type=aes256k client.admin "
                  "> /tmp/pru-admin.keyring",
                  node=exec_node, desc="rotation de la clé client.admin")
        if not self.dry:
            out = self.client._ssh(exec_node, "cat /tmp/pru-admin.keyring")
            self._backup_keyring(bdir, "client.admin.keyring", out)
        if self.dry:
            self._sim_rotated.append("client.admin")
        # 3) import dans TOUS les keyrings admin de chaque nœud — VIA LA
        #    CLÉ DE SECOURS (les keyrings locaux ne contiennent plus que
        #    l'ancienne clé, invalidée par la rotation)
        for node in self.nodes:
            if node != exec_node:
                if self.dry:
                    self._sim(f"diffusion du keyring de secours "
                              f"client.admin-backup vers {node} (/tmp, "
                              f"chmod 600, le temps de l'import)")
                else:
                    spread = ("printf '%s\\n' "
                              + shlex.quote(backup_content)
                              + " > /tmp/pru-admin-backup.keyring"
                                " && chmod 600"
                                " /tmp/pru-admin-backup.keyring")
                    self._mut(spread, node=node,
                              desc=f"diffusion du keyring de secours "
                                   f"vers {node} (le temps de l'import)")
            paths = self._admin_keyring_paths(node)
            if not paths:
                self.log.warning(f"  {node} : aucun keyring client.admin "
                                 f"détecté — vérification manuelle requise.")
                continue
            for p in paths:
                self._mut("ceph -n client.admin-backup"
                          " -k /tmp/pru-admin-backup.keyring"
                          " auth get client.admin > /tmp/pru-admin.keyring"
                          " && ceph-authtool --import-keyring"
                          " /tmp/pru-admin.keyring " + shlex.quote(p) +
                          " && rm -f /tmp/pru-admin.keyring",
                          node=node,
                          desc=f"import de la nouvelle clé admin dans {p} "
                               f"(via la clé de secours)")
            self._mut("ceph -s --format json >/dev/null", node=node,
                      desc=f"vérification : la CLI ceph de {node} "
                           f"fonctionne avec la nouvelle clé")
            if node != exec_node:
                if self.dry:
                    self._sim(f"nettoyage du keyring de secours de {node}")
                else:
                    self._mut("rm -f /tmp/pru-admin-backup.keyring",
                              node=node,
                              desc=f"nettoyage du keyring de secours "
                                   f"de {node}")
        # 3bis) .secret des storages CephFS PVE en client.admin
        #       IMPLICITE : la clé NUE — invisible pour la détection
        #       keyring (aucune section [client.admin]) — doit être
        #       régénérée AUSSI, sinon les storages restent KO
        self._sync_cephfs_secrets()
        # 4) la clé de secours n'est plus utile (elle resterait une clé
        #    « aes » qui déclencherait AUTH_INSECURE_CLIENT_KEY_TYPE)
        self._mut("ceph auth rm client.admin-backup && rm -f "
                  "/tmp/pru-admin-backup.keyring",
                  desc="suppression de la clé de secours (rotation "
                       "vérifiée sur tous les nœuds)")
        self.counts["keys_rotated"] += 1
        self._est(EST_KEY_ENTITY_S * (1 + len(self.nodes)))

    def _pve_cephfs_secrets(self) -> List[str]:
        """Chemins .secret des storages PVE (cephfs/rbd) authentifiant
        en client.admin IMPLICITE — sans ligne « username » dans
        /etc/pve/storage.cfg, PVE utilise client.admin par défaut et
        garde la clé de ce user dans /etc/pve/priv/ceph/<id>.secret
        (clé NUE, PAS un keyring). Lecture pure."""
        try:
            cfg = self.client.ceph_run("cat /etc/pve/storage.cfg")
        except Exception as e:
            self.log.warning(f"/etc/pve/storage.cfg illisible ({e}) — "
                             f"secrets CephFS des storages PVE non "
                             f"vérifiés.")
            return []
        ids: List[str] = []
        cur_type = cur_id = ""
        has_user = False
        for line in str(cfg or "").splitlines():
            if line.strip() and not line[0].isspace():     # section
                if cur_type in ("cephfs", "rbd") and not has_user \
                        and cur_id:
                    ids.append(cur_id)
                head = line.strip()
                cur_type = head.split(":", 1)[0] if ":" in head else ""
                cur_id = head.split(":", 1)[1].strip() if ":" in head \
                    else ""
                has_user = False
            elif line.strip():                              # propriété
                kv = line.strip().split(None, 1)
                if kv and kv[0] == "username":
                    has_user = True
        if cur_type in ("cephfs", "rbd") and not has_user and cur_id:
            ids.append(cur_id)
        if not ids:
            return []
        quoted = " ".join(shlex.quote(i) for i in ids)
        try:
            out = self.client.ceph_run(
                "for s in " + quoted + "; do "
                "[ -f /etc/pve/priv/ceph/$s.secret ] && echo $s; done")
        except Exception:
            return []
        res = []
        for ln in str(out or "").splitlines():
            s = ln.strip()
            if s:
                res.append(f"/etc/pve/priv/ceph/{s}.secret")
        return res

    def _sync_cephfs_secrets(self, key_db: str = "") -> None:
        """(Re)synchronise les .secret des storages PVE en client.admin
        IMPLICITE (pas de « username » dans storage.cfg).

        PIÈGE (vécu 13:1x) : un storage CephFS de Proxmox VE garde la
        clé de son user dans /etc/pve/priv/ceph/<STORAGE_ID>.secret —
        la clé NUE (PAS un keyring : aucune section [client.admin],
        donc _admin_keyring_paths ne le voit JAMAIS). Sans username
        explicite c'est une copie de la clé client.admin : « A CephFS
        storage holds only the bare key » et « one created without an
        explicit key holds a copy of client.admin, so rotating
        client.admin alone cuts that storage off » (doc PVE) — après la
        rotation de client.admin, les storages passent « non Active »
        (montage KO) tant que le .secret n'est pas régénéré. Idempotent
        : seuls les .secret divergents sont réécrits (« > » préserve
        le mode du fichier existant)."""
        paths = self._pve_cephfs_secrets()
        if not paths:
            return
        if self.dry:
            self._sim("vérification : les .secret des storages PVE en "
                      "client.admin implicite (" + ", ".join(paths) +
                      ") contiennent la clé courante")
            return
        bare = (key_db or "").strip()
        if not bare:
            try:
                bare = self.client.ceph_run(
                    "ceph auth get-key client.admin").strip()
            except Exception as e:
                self.log.warning(f"Clé client.admin illisible ({e}) — "
                                 f"secrets CephFS des storages PVE non "
                                 f"vérifiés.")
                return
        if not bare:
            return
        for p in paths:
            try:
                cur = self.client.ceph_run("cat " + shlex.quote(p)
                                           ).strip()
            except Exception:
                cur = None   # illisible : resynchroniser par prudence
            if cur == bare:
                self.log.info(f"  {p} contient déjà la clé admin "
                              f"courante ✔")
                continue
            self.log.warning(f"  {p} contient une clé admin PÉRIMÉE — "
                             f"régénération (clé nue de client.admin).")
            self._mut("ceph auth get-key client.admin > "
                      + shlex.quote(p),
                      desc=f"synchronisation du secret CephFS {p}")

    def _admin_keyring_sync(self) -> None:
        """Reprise de l'étape 10 : les keyrings LOCAUX contiennent-ils
        la clé client.admin COURANTE de l'auth DB ?

        PIÈGE (vécu 13:0x) : la reprise juge « client.admin déjà en
        aes256k » SUR L'AUTH DB SEULE — elle ne sait RIEN des keyrings
        locaux. Or un run interrompu à l'étape 10 (FATAL avant les
        imports) + une réparation manuelle PARTIELLE laissent des
        keyrings avec l'ANCIENNE clé : sur Proxmox VE, les storages
        CephFS/RBD de /etc/pve/priv/ceph/<storage>.keyring authentifient
        par ces fichiers — les montages CephFS passent KO / les storages
        PVE restent « non Active », alors même que la CLI est réparée
        (authoritatif à jour) et que le run se termine en santé OK.
        Cette vérification compare la clé de CHAQUE keyring détecté à
        celle de l'auth DB et ré-importe (idempotent) les divergents :
        la reprise CONVERGE au lieu de considérer l'étape acquise."""
        if self.dry:
            self._sim("vérification : les keyrings locaux client.admin "
                      "contiennent la clé courante de l'auth DB")
            return
        try:
            db = self.client.ceph_run("ceph auth get client.admin")
        except Exception as e:
            self.log.warning(f"Lecture de la clé client.admin dans "
                             f"l'auth DB impossible ({e}) — "
                             f"synchronisation des keyrings locaux "
                             f"ignorée, vérifiez manuellement.")
            return
        key_db = ""
        for line in str(db or "").splitlines():
            if "key = " in line:
                key_db = line.split("key = ", 1)[1].strip()
                break
        if not key_db:
            self.log.warning("Clé client.admin illisible dans la sortie "
                             "« ceph auth get client.admin » — "
                             "synchronisation des keyrings locaux "
                             "ignorée.")
            return
        for node in self.nodes:
            try:
                paths = self._admin_keyring_paths(node)
            except Exception as e:
                self.log.warning(f"  {node} : keyrings admin illisibles "
                                 f"({e}) — nœud ignoré.")
                continue
            for p in paths:
                try:
                    out = self.client._ssh(
                        node, "grep -F -q " + shlex.quote(key_db) + " "
                        + shlex.quote(p) + " && echo yes || echo no")
                    has_key = out.strip().endswith("yes")
                except Exception:
                    has_key = False
                if has_key:
                    self.log.info(f"  {node} : {p} contient déjà la clé "
                                  f"admin courante ✔")
                    continue
                self.log.warning(f"  {node} : {p} contient une clé admin "
                                 f"PÉRIMÉE — ré-import de la clé courante "
                                 f"(keyring jamais mis à jour par un run "
                                 f"interrompu / une réparation partielle).")
                self._mut("ceph auth get client.admin"
                          " > /tmp/pru-admin.keyring"
                          " && ceph-authtool --import-keyring"
                          " /tmp/pru-admin.keyring " + shlex.quote(p) +
                          " && rm -f /tmp/pru-admin.keyring",
                          node=node,
                          desc=f"synchronisation du keyring admin {p}")
        # .secret des storages CephFS PVE en client.admin implicite :
        # clé NUE, invisible pour _admin_keyring_paths (vécu 13:1x)
        self._sync_cephfs_secrets(key_db)

    def _admin_backup_cleanup(self) -> None:
        """Reprise d'un run interrompu : la clé de secours
        client.admin-backup (mon « allow * ») n'est supprimée qu'APRÈS
        la vérification de la CLI sur tous les nœuds — un run interrompu
        ENTRE les deux (vécu 11:40 : FATAL « permission denied » à
        l'import sur le premier nœud) la laisse dans l'auth DB : une
        backdoor admin « allow * ». Elle est supprimée ici si elle
        subsiste (la reprise n'exécute PAS l'étape 10 puisque
        client.admin est déjà migrée)."""
        if self.dry:
            self._sim("vérification : clé de secours client.admin-backup "
                      "absente de l'auth DB (supprimée par le run "
                      "précédent)")
            return
        try:
            out = self.client.ceph_run("ceph auth get client.admin-backup")
        except Exception as e:
            self.log.warning(f"client.admin-backup introuvable dans "
                             f"l'auth DB ({e}) — vérifiez manuellement "
                             f"« ceph auth ls | grep admin-backup ».")
            return
        if "client.admin-backup" not in str(out or ""):
            return  # get a réussi sans keyring : absente, rien à faire
        self.log.warning("client.admin-backup (clé de secours « mon "
                         "allow * » d'un run interrompu) encore présente "
                         "dans l'auth DB — suppression (la rotation de "
                         "client.admin est déjà vérifiée).")
        self._mut("ceph auth rm client.admin-backup",
                  desc="suppression de la clé de secours orpheline "
                       "(run précédent interrompu)")
        self._mut("rm -f /tmp/pru-admin-backup.keyring",
                  node=self.nodes[0],
                  desc="nettoyage du keyring de secours local résiduel")

    def _admin_keyring_paths(self, node: str) -> List[str]:
        """Chemins des keyrings contenant client.admin sur un nœud.
        Lecture pure.

        PIÈGE (vécu 12:29) : sur Proxmox VE, le keyring admin
        AUTHORITATIF est /etc/pve/priv/ceph.client.admin.keyring (pas
        la copie de /etc/ceph !) — c'est LUI que lit la CLI « ceph »
        du root via le ceph.conf PVE. /etc/pve/priv/ceph.mon.keyring
        contient aussi une section client.admin (aux côtés de mon.) :
        l'import par entité de ceph-authtool remplace client.admin SANS
        toucher à mon. (merge sûr, ne jamais écraser le fichier).
        Importer la nouvelle clé uniquement dans /etc/ceph/… et les
        keyrings des storages (/etc/pve/priv/ceph/<id>.keyring) ne
        répare PAS la CLI : « ceph -s » continue d'échouer en
        « monclient(hunting): handle_auth_bad_method … (13) Permission
        denied » tant que l'authoritatif garde l'ancienne clé."""
        out = self.client._ssh(
            node,
            "for f in /etc/ceph/ceph.client.admin.keyring "
            "/etc/pve/priv/ceph.client.admin.keyring "
            "/etc/pve/priv/ceph.mon.keyring "
            "/etc/pve/priv/ceph/*.keyring; do "
            "[ -f \"$f\" ] && grep -l '^\\[client\\.admin\\]' \"$f\" "
            "2>/dev/null; done")
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

    def _rotate_client_keys(self, bdir: str) -> None:
        """Rotation des clés clients restantes. Les bootstrap-* (utilisées
        pour créer de futurs OSDs/MDS) et client.crash (daemon ceph-crash
        des nœuds) sont re-distribuées automatiquement ; les clients
        métier (ex. client.fs) sont sauvegardés avec instructions de
        distribution MANUELLE (le script ne peut pas connaître leurs
        consommateurs).

        PIÈGE (vécu 12:52) : le keyring bootstrap-<type> local
        (/var/lib/ceph/<type>/ceph.keyring) ne doit être mis à jour QUE
        là où le répertoire /var/lib/ceph/<type>/ EXISTE — il est absent
        des nœuds (voire de tout le cluster) quand le service n'y est
        pas déployé (ex. rbd/rbd-mirror/rgw sur un cluster sans ces
        services), et « ceph auth get > …/ceph.keyring » échoue alors
        en « No such file or directory ». La rotation de la clé DANS
        l'auth DB, elle, a réussi : la reprise ne refera ni l'une ni
        l'autre, il faut donc SKIPPER proprement (motif client.crash)
        au lieu de laisser le run FATALer."""
        inc = self._refresh_insecure()
        clients = [e for e in inc.get("AUTH_INSECURE_CLIENT_KEY_TYPE", [])
                   if e and e != "client.admin"]
        if not clients:
            self.log.info("Aucune clé client restante — tout est propre ✔")
            return
        for ent in clients:
            if ent in self.skip_clients:
                self.log.warning(
                    f"  {ent} : rotation DIFFÉRÉE (--skip-client) — la clé "
                    f"reste en « aes » pour le moment. Migrez ses "
                    f"consommateurs (keyrings prêtes à distribuer, clients "
                    f"noyau ≥ 7.0), puis relancez --rotate-keys SANS "
                    f"--skip-client : la reprise ne traitera que le reste.")
                continue
            cid = ent.split(".", 1)[1] if "." in ent else ent
            bootstrap = cid.startswith("bootstrap-")
            crash = ent == "client.crash"
            exec_node = self.nodes[0]
            self._mut(f"ceph auth rotate --key-type=aes256k {ent} "
                      f"> /tmp/pru-rot.keyring",
                      node=exec_node, desc=f"rotation de la clé {ent}")
            if not self.dry:
                content = self.client._ssh(exec_node,
                                            "cat /tmp/pru-rot.keyring")
                self._backup_keyring(bdir, f"{ent}.keyring", content)
                self.client._ssh(exec_node, "rm -f /tmp/pru-rot.keyring")
            if self.dry:
                self._sim_rotated.append(ent)
            self.counts["keys_rotated"] += 1
            self._est(EST_KEY_ENTITY_S)
            if bootstrap:
                btype = cid[len("bootstrap-"):]
                bdir_path = f"/var/lib/ceph/{btype}"
                for node in self.nodes:
                    # le répertoire du service n'existe pas partout :
                    # ne mettre à jour le keyring QUE là où il est
                    # déployé (vécu 12:52 : FATAL « No such file or
                    # directory » sur bootstrap-rbd, service absent).
                    try:
                        out = self.client._ssh(
                            node, f"test -d {bdir_path} && echo yes "
                                  f"|| echo no")
                        has_dir = out.strip().endswith("yes")
                    except Exception:
                        has_dir = False
                    if has_dir:
                        self._mut(f"ceph auth get {ent} > {bdir_path}/"
                                  f"ceph.keyring && chmod 600 "
                                  f"{bdir_path}/ceph.keyring",
                                  node=node,
                                  desc=f"mise à jour du keyring "
                                       f"bootstrap-{btype} de {node}")
                    else:
                        self.log.info(f"  {ent} : {bdir_path} absent de "
                                      f"{node} — service non déployé, "
                                      f"rien à y distribuer.")
            elif crash:
                # client.crash n'est PAS un client métier : c'est la clé du
                # daemon ceph-crash des nœuds (keyring
                # /etc/ceph/ceph.client.crash.keyring). Le keyring est
                # re-distribué UNIQUEMENT là où il existe déjà (aucune
                # création), puis le service est redémarré s'il tourne.
                cpath = "/etc/ceph/ceph.client.crash.keyring"
                for node in self.nodes:
                    try:
                        out = self.client._ssh(
                            node, f"test -f {cpath} && echo yes || echo no")
                        has_crash = out.strip().endswith("yes")
                    except Exception:
                        has_crash = False
                    if has_crash:
                        self._mut(f"ceph auth get {ent} > {cpath} && "
                                  f"chmod 600 {cpath}",
                                  node=node,
                                  desc=f"mise à jour du keyring crash "
                                       f"de {node}")
                        self._mut(f"systemctl try-restart ceph-crash.service "
                                  f"2>/dev/null || true",
                                  node=node,
                                  desc=f"redémarrage du daemon ceph-crash "
                                       f"de {node} (s'il tourne)")
                    else:
                        self.log.info(f"  {ent} : aucun keyring crash sur "
                                      f"{node} — rien à y distribuer.")
            else:
                self.log.warning(f"  {ent} : clé client métier — la nouvelle "
                                 f"keyring est archivée localement "
                                 f"(backup) : DISTRIBUEZ-LA manuellement à "
                                 f"tous ses consommateurs (VMs, hyperviseurs "
                                 f"externes, scripts…).")
        # si des clients métier restent non migrés (consommateurs externes),
        # l'étape 12 refusera le retrait de « aes » avec la marche à suivre.

    def _check_cleared(self, code: str, err: str) -> None:
        """Vérifie qu'un check AUTH_INSECURE_* a disparu après l'étape.

        Le health check est recalculé ASYNCHRONEMENT par les mons :
        une lecture immédiate peut relire l'état d'AVANT la dernière
        rotation/étape (vécu 11:02 : FATAL « mds.v-testprox03-C » 7 s
        après SON restart — la DERNIÈRE des 31 rotations — alors que
        le check avait disparu à la lecture suivante, une seconde
        plus tard ; même classe de course que min_mon_release et
        l'élection mgr, déjà pollées ailleurs). On POLL donc
        jusqu'à ROTATE_CHECK_TIMEOUT_S avant de déclarer FATAL — le
        message d'échec reste inchangé : run relançable, la reprise
        sautera ce qui est déjà traité."""
        t0 = time.time()
        while True:
            inc = self._refresh_insecure()
            if code not in inc:
                break
            if time.time() - t0 > ROTATE_CHECK_TIMEOUT_S:
                ents = inc.get(code) or []
                raise RuntimeError(
                    f"{code} TOUJOURS PRÉSENT après l'étape ({err})"
                    + (f" — entités : {', '.join(ents)}" if ents else ""))
            self.log.warning(
                f"{code} encore présent"
                + (f" ({', '.join(inc.get(code) or [])})"
                   if inc.get(code) else "")
                + " — le health check des mons se recalcule toutes les "
                f"quelques secondes, attente (recheck toutes les "
                f"{CEPH_POLL_S} s, max {int(ROTATE_CHECK_TIMEOUT_S)} s)…")
            time.sleep(CEPH_POLL_S)
        self.log.info(f"{code} : disparu ✔")

    def rotate_keys_run(self) -> None:
        st = self.client.ceph_status() or {}
        fsid = str(st.get("fsid", "fsid-inconnu"))
        bdir = KEY_BACKUP_DIR or os.path.join(
            ".", f"ceph-keys-backup-{fsid[:8]}-"
                 f"{datetime.now():%Y%m%d-%H%M%S}")
        if self.dry:
            self._sim(f"Répertoire de sauvegarde des keyrings : {bdir} "
                      f"(chmod 700, fichiers 0600)")
        else:
            os.makedirs(bdir, exist_ok=True)
            os.chmod(bdir, 0o700)
            self.log.info(f"Répertoire de sauvegarde des keyrings : {bdir}")
        self._sim_rotated = []
        self._sim_cleared_codes = []
        self._rotate_keys_run(bdir)

    # ---------------- Bilan final ----------------
    def final_report(self) -> None:
        banner(self.log, "BILAN — Ceph rolling update", ColorFormatter.MAGENTA)
        if self.aborted:
            self.log.critical(
                f"⚠ RUN INTERROMPU (les compteurs ci-dessous ne sont "
                f"PAS ceux d'un run complet) : {self.aborted}")
            self.log.critical(
                "  Flags de maintenance retirés par le bloc finally — "
                "le run est RELANÇABLE (reprise là où il s'est arrêté).")
        st = self.client.ceph_status()
        if st is None:
            self.log.error("Ceph injoignable pour le bilan final.")
            return
        raw = (st.get("health") or {}).get("status", "?")
        eff, ignored = self.client.ceph_effective_health(st)
        self.log.info(f"Santé Ceph : brute {raw}, effective {eff}"
                      + (f" ({len(ignored)} check(s) AUTH_INSECURE "
                         f"toléré(s))" if ignored else ""))
        if ignored and self.action != "rotate-keys":
            self.log.info(
                "Rappel CVE-2025-30156 : ce cluster porte encore des clés "
                "CephX « aes » (checks AUTH_INSECURE_* tolérés) — une fois "
                "la version majeure en place, remédiez avec "
                "« --execute --rotate-keys » (nécessite ≥ 19.2.6-pve3 en "
                "squid, ≥ 20.2.4-pve3 en tentacle sur les MONs ; vérifiez "
                "AUSSI les nœuds sans daemon (clients libs)).")
        if not self.dry:
            inc = self.client.insecure_entities()
            if inc:
                for code, ents in sorted(inc.items()):
                    self.log.warning(f"  check résiduel : {code} "
                                      f"({', '.join(ents) if ents else 'config mon'})")
            elif self.action == "rotate-keys":
                self.log.info("Plus AUCUN check AUTH_INSECURE_* — "
                              "remédiation complète ✔ (retirez "
                              "PVE_CEPH_ALLOW_AUTH_INSECURE=1 du env)")
        else:
            inc = self._refresh_insecure() if self.action == "rotate-keys" else {}
            if self.action == "rotate-keys" and not inc:
                self._sim("Bilan attendu : plus AUCUN check AUTH_INSECURE_*")
        if self._nonsharded:
            shown = ", ".join(self._nonsharded[:10]) + (
                "…" if len(self._nonsharded) > 10 else "")
            self.log.warning(
                f"Vérité terrain (Phase E) : {len(self._nonsharded)} "
                f"OSD(s) NON shardée(s) : {shown}. Piège META du wiki : "
                f"surveillez « ceph osd df » (colonne META) dans les jours "
                f"qui suivent la montée ; contournement : « ceph daemon "
                f"osd.N compact » un par un (I/O intensif, heures creuses).")
        elif self._shard_probed:
            self.log.info(
                f"Sharding RocksDB : {self._shard_probed} OSD(s) "
                f"testée(s) pendant la Phase E — toutes shardées ✔ "
                f"(piège META du wiki non applicable).")
        if self._osd_target_used:
            self.log.info(
                "Phase E (mode par défaut) : sharding RocksDB NON testé "
                "(restart ceph-osd.target par nœud — le test exige "
                "l'arrêt individuel de chaque OSD) ; les dates de "
                "création des répertoires ne sont qu'une heuristique "
                "— vérité terrain : relancez un run avec "
                "--force-detection-sharding (les OSDs déjà à jour "
                "seront re-testées une par une), ou surveillez "
                "« ceph osd df » (colonne META) après la montée.")
        if self._osd_skipped:
            self.log.info(
                f"Reprise : {self._osd_skipped} OSD(s) déjà en "
                f"{self.major_release} — aucune redémarrée inutilement "
                f"(version courante vérifiée via « ceph osd "
                f"metadata »).")
        versions = self.client.ceph_versions()
        shown = False
        for t in ("mon", "mgr", "osd", "mds"):
            for ver, nb in sorted((versions.get(t) or {}).items()):
                if not shown:
                    self.log.info("Versions des daemons après run :")
                    shown = True
                self.log.info(f"  {t}: {nb}× {ver}")
        self.log.info(f"Compteurs : {self.counts['restarts']} redémarrage(s) "
                      f"de daemon(s), {self.counts['keys_rotated']} clé(s) "
                      f"rotationnée(s), {self.counts['pkg_nodes']} nœud(s) "
                      f"upgradé(s), {self.counts['gates']} gate(s) de santé")
        if self.dry:
            self.log.info(f"Durée estimée : ~{_est_hms(self.est_s)} "
                          f"(±50% : hypothèses ajustables via PVE_EST_*)")
        else:
            self.log.info(f"Durée réelle : "
                          f"{_est_hms(time.time() - self.t_start)}")
        if self.action == "rotate-keys":
            self.log.info("Rappel : les keyrings régénérées (mon., "
                          "client.admin, clients) sont archivées localement "
                          "— conservez-les hors du cluster (sécurité de "
                          "secours).")

    # ---------------- Orchestration ----------------
    def run(self) -> None:
        try:
            if not self.preflight():
                return
            scan = None
            ok = False
            if self.action == "minor":
                # Scan des paquets en attente AVANT toute maintenance :
                # si aucun nœud n'a rien à faire, on ne pose même pas
                # les flags et on ne redémarre aucun daemon.
                scan = self.minor_scan()
                if not any(scan.values()):
                    self.log.info(
                        f"Aucun paquet Ceph en attente sur aucun des "
                        f"{len(scan)} nœud(s) — le cluster est déjà à "
                        f"jour : rien à faire (aucun redémarrage de "
                        f"daemon, aucun flag de maintenance posé).")
                    return
            self._flags_on()
            try:
                if self.action == "minor":
                    banner(self.log, "ACTION — Mise à jour MINEURE des "
                                     "paquets Ceph (sans reboot)",
                           ColorFormatter.GREEN)
                    self.minor_run(scan)
                elif self.action == "major":
                    banner(self.log, f"ACTION — Mise à jour MAJEURE vers "
                                     f"Ceph {self.major_release}",
                           ColorFormatter.GREEN)
                    self.major_run()
                elif self.action == "rotate-keys":
                    banner(self.log, "ACTION — Remédiation CVE-2025-30156 : "
                                     "rotation des clés CephX vers aes256k",
                           ColorFormatter.GREEN)
                    self.rotate_keys_run()
                if not self.dry:
                    self.log.info("✔ Action terminée sans erreur.")
                ok = True
            finally:
                self._flags_off()
                self._state_clear()
                if ok and not self.dry:
                    # Convergence finale APRÈS retrait des flags :
                    # le backfill gelé reprend, « clean » devient
                    # exigible (avertissement sans abort si lent).
                    self._final_converge()
        except Exception as e:
            # L'erreur est loggée ICI (donc dans le fichier de log) AVANT
            # le bilan — plus jamais d'échec silencieux en exit(2).
            self.aborted = str(e)
            self.log.critical(f"RUN INTERROMPU : {e}")
            raise
        finally:
            self.final_report()


# ---------------------------------------------------------------------------
# POINT D'ENTRÉE
# ---------------------------------------------------------------------------
def load_env_file(path: str, logger: logging.Logger):
    """Charge un fichier KEY=VALUE (ex. /etc/proxmox-updater/proxmox.env).
    Les variables déjà présentes dans l'environnement ne sont PAS
    écrasées (précédence : shell env > fichier env > défauts)."""
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
        description="Mise à jour glissante du Ceph d'un cluster Proxmox VE "
                    "hyperconvergé (mineur / majeur / rotation des clés "
                    "CVE-2025-30156).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true",
                      help="Simulation complète, aucune écriture sur le "
                           "cluster.")
    mode.add_argument("--execute", action="store_true",
                      help="Exécution réelle.")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--major", metavar="RELEASE",
                        help="Changement de version MAJEURE (ex. --major "
                             "tentacle) : bascule du dépôt + paquets sur tous "
                             "les nœuds + redémarrages par type de daemon "
                             "(mons → mgrs → OSDs → MDS → require-osd-"
                             "release). Montée d'EXACTEMENT une release "
                             "(descente et saut refusés en préflight).")
    action.add_argument("--rotate-keys", action="store_true",
                        help="Remédiation CVE-2025-30156 : rotation de "
                             "toutes les clés CephX « aes » vers "
                             "« aes256k » (procédure officielle Ceph, "
                             "reprise possible).")
    parser.add_argument("--skip-client", action="append", default=[],
                        metavar="ENTITY",
                        help="rotate-keys : DIFFÉRER la rotation de cette "
                             "clé client métier (répétable, ex. "
                             "--skip-client client.rhospdc). Utile pour "
                             "migrer en 2 phases quand des consommateurs "
                             "externes ne savent pas encore faire aes256k "
                             "(ex. clients noyau < 7.0). Le retrait final "
                             "de « aes » est alors différé proprement "
                             "tant qu'une clé différée reste en « aes ».")
    parser.add_argument("--node",
                        help="Ne traiter que ce nœud (mode mineur "
                             "uniquement).")
    parser.add_argument("--force-detection-sharding", action="store_true",
                        help="Phase E de --major (OPT-IN) : tester le "
                             "sharding RocksDB RÉEL de CHAQUE OSD en la "
                             "redémarrant UNE PAR UNE (arrêt → "
                             "ceph-bluestore-tool show-sharding → "
                             "démarrage), SANS exemption de version — "
                             "les OSDs déjà sur la release cible sont "
                             "elles aussi testées. Par DÉFAUT (sans "
                             "cette option) le sharding n'est PAS "
                             "testé : la version courante de chaque "
                             "OSD (« ceph osd metadata ») est lue, un "
                             "nœud dont toutes les OSDs sont déjà sur "
                             "la release cible est sauté, les autres "
                             "sont redémarrées d'un coup via « systemctl "
                             "restart ceph-osd.target » (une gate par "
                             "nœud).")
    parser.add_argument("--env-file",
                        default="/etc/proxmox-updater/proxmox.env",
                        help="Fichier d'environnement contenant les "
                             "secrets (par défaut "
                             "/etc/proxmox-updater/proxmox.env).")
    parser.add_argument("--log-file", default=None,
                        help="Écrire les logs en parallèle dans ce fichier "
                             "(sans ANSI, horodatage complet).")
    parser.add_argument("--no-color", action="store_true",
                        help="Forcer la désactivation des couleurs.")
    parser.add_argument("--force-color", action="store_true",
                        help="Forcer l'activation des couleurs.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    if args.force_detection_sharding and not args.major:
        parser.error("--force-detection-sharding n'a de sens qu'avec "
                     "--major RELEASE")

    logger = setup_logger(args.verbose, args.log_file,
                          args.no_color, args.force_color)
    try:
        load_env_file(args.env_file, logger)
    except FileNotFoundError:
        logger.error(f"Fichier d'environnement '{args.env_file}' "
                     f"introuvable — arrêt. Indiquez le bon chemin via "
                     f"--env-file.")
        sys.exit(1)
    # Log fichier via PVE_LOG_FILE (comme le script PVE)
    env_log_file = _env("PVE_LOG_FILE", "").strip()
    if env_log_file and not args.log_file:
        try:
            # Stream ligne-buffered PARTAGÉ avec le tee stderr :
            # un seul descripteur → ordre d'écriture préservé.
            stream = open(env_log_file, "a", encoding="utf-8", buffering=1)
            fh = logging.StreamHandler(stream)
            fh.setFormatter(PlainFileFormatter())
            logger.addHandler(fh)
            _tee_stderr_to(stream)
            logger.info(f"Logs également écrits dans : {env_log_file} "
                        f"(stderr y est aussi capturé)")
        except OSError as e:
            logger.warning(f"Fichier de log '{env_log_file}' inutilisable "
                           f"({e}) — poursuite sans log fichier.")
    # Relecture des constantes maintenant que l'env est chargé
    global API_HOST, API_HOSTS, API_USER, API_TOKEN_NAME, API_TOKEN_VALUE
    global VERIFY_SSL, SSH_USER, SSH_PRIVATE_KEY, SSH_PORT, SSH_KEY_PASSPHRASE
    global SSH_RETRIES
    global CEPH_STABLE_TIMEOUT, CEPH_POLL_S
    global FINAL_CONVERGE_TIMEOUT
    global CEPH_UTIL_MAX_PCT, STATE_FILE, KEY_BACKUP_DIR
    global EST_APT_MIN, EST_UPGRADE_MIN, EST_RESTART_MON_S, EST_RESTART_MGR_S
    global EST_RESTART_OSD_S, EST_RESTART_MDS_S, EST_KEY_ENTITY_S
    global EST_STABILIZE_S
    API_HOST = _env("PVE_API_HOST", API_HOST)
    API_HOSTS = [h.strip() for h in _env("PVE_API_HOSTS", "").split(",")
                 if h.strip()]
    API_USER = _env("PVE_API_USER", API_USER)
    API_TOKEN_NAME = _env("PVE_API_TOKEN_NAME", API_TOKEN_NAME)
    API_TOKEN_VALUE = _env("PVE_API_TOKEN_VALUE", API_TOKEN_VALUE)
    VERIFY_SSL = _env("PVE_VERIFY_SSL", str(VERIFY_SSL)).lower() in (
        "1", "true", "yes")
    SSH_USER = _env("PVE_SSH_USER", SSH_USER)
    SSH_PRIVATE_KEY = _env("PVE_SSH_KEY", SSH_PRIVATE_KEY)
    SSH_PORT = int(_env("PVE_SSH_PORT", str(SSH_PORT)))
    SSH_KEY_PASSPHRASE = _env("PVE_SSH_PASSPHRASE", "")
    SSH_RETRIES = int(_env("PVE_SSH_RETRIES", str(SSH_RETRIES)))
    CEPH_STABLE_TIMEOUT = int(_env("PVE_CEPH_STABLE_TIMEOUT",
                                   str(CEPH_STABLE_TIMEOUT)))
    FINAL_CONVERGE_TIMEOUT = int(_env("PVE_CEPH_FINAL_CONVERGE_TIMEOUT",
                                       str(FINAL_CONVERGE_TIMEOUT)))
    CEPH_POLL_S = int(_env("PVE_CEPH_POLL_S", str(CEPH_POLL_S)))
    CEPH_UTIL_MAX_PCT = float(_env("PVE_CEPH_UTIL_MAX_PCT",
                                    str(CEPH_UTIL_MAX_PCT)))
    STATE_FILE = _env("PVE_CEPH_STATE_FILE", STATE_FILE)
    KEY_BACKUP_DIR = _env("PVE_CEPH_KEY_BACKUP_DIR", KEY_BACKUP_DIR)
    EST_APT_MIN = float(_env("PVE_EST_APT_MIN", str(EST_APT_MIN)))
    EST_UPGRADE_MIN = float(_env("PVE_EST_UPGRADE_MIN", str(EST_UPGRADE_MIN)))
    EST_RESTART_MON_S = float(_env("PVE_EST_RESTART_MON_S",
                                   str(EST_RESTART_MON_S)))
    EST_RESTART_MGR_S = float(_env("PVE_EST_RESTART_MGR_S",
                                   str(EST_RESTART_MGR_S)))
    EST_RESTART_OSD_S = float(_env("PVE_EST_RESTART_OSD_S",
                                   str(EST_RESTART_OSD_S)))
    EST_RESTART_MDS_S = float(_env("PVE_EST_RESTART_MDS_S",
                                   str(EST_RESTART_MDS_S)))
    EST_KEY_ENTITY_S = float(_env("PVE_EST_KEY_ENTITY_S",
                                  str(EST_KEY_ENTITY_S)))
    EST_STABILIZE_S = float(_env("PVE_EST_STABILIZE_S",
                                 str(EST_STABILIZE_S)))
    logger.info(f"Passphrase SSH        : "
                f"{'définie via PVE_SSH_PASSPHRASE' if SSH_KEY_PASSPHRASE else 'absente (aucune invite si la clé est nue)'}")
    if args.major:
        action_name = "major"
    elif args.rotate_keys:
        action_name = "rotate-keys"
    else:
        action_name = "minor"
    dry = args.dry_run
    banner(logger, f"PROXMOX CEPH ROLLING UPDATE — mode "
                   f"{'DRY-RUN (simulation)' if dry else 'EXÉCUTION RÉELLE'}"
                   f" — action : {action_name}",
           ColorFormatter.GREEN if dry else "\033[91;1m")
    client = ProxmoxClient(logger)
    updater = CephUpdater(logger, dry, client, {
        "action": action_name,
        "major": args.major,
        "node": args.node,
        "skip_clients": args.skip_client,
        "force_sharding_detection": args.force_detection_sharding,
    })
    try:
        updater.run()
        sys.exit(0)
    except KeyboardInterrupt:
        logger.critical("Interruption utilisateur (Ctrl-C) — flags de "
                        "maintenance retirés par le bloc finally. Les "
                        "entités déjà migrées seront détectées et sautées "
                        "au prochain run (reprise).")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Run échoué : {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()
