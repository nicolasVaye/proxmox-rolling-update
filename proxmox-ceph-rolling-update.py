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
     vérification min_mon_release → mgrs → OSDs nœud par nœud → MDS
     (procédure max_mds) → vérification que TOUTES les OSDs tournent
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
(seulement ceux qu'il pose lui-même, les vôtres sont conservés), et
les RETIRE dans le bloc finally — même en cas d'abort. Un fichier
d'état JSON trace les flags et la progression (reprise possible pour
--rotate-keys : les entités déjà migrées sont re-détectées et sautées).

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
import socket
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# CONFIGURATION — à adapter à votre plateforme
# ---------------------------------------------------------------------------
# Les valeurs sensibles sont surchargées par (dans l'ordre de priorité) :
#   1) la variable d'environnement correspondante,
#   2) le fichier d'environnement passé via --env-file, chargé au démarrage,
#   3) les valeurs par défaut ci-dessous.


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


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
# Timeout global d'attente de stabilisation (santé OK + PGs active+clean)
# après chaque redémarrage de daemon / nœud.
CEPH_STABLE_TIMEOUT = int(_env("PVE_CEPH_STABLE_TIMEOUT", "1800"))
# Nombre MAXIMAL de PGs tolérées hors « active+clean » pour passer une gate
# (0 = exigence stricte : toutes les PGs doivent être propres).
CEPH_MAX_DEGRADED_PGS = int(_env("PVE_CEPH_MAX_DEGRADED_PGS", "0"))
# Période de poll des gates (s).
CEPH_POLL_S = int(_env("PVE_CEPH_POLL_S", "15"))
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

    def ceph_pkg_pending(self, node: str) -> List[Tuple[str, str]]:
        """Paquets Ceph en attente de mise à jour sur un nœud (simulation
        apt -s, lecture pure) : [(nom, version_cible)]."""
        try:
            out = self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                                  "apt-get -s full-upgrade -q")
        except Exception:
            return []
        pkgs: List[Tuple[str, str]] = []
        for m in re.finditer(r"^Inst (\S+) \((\S+)", out, re.M):
            name = m.group(1)
            if re.search(r"^(ceph|rados|librbd|libcephfs|librados|"
                         r"python3-rbd|python3-cephfs|rbd-nbd)", name):
                pkgs.append((name, m.group(2)))
        return pkgs

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

    def ceph_effective_health(self, st: Optional[Dict]) -> Tuple[str, Tuple[str, ...]]:
        """(santé effective, codes ignorés) : recompte la santé après
        filtrage des checks AUTH_INSECURE_* si (et seulement si)
        PVE_CEPH_ALLOW_AUTH_INSECURE=1."""
        if st is None:
            return "?", ()
        h = (st.get("health") or {})
        health = h.get("status", "?")
        checks = h.get("checks") or {}
        ignored = tuple(sorted(c for c in checks
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
        self.log.warning(
            f"[Ceph] PVE_CEPH_ALLOW_AUTH_INSECURE=1 : {len(ignored)} "
            f"check(s) de sécurité cephx toléré(s) ({', '.join(ignored)}) — "
            f"avis cryptographique (CVE-2025-30156, clés « aes »), sans "
            f"impact IO/daemons. Remédiation définitive : --rotate-keys "
            f"(migration des clés vers « aes256k »).")

    def ceph_diagnose(self, st: Optional[Dict]) -> None:
        if st is None:
            return
        h = (st.get("health") or {})
        if h.get("status", "?") == "HEALTH_OK":
            return
        status = h.get("status", "?")
        self.log.warning(f"[Ceph] Diagnostic ({status}) :")
        checks = h.get("checks") or {}
        if not checks:
            self.log.warning("    aucun détail dans le status — consultez "
                             "« ceph -s » / « ceph health detail » sur un nœud.")
            return
        for code, c in sorted(checks.items()):
            sev = c.get("severity", "?")
            msg = ((c.get("summary") or {}).get("message") or "").strip()
            self.log.warning(f"    {code} [{sev}] : {msg}")
            for d in (c.get("detail") or [])[:6]:
                dm = ((d.get("message") or "").strip().replace("\n", " "))
                if dm:
                    self.log.warning(f"        {dm[:200]}")

    # ---------- Commandes Ceph via SSH ----------
    def ceph_json(self, cmd: str, node: Optional[str] = None) -> Dict:
        """Exécute une commande ceph --format json (lecture pure) et
        décode le JSON. `node` facultatif : sinon premier nœud joignable."""
        cmdj = cmd if "--format" in cmd else f"{cmd} --format json"
        if node:
            out = self._ssh(node, cmdj)
        else:
            _, out = self.ssh_any(cmdj)
        try:
            return json.loads(out)
        except ValueError as e:
            raise RuntimeError(f"Sortie non-JSON de « {cmd} » : "
                               f"{out.strip()[:200]} ({e})")

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

    def ceph_maintenance_on(self) -> Dict[str, bool]:
        """Pose les flags de maintenance (globaux au cluster). Retourne
        UNIQUEMENT les flags posés par CE RUN — les flags déjà posés par
        l'administrateur ne sont ni touchés ni retirés."""
        cur = self.ceph_flags_current()
        if cur is None:
            raise RuntimeError("Impossible de lire les flags Ceph — "
                               "refus de continuer sans visibilité.")
        changed: Dict[str, bool] = {}
        for f in CEPH_MAINT_FLAGS:
            if f in cur:
                self.log.info(f"[Ceph] flag {f} déjà posé (admin) — conservé.")
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
        Lecture pure."""
        dump = self.ceph_json("ceph osd dump")
        res: Dict[int, Dict] = {}
        for o in dump.get("osds", []):
            raw = o.get("state", "")
            states = (raw if isinstance(raw, list)
                      else str(raw).replace(",", " ").split())
            res[int(o.get("id", -1))] = {
                "up": "up" in states,
                "in": "exists" in states and "out" not in states,
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

    # ---------- Gates de stabilisation ----------
    def wait_ceph_stable(self, action: str,
                         node: Optional[str] = None,
                         timeout: Optional[int] = None,
                         require_clean: bool = True) -> bool:
        """LA gate centrale : attend que le cluster soit de nouveau
        opérationnel après un redémarrage de daemon :
          1. santé effective HEALTH_OK (AUTH_INSECURE_* tolérés si
             PVE_CEPH_ALLOW_AUTH_INSECURE=1 — toute autre dégradation
             compte) ;
          2. quorum mon COMPLET ;
          3. PGs : nombre de PGs non « active+clean » ≤
             PVE_CEPH_MAX_DEGRADED_PGS (défaut 0) ;
          4. si `node` est fourni : tous les OSDs de ce nœud sont 'up'.
        `require_clean=False` : phase volontairement dégradée (OSD
        arrêté pour rotation de clé) — seul le retour 'up' du nœud est
        attendu. Retourne False si timeout atteint."""
        t0 = time.time()
        timeout = timeout or CEPH_STABLE_TIMEOUT
        osd_ids: List[int] = []
        if node:
            try:
                tree = self.osds_of_node_tree()
                osd_ids = tree.get(node, [])
            except Exception:
                osd_ids = []
        diag_done = False
        last_pgs = ""
        while True:
            st = self.ceph_status()
            if st is None:
                raise RuntimeError("Ceph devenu injoignable — abort.")
            health, ignored = self.ceph_effective_health(st)
            if ignored:
                self.ceph_log_auth_insecure(ignored)
            quorum_ok = self.mon_quorum_complete(st)
            pg_bad = -1
            pg_desc = ""
            pgmap = st.get("pgmap") or {}
            states = pgmap.get("pgs_by_state") or []
            if require_clean:
                total = sum(int(s.get("count", 0)) for s in states) or 1
                bad = total - sum(int(s.get("count", 0)) for s in states
                                  if s.get("state_name") == "active+clean")
                pg_bad = bad
                bad_desc = ", ".join(f"{s.get('count')}×{s.get('state_name')}"
                                     for s in states
                                     if s.get("state_name") != "active+clean")
                pg_desc = f"{bad} PG(s) non active+clean"
                last_pgs = bad_desc
            osd_ok = True
            if node and osd_ids:
                try:
                    ups = self.osd_up_status()
                    osd_ok = all(ups.get(i, {}).get("up") for i in osd_ids)
                except Exception:
                    osd_ok = False
            if (health == "HEALTH_OK" and quorum_ok
                    and (pg_bad == 0 if require_clean else True)
                    and osd_ok):
                self.log.info(f"Ceph stable après « {action} » "
                              f"(HEALTH_OK, quorum complet, PGs actives "
                              f"+ propres ✔"
                              + (f", OSDs de {node} 'up' ✔" if node and osd_ids
                                 else "") + ")")
                return True
            if time.time() - t0 > timeout:
                self.ceph_diagnose(st)
                if last_pgs:
                    self.log.error(f"PGs non nettoyées : {last_pgs}")
                self.log.error(f"Ceph non stabilisé après {timeout}s "
                               f"(action « {action} »).")
                return False
            if not diag_done and health not in ("HEALTH_OK",):
                self.ceph_diagnose(st)
                diag_done = True
            self.log.warning(f"Ceph en convergence après « {action} » "
                             f"(santé {health}, quorum "
                             f"{'OK' if quorum_ok else 'INCOMPLET'}"
                             + (f", {pg_desc}" if require_clean else "")
                             + (f", OSDs {node} en attente" if node and osd_ids
                                and not osd_ok else "")
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
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
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
              require_clean: bool = True) -> None:
        """Gate de stabilisation entre deux unités redémarrées."""
        self.counts["gates"] += 1
        if self.dry:
            self.log.info(f"[SIMULATION] Gate santé après « {action} » : "
                          f"HEALTH_OK + quorum complet + PGs active+clean "
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
                      if not c.startswith("AUTH_INSECURE_")}
            if non_ai:
                self.client.ceph_diagnose(st)
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
            self.client.ceph_diagnose(st)
            raise RuntimeError(
                f"Ceph est en {health} — action {self.action} REFUSÉE : "
                f"un cluster dégradé ne se met pas à jour.")
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
            # Piège connu du wiki (OSDs créées sous Octopus ou avant) :
            self.log.warning(
                "Piège connu du wiki : des OSDs créées sous Octopus (v15) "
                "ou avant peuvent voir leur usage META (RocksDB non "
                "shardé) fortement augmenter APRÈS la montée — vérifiez "
                "« ceph osd df » (colonne META) après le run ; "
                "contournement : « ceph daemon osd.N compact » un par un.")
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
        if self.dry:
            flags = [f for f in CEPH_MAINT_FLAGS
                     if f not in (self.client.ceph_flags_current() or {})]
            self.flags_we_set = {f: True for f in flags}
            self._sim(f"Pose des flags de maintenance : "
                      f"{', '.join(sorted(flags))} (les flags déjà posés "
                      f"par l'admin sont conservés)")
            return
        self.flags_we_set = self.client.ceph_maintenance_on()
        self._state_write("démarrage")

    def _flags_off(self) -> None:
        if not self.flags_we_set:
            return
        if self.dry:
            self._sim(f"Retrait des flags posés par le run : "
                      f"{', '.join(sorted(self.flags_we_set))} — le cluster "
                      f"reprend son fonctionnement nominal")
            return
        self.client.ceph_maintenance_off(self.flags_we_set)
        self._state_clear()

    # ---------------- Action 1 : mise à jour MINEURE ----------------
    def minor_scan(self) -> Dict[str, List]:
        """Rafraîchit les listes apt de chaque nœud et collecte les
        paquets Ceph en attente (lecture seule — AVANT toute pose de
        flag). Retourne {nœud: [(paquet, version), …]}."""
        pending_by_node: Dict[str, List] = {}
        for node in self.nodes:
            if self.dry:
                self._sim(f"{node} : apt-get update -q")
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
            self._mut(f"sed -i 's/ceph-{branch}/ceph-{rel}/g' "
                      f"/etc/apt/sources.list.d/ceph.list "
                      f"/etc/apt/sources.list.d/ceph.sources 2>/dev/null",
                      node=node, desc=f"bascule du dépôt ceph-{branch} → "
                                      f"ceph-{rel}")
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
                self._sim(f"{node} : apt-get update -q")
                self._sim(f"{node} : apt-get full-upgrade -y (binaires {rel} "
                          f"installés, les anciens daemons tournent encore)")
            else:
                self.client.apt_update(node)
                self.log.info(f"{node} : apt full-upgrade (binaires {rel}) — "
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
                out = self.client.ceph_run("ceph mon dump | grep "
                                           "min_mon_release")
                got = out.strip()
                if f"min_mon_release {num} " not in got + " ":
                    raise RuntimeError(
                        f"min_mon_release attendu {num} ({rel}) non atteint "
                        f"({got}) — un mon n'a pas redémarré sur les nouveaux "
                        f"binaires. « ceph mon dump » pour diagnostiquer.")
                self.log.info(f"min_mon_release OK : {got} ✔")
        # ---- Phase D : mgrs ----
        banner(self.log, "PHASE D — Redémarrage des MGRS (tous les nœuds)")
        restarted_mgr = False
        for node in self.nodes:
            for mid in self.client.node_daemons(node)["mgr"]:
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
                dump = self.client.ceph_json("ceph mgr dump")
                if not dump.get("active_name"):
                    raise RuntimeError("Aucun mgr actif après les "
                                        "redémarrages — « ceph mgr dump » "
                                        "pour diagnostiquer.")
                self.log.info(f"mgr actif : {dump['active_name']} ✔")
        # ---- Phase E : OSDs nœud par nœud ----
        banner(self.log, "PHASE E — Redémarrage des OSDs nœud par nœud "
                         "(jamais deux nœuds à la fois)")
        for node in self.nodes:
            osds = self.client.node_daemons(node)["osd"]
            if not osds:
                continue
            self._mut("systemctl restart ceph-osd.target", node=node,
                      desc=f"redémarrage des {len(osds)} OSD(s) de {node}")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_OSD_S)
            self._gate(f"restart des OSDs de {node}", node=node)
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

    def _major_mds(self) -> None:
        """Procédure MDS du wiki Proxmox : standby_replay off, max_mds→1,
        attente des ranks, arrêt des standbys, restart du dernier actif,
        redémarrage des standbys, restauration des réglages."""
        rel = self.major_release
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
            if not self.dry:
                out = self.client.ceph_run(f"ceph fs get {fs}")
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
        # 2) attente de la réduction des ranks (lecture pure / sim)
        if self.dry:
            self._sim("attente : les ranks non nuls se désactivent "
                      "(« ceph status » → active mds == nombre de FS)")
        else:
            t0 = time.time()
            while True:
                st = self.client.ceph_status() or {}
                mdsmap = st.get("mdsmap") or {}
                active = mdsmap.get("up") or []
                if len(active) <= len(fs_list):
                    self.log.info(f"Ranks réduits : {len(active)} MDS "
                                  f"actif(s) ✔")
                    break
                if time.time() - t0 > CEPH_STABLE_TIMEOUT:
                    raise RuntimeError("Les ranks MDS ne se désactivent "
                                       "pas — « ceph status » pour "
                                       "diagnostiquer.")
                self.log.warning("Attente de la désactivation des ranks "
                                 "MDS supplémentaires…")
                time.sleep(CEPH_POLL_S)
        # 3) nœud du/des MDS actifs (rank 0)
        active_nodes: List[str] = []
        if not self.dry:
            st = self.client.ceph_status() or {}
            for u in (st.get("mdsmap") or {}).get("up") or []:
                name = str(u.get("name", "")).replace("mds.", "")
                if name and name not in active_nodes:
                    active_nodes.append(name)
        # 4) arrêt des standbys, restart de l'actif, retour des standbys
        standby_nodes = [n for n in mds_nodes if n not in active_nodes]
        for node in standby_nodes:
            self._mut("systemctl stop ceph-mds.target", node=node,
                      desc="arrêt du/de la MDS standby")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_MDS_S)
        for node in active_nodes:
            self._mut("systemctl restart ceph-mds.target", node=node,
                      desc="redémarrage du MDS actif (dernier à tourner "
                           f"sur {rel})")
            self.counts["restarts"] += 1
            self._est(EST_RESTART_MDS_S)
            self._gate(f"restart MDS actif ({node})")
        for node in standby_nodes:
            self._mut("systemctl start ceph-mds.target", node=node,
                      desc="retour du/de la MDS standby")
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
                    self.log.info(f"  {entity} : déjà en aes256k — repris ✔")
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
        inc = self._refresh_insecure()
        leftover = [e for e in inc.get("AUTH_INSECURE_CLIENT_KEY_TYPE", [])
                    if e and e != "client.admin"
                    and e not in self.skip_clients]
        leftover += inc.get("AUTH_INSECURE_SERVICE_KEY_TYPE", [])
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
                self.client.ceph_diagnose(st)
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
                  desc=f"arrêt de {entity}")
        self._mut(f"ceph osd down {oid}",
                  desc=f"{entity} marqué 'down' explicitement")
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
                  desc=f"rotation + import de la clé {entity}"
                       + (f" + label bluestore ({lv_path})"
                          if lv_path else ""))
        if self.dry:
            self._sim_rotated.append(entity)
        self._mut(f"systemctl start ceph-osd@{oid}", node=node,
                  desc=f"démarrage de {entity}")
        self.counts["restarts"] += 1
        self.counts["keys_rotated"] += 1
        self._est(EST_KEY_ENTITY_S + EST_RESTART_OSD_S / 4)
        self._gate(f"restart {entity} ({node})", node=node)

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
                self.log.debug(f"    osd.{oid} : entrées ceph-volume lvm "
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
            self.log.warning(f"  osd.{oid} : lecture ceph-volume impossible "
                             f"({' ; '.join(err)}) — device introuvable, "
                             f"label bluestore NON mis à jour : vérifiez "
                             f"manuellement si l'OSD refuse de redémarrer.")
        else:
            self.log.info(f"  osd.{oid} : OSD non géré par ceph-volume — "
                          f"pas de label bluestore à mettre à jour.")
        return None

    def _rotate_admin_key(self, bdir: str) -> None:
        """Rotation de client.admin avec clé de secours, distribution sur
        TOUS les chemins de keyring admin détectés, vérification sur
        chaque nœud, puis suppression de la clé de secours. Toutes les
        opérations /tmp sont épinglées au MÊME nœud d'exécution."""
        if not self._needs_key("client.admin"):
            self.log.info("client.admin déjà en aes256k — repris ✔")
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
        if not self.dry:
            out = self.client._ssh(exec_node,
                                   "cat /tmp/pru-admin-backup.keyring")
            self._backup_keyring(bdir, "client.admin-backup.keyring", out)
        # 2) rotation (la NOUVELLE clé vit dans l'auth DB : chaque nœud la
        #    récupère via « ceph auth get client.admin »)
        self._mut("ceph auth rotate --key-type=aes256k client.admin "
                  "> /tmp/pru-admin.keyring",
                  node=exec_node, desc="rotation de la clé client.admin")
        if not self.dry:
            out = self.client._ssh(exec_node, "cat /tmp/pru-admin.keyring")
            self._backup_keyring(bdir, "client.admin.keyring", out)
        if self.dry:
            self._sim_rotated.append("client.admin")
        # 3) import dans TOUS les keyrings admin de chaque nœud
        for node in self.nodes:
            paths = self._admin_keyring_paths(node)
            if not paths:
                self.log.warning(f"  {node} : aucun keyring client.admin "
                                 f"détecté — vérification manuelle requise.")
                continue
            for p in paths:
                self._mut(f"ceph auth get client.admin > /tmp/pru-admin."
                          f"keyring && ceph-authtool --import-keyring "
                          f"/tmp/pru-admin.keyring {p} && rm -f "
                          f"/tmp/pru-admin.keyring",
                          node=node,
                          desc=f"import de la nouvelle clé admin dans {p}")
            self._mut("ceph -s --format json >/dev/null", node=node,
                      desc=f"vérification : la CLI ceph de {node} "
                           f"fonctionne avec la nouvelle clé")
        # 4) la clé de secours n'est plus utile (elle resterait une clé
        #    « aes » qui déclencherait AUTH_INSECURE_CLIENT_KEY_TYPE)
        self._mut("ceph auth rm client.admin-backup && rm -f "
                  "/tmp/pru-admin-backup.keyring",
                  desc="suppression de la clé de secours (rotation "
                       "vérifiée sur tous les nœuds)")
        self.counts["keys_rotated"] += 1
        self._est(EST_KEY_ENTITY_S * (1 + len(self.nodes)))

    def _admin_keyring_paths(self, node: str) -> List[str]:
        """Chemins des keyrings contenant client.admin sur un nœud
        (PVE : /etc/pve/priv/ceph/<fsid>.keyring et/ou
        /etc/ceph/ceph.client.admin.keyring). Lecture pure."""
        out = self.client._ssh(
            node,
            "for f in /etc/ceph/ceph.client.admin.keyring "
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
        consommateurs)."""
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
                for node in self.nodes:
                    self._mut(f"ceph auth get {ent} > /var/lib/ceph/"
                              f"{btype}/ceph.keyring && chmod 600 "
                              f"/var/lib/ceph/{btype}/ceph.keyring",
                              node=node,
                              desc=f"mise à jour du keyring bootstrap-{btype} "
                                   f"de {node}")
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
        """Vérifie qu'un check AUTH_INSECURE_* a disparu après l'étape."""
        inc = self._refresh_insecure()
        if code in inc:
            ents = inc.get(code) or []
            raise RuntimeError(
                f"{code} TOUJOURS PRÉSENT après l'étape ({err})"
                + (f" — entités : {', '.join(ents)}" if ents else ""))
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
            finally:
                self._flags_off()
                self._state_clear()
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
    global CEPH_STABLE_TIMEOUT, CEPH_MAX_DEGRADED_PGS, CEPH_POLL_S
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
    CEPH_MAX_DEGRADED_PGS = int(_env("PVE_CEPH_MAX_DEGRADED_PGS",
                                      str(CEPH_MAX_DEGRADED_PGS)))
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