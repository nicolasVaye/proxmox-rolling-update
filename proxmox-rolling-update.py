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
nœuds du mode maintenance avant de quitter.

Usage :
    python3 proxmox_rolling_update.py --dry-run
    python3 proxmox_rolling_update.py --execute
    python3 proxmox_rolling_update.py --execute --node pve-node3   # un seul nœud
"""

import argparse
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
MIGRATE_TIMEOUT = 600           # secondes max par migration
CEPH_TIMEOUT = 900              # secondes max d'attente d'un Ceph HEALTH_OK
REBOOT_TIMEOUT = 900            # secondes max d'attente du retour d'un nœud

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
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(PlainFileFormatter())
        handlers.append(fh)
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
                                         for ri in self.ha_rules_info])
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
                          plans: Optional[List[Dict]] = None):
    """Vue arborescente unifiée du cluster : une ligne d'hyperviseur
    (RAM déclarée/consommée/libre/allouable + CPU + % + nb VMs + état)
    suivie de ses VMs en retrait (id, nom, RAM max, CPU, état, HA).
    Utilisée PARTOUT (état initial, avant/après chaque action, état
    final) pour un affichage homogène et facile à lire d'une traite.
    highlight : nœud en cours de traitement (surbrillance cyan)."""
    banner(logger, title, ColorFormatter.MAGENTA)
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
        # Libellé selon la sémantique : « RAM » = consommation réelle de
        # l'inventaire ; « RAM (pression) » = état interne MUTÉ (pire cas
        # du modèle : Σ charges des running). L'égalité avec « Σ déclarée »
        # en mode pression est STRUCTURELLE : un nœud vidé puis re-rempli
        # ne reçoit que des charges de guests, d'où RAM == Σ déclarée.
        ram_lbl = "RAM (pression)" if state.simulated else "RAM"
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
        # Affinité HA : strict=1 = CONTRAINTE DURE (aucun repli — le
        # CRM la respecterait de toute façon) ; strict=0 = PRÉFÉRENCE
        # (sémantique du CRM : repli autorisé si saturation, cf. wiki
        # Proxmox). Pas de règle = pas de contrainte.
        hard = state.ha_affinity_hard.get(vm.vmid)
        affinity = state.ha_affinity.get(vm.vmid)
        aff_no_target = False
        if hard is not None:
            allowed = [t for t in targets if t.name in hard]
            if not allowed:
                raise RuntimeError(
                    f"Impossible de placer {vm} : sa règle d'affinité "
                    f"DURE (strict=1) n'autorise que "
                    f"{', '.join(sorted(hard))} et aucun de ces nœuds "
                    f"n'est une cible disponible (online, hors "
                    f"maintenance) pour vider {source.name}.")
        elif affinity is not None:
            allowed = [t for t in targets if t.name in affinity]
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
            allowed = targets
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


def plan_off_rule_failback(state: ClusterState, logger: logging.Logger,
                           vmids: Set[int]) -> List[Dict]:
    """Avant le rééquilibrage final : rapatrie vers leurs nœuds préférés
    (règle 'node-affinity' strict=0) les ressources HA qui ont été repliées
    HORS règle pendant l'Étape 1 (saturation du site au moment de
    l'évacuation). Objectif : un dégel final COHÉRENT — sans cela, le CRM
    re-migrerait la ressource hors-règle juste après le dégel (« nach
    kurzer Zeit », forum Proxmox), cassant en post-run l'équilibre que le
    rééquilibrage vient d'atteindre. Le rapatriement est planifié ICI (état
    simulé muté, mêmes sémantiques que plan_rebalance) et exécuté PENDANT
    la fenêtre de gel CRM, AVANT le rééquilibrage proprement dit — le
    rééquilibrage optimise donc AUTOUR du placement conforme.
    Si aucun nœud de la règle ne respecte la marge RAM/CPU : la ressource
    reste sur son hôte de repli (WARNING) et le CRM décidera au dégel
    (comportement attendu, pas une anomalie)."""
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
            logger.warning(
                f"  {vm} : rapatriement impossible sur sa règle "
                f"({', '.join(sorted(affinity))}, strict=0) — aucun nœud "
                f"de la règle ne respecte la marge RAM/CPU, la limite "
                f"anti-overcommit mémoire ou l'anti-affinité "
                f"keep-separate : elle reste sur "
                f"{src.name} (hôte de repli) ; le CRM pourra la "
                f"re-migrer après le dégel (comportement attendu).")
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
        logger.info(f"  {vm} : rapatriement {src.name} ➔ {tgt.name} "
                    f"(nœud de sa règle strict=0 — marge RAM restante "
                    f"après placement : {gb(tgt.ram_free_margin())}) : "
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
        # Bilan dry-run : détection des guests avec disque sur stockage
        # NON partagé, mémoïsée par (vmtype, vmid) -> True/False/None.
        self._vm_local_disks: Dict[Tuple[str, int], Optional[bool]] = {}
        # Storages partagés par nœud (GET /nodes/{node}/storage) :
        # None = échec MÉMOÏSÉ pour ce nœud — les guests suivants ne
        # redéclenchent PAS un cycle de bascule d'hôte API complet.
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

    def _ssh(self, node: str, cmd: str, stream: bool = False,
             retries: int = 2) -> str:
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
        retries=2 => jusqu'à 3 tentatives (attente 10s puis 20s)."""
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            if attempt:
                wait = min(60, 10 * attempt)
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
            f"tentatives ({last_exc})")

    def _ssh_once(self, node: str, cmd: str, stream: bool = False) -> str:
        import paramiko
        pkey = self._get_ssh_pkey()
        # Utiliser l'IP résolue lors de la découverte (le nom DNS peut ne pas
        # être résolvable depuis le worker, mais l'IP de gestion est connue).
        addr = self.node_addr.get(node, node)
        cli = paramiko.SSHClient()
        cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            cli.connect(addr, port=SSH_PORT, username=SSH_USER,
                        pkey=pkey, look_for_keys=False, allow_agent=True,
                        timeout=30, banner_timeout=30, auth_timeout=30)
        except Exception as e:
            # échec d'ÉTABLISSEMENT de connexion : injoignable →
            # retentable par l'enveloppe _ssh (coupure transitoire)
            raise SshTransportLost(f"connexion SSH à {addr} impossible ({e})")
        # Keepalive TCP : sans lui, une micro-coupure réseau prolongée
        # n'est détectée par personne et readline() bloque pour toujours.
        cli.get_transport().set_keepalive(15)
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
        finally:
            cli.close()

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
        return state

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

    def wait_ha_settled(self, timeout: int = MIGRATE_TIMEOUT,
                        stable_window: int = 60):
        """Attend que le CRM HA n'ait plus AUCUNE tâche en cours sur les
        ressources (états transitoires : migrate, relocate, recover,
        fence, freeze, lost). En fin de run, garantir un cluster stable
        avant le rapport final.

        NB : un instantané unique ne suffit PAS. À la sortie du mode
        maintenance, le CRM met plusieurs secondes (voire dizaines) à
        DÉCIDER un relocate (ex. rapatriement d'une VM évacuée vers son
        nœud d'origine). Un point isolé « rien en cours » peut donc
        précéder de peu une migration. On exige donc que l'état soit
        stable PENDANT stable_window secondes consécutives : toute
        tâche qui démarre dans la fenêtre réarme le compteur."""
        transient = ("migrate", "relocate", "recover", "fence", "freeze", "lost")
        t0 = time.time()
        stable_since = None
        last_beat = 0
        while time.time() - t0 < timeout:
            items = self.with_api(lambda p: p.cluster.ha.status.current.get())
            busy = [i for i in items if i.get("type") == "service"
                    and any(t in str(i.get("state", "")) for t in transient)]
            if not busy:
                if stable_since is None:
                    stable_since = time.time()
                    self.log.info(
                        f"CRM HA : aucune tâche en cours — confirmation "
                        f"pendant {stable_window}s…")
                elif time.time() - stable_since >= stable_window:
                    self.log.info(f"CRM HA : cluster stable depuis "
                                  f"{stable_window}s ✔")
                    return
            else:
                stable_since = None
                self.log.info("  CRM HA : tâches en cours — "
                              + ", ".join(f"{i.get('sid')} ({i.get('state')})"
                                          for i in busy))
            # battement de cœur pendant la fenêtre de stabilité :
            # un point toutes les 15s prouve que le script tourne toujours
            elapsed = int(time.time() - t0)
            if elapsed - last_beat >= 15 and stable_since is not None:
                last_beat = elapsed
                self.log.info("  … CRM HA : stabilité confirmée "
                               f"depuis {int(time.time() - stable_since)}s "
                               f"/ {stable_window}s")
            time.sleep(5)
        raise RuntimeError(f"Le CRM HA a toujours des tâches en cours "
                           f"après {timeout}s — cluster instable")

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
            msg = ((c.get("summary") or {}).get("message") or "").strip()
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
        Vérifie aussi que tous les OSDs du nœud sont 'up'."""
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
        while health not in ("HEALTH_OK",):
            if not diag_done:
                self.ceph_diagnose(st)
                diag_done = True
            if health == "HEALTH_WARN" and allow_warn:
                self.log.warning("Ceph en HEALTH_WARN — toléré "
                                 "(PVE_CEPH_ALLOW_WARN=1)")
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
                          timeout: int = MIGRATE_TIMEOUT):
        """Attend que le CRM ait évacué TOUTES les ressources HA du nœud,
        en deux conditions :
        1. plus aucune entrée /cluster/ha/resources ne pointe sur le nœud ;
        2. plus aucun guest HA ne se trouve PHYSIQUEMENT sur le nœud —
           l'entrée ressource change dès que la migration est DÉCLENCHÉE,
           mais la VM (live-)migre encore : migrer un guest dont la
           migration HA est en cours échoue ou se fait refuser.
        NB : le choix des cibles revient au CRM (règles d'affinité) ; une
        migration manuelle vers une cible arbitraire serait rejetée avec
        « not allowed on target node »."""
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

    def migrate_vm(self, node: str, vmid: int, target: str, vmtype: str):
        """Migration d'un guest. QEMU : live migration (zéro downtime).
        LXC : PAS de live migration possible — on utilise le mode 'restart'
        (arrêt, transfert, redémarrage sur la cible : downtime de quelques
        secondes/minutes selon le stockage)."""
        if vmtype == "lxc":
            self.log.info(f"Migration du CT {vmid} : {node} ➔ {target} "
                          f"(mode restart : ARRET/REDÉMARRAGE, downtime court)")
            task = self.with_api(lambda p: p.nodes(node).lxc(vmid).migrate.post(
                target=target, restart=1))
        else:
            self.log.info(f"Live migration de la VM {vmid} : {node} ➔ {target}")
            kwargs = {"target": target, "online": 1}
            if WITH_LOCAL_DISKS:
                # disques locaux inclus dans la migration (storage non partagé)
                kwargs["with-local-disks"] = 1
            task = self.with_api(lambda p: p.nodes(node).qemu(vmid).migrate.post(**kwargs))
        self._wait_task(node, task)

    def _wait_task(self, node: str, upid: str, timeout: int = MIGRATE_TIMEOUT):
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
                if st.get("exitstatus") in ("OK", None):
                    return
                raise RuntimeError(f"Tâche {upid} échouée : {st.get('exitstatus')}")
            time.sleep(5)
        raise RuntimeError(f"Timeout ({timeout}s) sur la tâche {upid}")

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

    def apt_upgrade_pending(self, node: str) -> Tuple[int, bool, int, int]:
        """Évalue (sans rien installer) les mises à jour en attente :
        - simulation apt-get (mode -s, aucune action),
        - retour : (nb de paquets à mettre à jour, noyau concerné ?,
                    octets à télécharger, octets d'espace disque
                    supplémentaire requis (négatif si libéré)).
        Le noyau dans la liste => reboot attendu après le full-upgrade."""
        out = self._ssh(node, "DEBIAN_FRONTEND=noninteractive "
                              "apt-get -s full-upgrade -q")
        m = re.search(r"(\d+) upgraded", out)
        n = int(m.group(1)) if m else 0
        kernel = bool(re.search(r"^Inst (proxmox-kernel|linux-image)",
                                out, re.M))

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
        return n, kernel, dl, inst

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
                    summ = ((s.get("health") or {}).get("checks")
                            or {}).get("PG_DEGRADED", {}).get("summary", "")
                    m = re.search(r"(\d+)/\d+ objects degraded", summ)
                    if m:
                        deg = int(m.group(1))
                return (nq, nmon, osdm.get("num_up_osds"),
                        osdm.get("num_in_osds"), osdm.get("num_osds"),
                        deg)

            first_degraded = _vitals(st)[5]
            while health != "HEALTH_OK" and time.time() - t0 < timeout:
                if not diag_done:
                    self.ceph_diagnose(st)
                    diag_done = True
                if health == "HEALTH_WARN" and allow_warn:
                    self.log.warning("  Ceph HEALTH_WARN après reboot — "
                                     "toléré (PVE_CEPH_ALLOW_WARN=1)")
                    break
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
        self.maintenance_nodes: List[str] = []   # pour le bloc finally
        self.touched = False   # le run a-t-il MODIFIÉ le cluster ?
        self.evacuated: Dict[str, List[Dict]] = {}   # nœud -> plans d'évacuation
        self.state: Optional[ClusterState] = None
        # sid -> état HA d'origine {"state","comment"} des ressources
        # détachées en 'ignored' : à restaurer en TOUT ÉTAT DE CAUSE.
        self.ha_snapshot: Dict[str, Dict] = {}
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
        self._off_rule_deferred_logged: Set[str] = set()
        # vmid des ressources HA repliées hors règle puis RAPATRIÉES sur
        # un nœud de leur règle pendant le rééquilibrage final (gel CRM) :
        # pour le rapport final — dégel cohérent, CRM sans correction.
        self.off_rule_returned: Set[int] = set()
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
        dernier état connu. Absent en dry-run (aucune modification)."""
        if self.dry:
            return
        try:
            data = {"updated": datetime.now().isoformat(timespec="seconds"),
                    "maintenance": self.maintenance_nodes,
                    "ha_ignored": self.ha_snapshot,
                    "ceph_flags": self.ceph_flags}
            with open(self._state_file(), "w", encoding="utf-8") as fh:
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
        if not res and not maint and not flags:
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
        if self.dry:
            self.log.info("[SIMULATION] En exécution réelle, ces ressources "
                          "seraient réactivées dans leur état d'origine et "
                          "ces nœuds sortis de maintenance.")
            return
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
        # l'état zéro est restauré : le fichier ne doit plus servir
        self._state_clear()
        # touched uniquement si la récupération a MODIFIÉ le cluster :
        # un fichier d'état vide (run précédent arrêté avant toute
        # écriture) ne justifie pas la fenêtre de stabilité de 60s
        # en fin de run.
        if res or maint:
            self.touched = True
        if res or maint:
            try:
                self.client.wait_ha_settled()
            except Exception as e:
                self.log.warning(f"Fenêtre de stabilité post-récupération : "
                                 f"{e}")

    # ---------- helpers ----------
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
                    self.client.migrate_vm(p["from"], real.vmid, tgt, real.vmtype)
                    self.touched = True
                    # diagnostic post-migration : la VM a-t-elle survécu ?
                    # (guest agent si présente, sinon qmpstatus/qemu ;
                    # une VM stopped reste stopped : migration hors ligne)
                    k = "CT" if real.vmtype == "lxc" else "VM"
                    if not self.client.vm_alive(tgt, real.vmid, real.vmtype,
                                                expect=real.status):
                        raise RuntimeError(
                            f"{k} {real.vmid} injoignable après migration "
                            f"vers {tgt} — arrêt avant d'aggraver la "
                            f"situation (fichier d'état conservé).")
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
    def preflight(self):
        banner(self.log, "ÉTAPE 0 — Pré-vérifications du cluster")
        # Les pré-vérifications sont de PURE LECTURE (quorum, versions PVE,
        # état HA) : elles s'exécutent aussi en dry-run — inutile de les
        # simuler, elles échoueraient réellement si le cluster allait mal.
        # ... sauf la récupération d'un run interrompu, qui MODIFIE le
        # cluster en --execute (réactivation des ressources HA laissées
        # en 'ignored', sortie des maintenances résiduelles).
        self._recover_interrupted_run()
        st = self.client.with_api(lambda p: p.cluster.status.get())
        cname = next((s.get("name", "?") for s in st
                      if s.get("type") == "cluster"), "?")
        if not any(s.get("quorate") == 1 for s in st if s.get("type") == "cluster"):
            raise RuntimeError("Le cluster n'est PAS quorate — abandon.")
        versions = self.client.node_versions()
        self.log.info(f"Cluster : {cname} — "
                      f"versions/nœuds accessibles : {versions}")
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
        print_occupancy_table(self.log, self.state, "ÉTAT INITIAL DU CLUSTER")
        gap = pressure_gap(self.state)
        if gap is not None:
            self.log.info(f"Écart de pression RAM initial (max-min) : {gap:.0%} "
                          f"(cible de rééquilibrage : "
                          f"AUTO — optimum théorique calculé en fin de run)")

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
        self.client.apt_update(node)
        n_up, kernel_up, dl_b, inst_b = self.client.apt_upgrade_pending(node)

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
        self.log.info(f"{node}: {n_up} paquet(s) à mettre à jour"
                      + (" — noyau inclus, reboot attendu après upgrade"
                         if kernel_up else ""))
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

        if self.dry:
            # ===== simulation : plan complet, VMs HA marquées =====
            sim = state.clone()
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
            if ha_plans:
                ha_desc = (f"{len(ha_plans)} ressource HA à détacher"
                           if len(ha_plans) == 1 else
                           f"{len(ha_plans)} ressources HA à détacher")
                self.log.info(f"  Résumé : {len(all_plans)} guest(s) à "
                              f"migrer dont {ha_desc} en 'ignored' ("
                              + ", ".join(str(p["vm"].vmid) for p in ha_plans)
                              + f") et {len(other_plans)} guest(s) sans HA.")
            else:
                self.log.info(f"  Résumé : {len(all_plans)} guest(s) à "
                              f"migrer — AUCUNE ressource HA sur {node}, "
                              f"rien à détacher.")
            # mémoriser l'évacuation pour un éventuel rapatriement (--node)
            self.evacuated[node] = all_plans

            # ===== 2a) détachement HA — UNIQUEMENT s'il y a des HA =====
            if ha_plans:
                self.log.info(f"[SIMULATION] 2a) Détachement HA : état "
                              f"'ignored' + label {PRU_LABEL} dans le "
                              f"comment — le CRM ne les gère plus")
                for p in ha_plans:
                    sid = self.client.ha_sids().get(p["vm"].vmid,
                                                     f"vm:{p['vm'].vmid}")
                    orig = self.client.ha_resource_snapshot(sid)
                    self.log.info(f"[SIMULATION] 2a)    {sid} "
                                  f"({p['vm'].name}) : {orig['state']} → "
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
                                  f"ÉTAT SIMULÉ APRÈS MIGRATION — {node} vidé",
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
            if ha_plans:
                detached = (f"{len(ha_plans)} ressource HA détachée"
                            if len(ha_plans) == 1 else
                            f"{len(ha_plans)} ressources HA détachées")
                self.log.info(f"[SIMULATION] 2g) Sortie de maintenance de "
                              f"{node} + réactivation des {detached} "
                              f"dans leur état d'origine (comment "
                              f"restauré) + fenêtre de stabilité CRM 60s")
                for p in ha_plans:
                    sid = self.client.ha_sids().get(p["vm"].vmid,
                                                     f"vm:{p['vm'].vmid}")
                    orig = self.client.ha_resource_snapshot(sid)
                    if p.get("off_rule"):
                        self.log.info(
                            f"[SIMULATION] 2g)    {sid} "
                            f"({p['vm'].name}) : réactivation DIFFÉRÉE "
                            f"(repli hors règle strict=0) — reste "
                            f"'ignored' jusqu'à la fin du run")
                    else:
                        self.log.info(f"[SIMULATION] 2g)    {sid} "
                                      f"({p['vm'].name}) : ignored → "
                                      f"{orig['state']} (comment d'origine "
                                      f"restauré)")
            else:
                self.log.info(f"[SIMULATION] 2g) Sortie de maintenance de "
                              f"{node} — aucune ressource HA n'a été "
                              f"détachée sur ce nœud, rien à réactiver.")
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

        try:
            # 2c) plan puis migrations réelles de TOUTES les VMs :
            # les ressources HA sont 'ignored', le script peut les
            # déplacer comme des VMs ordinaires (qm migrate live).
            sim = state.clone()
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
                                  f"OCCUPATIONS — après migration ({node} vidé)",
                                  highlight=node, plans=plans)

            # ===== PHASE 2 : UPGRADE SYSTÈME (dissociée de l'évacuation) =====
            banner(self.log, f"PHASE 2 — "
                   + ("REBOOT EN ATTENTE" if reboot_only else "UPGRADE SYSTÈME")
                   + f" DE {node}", ColorFormatter.CYAN)
            if reboot_only:
                self.log.info(f"{node}: apt full-upgrade Sauté — aucun "
                              f"paquet à mettre à jour, seul le reboot du "
                              f"noyau en attente est traité")
            else:
                self.client.apt_upgrade(node)
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
                                  "ressources repliées hors règle (strict=0) "
                                  "vers leurs nœuds préférés ✔ — dégel final "
                                  "cohérent, le CRM n'aura rien à corriger")
                self._apply_migrations(plans, self.state, ha_live=True)
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
                            "repliées hors règle (strict=0) vers leurs "
                            "nœuds préférés — AVANT le rééquilibrage, "
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
                  "(PVE_EST_MIGRATE_SPEED_MBPS, PVE_EST_MIGRATE_OVERHEAD_S)")
            self.log.info(
                f"  hypothèses (ajustables par env) : apt {EST_APT_MIN:.0f} min "
                f"+ upgrade {EST_UPGRADE_MIN:.0f} min + reboot "
                f"{EST_REBOOT_MIN:.0f} min par nœud maintenu "
                "(PVE_EST_APT_MIN, PVE_EST_UPGRADE_MIN, PVE_EST_REBOOT_MIN)")
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
        print_occupancy_table(self.log, self.state, "ÉTAT FINAL DU CLUSTER")
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
                f"hors règle (strict=0) pendant l'évacuation, puis "
                f"RAPATRIÉE(S) sur un nœud de leur règle pendant le "
                f"rééquilibrage final : dégel cohérent, le CRM n'a rien "
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
                    f"{len(back_home)} ressource(s) HA repliée(s) hors "
                    f"règle (strict=0) pendant ce run, puis rentrée(s) "
                    f"d'elles-mêmes sur un nœud de leur règle (placement "
                    f"normal des évacuations suivantes) — déjà chez "
                    f"elles à la fin du run, le CRM n'aura rien à "
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
        if self.dry:
            self.estimation_report()
            self.log.info("✅ DRY-RUN terminé — aucune action réelle n'a été exécutée.")

    # ---------- point d'entrée ----------
    def run(self, only_node: Optional[str]):
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
            self.preflight()
            # fichier d'état : trace ce qu'il faudra restaurer si ce run
            # plante (ressources HA détachées, nœuds en maintenance).
            # Mis à jour à CHAQUE transition, supprimé en fin de run OK.
            if not self.dry:
                self._state_write()
            for idx, node in enumerate(nodes, 1):
                self.update_node(node, f"{idx}/{len(nodes)}")
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
            fh = logging.FileHandler(env_log_file, encoding="utf-8")
            fh.setFormatter(PlainFileFormatter())
            logger.addHandler(fh)
            logger.info(f"Logs également écrits dans : {env_log_file}")
        except OSError as e:
            logger.warning(f"Fichier de log '{env_log_file}' inutilisable ({e}) "
                           f"— poursuite sans log fichier.")
    # Relecture des constantes maintenant que l'environnement est chargé
    # (elles ont été évaluées avant le chargement du fichier d'env).
    global API_HOST, API_HOSTS, API_USER, API_TOKEN_NAME, API_TOKEN_VALUE, VERIFY_SSL
    global SSH_USER, SSH_PRIVATE_KEY, SSH_PORT, SSH_KEY_PASSPHRASE
    global WITH_LOCAL_DISKS
    global EST_MIGRATE_SPEED, EST_MIGRATE_OVERHEAD_S
    global EST_APT_MIN, EST_UPGRADE_MIN, EST_REBOOT_MIN
    API_HOST = _env("PVE_API_HOST", API_HOST)
    # PVE_API_HOSTS et PVE_EST_* : relus APRÈS le fichier d'env comme les
    # autres — sinon une valeur posée UNIQUEMENT dans ce fichier serait
    # silencieusement ignorée (constante déjà évaluée à l'import ; la
    # précédence reste : shell env > fichier env > défaut).
    API_HOSTS = [h.strip() for h in _env("PVE_API_HOSTS", "").split(",") if h.strip()]
    EST_MIGRATE_SPEED = int(_env("PVE_EST_MIGRATE_SPEED_MBPS",
                                 str(EST_MIGRATE_SPEED // 1024 ** 2))) * 1024 ** 2
    EST_MIGRATE_OVERHEAD_S = int(_env("PVE_EST_MIGRATE_OVERHEAD_S",
                                      str(EST_MIGRATE_OVERHEAD_S)))
    EST_APT_MIN = float(_env("PVE_EST_APT_MIN", str(EST_APT_MIN)))
    EST_UPGRADE_MIN = float(_env("PVE_EST_UPGRADE_MIN", str(EST_UPGRADE_MIN)))
    EST_REBOOT_MIN = float(_env("PVE_EST_REBOOT_MIN", str(EST_REBOOT_MIN)))
    API_USER = _env("PVE_API_USER", API_USER)
    API_TOKEN_NAME = _env("PVE_API_TOKEN_NAME", API_TOKEN_NAME)
    API_TOKEN_VALUE = _env("PVE_API_TOKEN_VALUE", API_TOKEN_VALUE)
    VERIFY_SSL = _env("PVE_VERIFY_SSL", str(VERIFY_SSL)).lower() in ("1", "true", "yes")
    SSH_USER = _env("PVE_SSH_USER", SSH_USER)
    SSH_PRIVATE_KEY = _env("PVE_SSH_KEY", SSH_PRIVATE_KEY)
    SSH_PORT = int(_env("PVE_SSH_PORT", str(SSH_PORT)))
    SSH_KEY_PASSPHRASE = _env("PVE_SSH_PASSPHRASE", "")
    WITH_LOCAL_DISKS = _env("PVE_WITH_LOCAL_DISKS", str(WITH_LOCAL_DISKS)).lower() in ("1", "true", "yes")
    logger.info(f"Marges RAM : {margins_desc()}")
    # Diagnostic : la passphrase SSH est-elle disponible AVANT tout usage ?
    logger.info(f"Passphrase SSH        : "
                f"{'définie via PVE_SSH_PASSPHRASE' if SSH_KEY_PASSPHRASE else 'absente (aucune invite si la clé est nue)'}")
    dry = args.dry_run
    banner(logger, f"PROXMOX ROLLING UPDATE — mode {'DRY-RUN (simulation)' if dry else 'EXÉCUTION RÉELLE'}",
           ColorFormatter.GREEN if dry else "\033[91;1m")

    # Le client Proxmox est instancié dans TOUS les cas : l'inventaire du
    # cluster (lecture seule) est nécessaire aussi bien en dry-run (pour
    # simuler sur l'état réel) qu'en exécution. C'est le paramètre `dry`
    # passé à l'Updater qui garantit qu'AUCUNE action d'écriture n'est
    # effectuée sur les nœuds en mode dry-run.
    client = ProxmoxClient(logger)

    updater = Updater(logger, dry, client)
    try:
        updater.run(args.node)
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
    except Exception:
        sys.exit(2)


if __name__ == "__main__":
    main()