"""Draws every figure for the Chapters 1-3 revision as PNG files in ./fig (print style, 200 dpi)."""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Ellipse, FancyArrowPatch, Rectangle

plt.rcParams.update({"font.family": "Arial", "font.size": 8})
OUT = Path(__file__).with_name("fig")
OUT.mkdir(exist_ok=True)

INK = "#1f2933"
MUTED = "#52606d"
BLUE, BLUE_BG = "#2b5d8a", "#e8f0f8"
GREEN, GREEN_BG = "#2f7a55", "#e7f4ec"
PURPLE, PURPLE_BG = "#5b4a9b", "#efecf8"
AMBER, AMBER_BG = "#8a6100", "#fbf2dc"
GREY, GREY_BG = "#7b8794", "#f2f4f7"
RED = "#b23b2e"


def canvas(w, h):
    fig = plt.figure(figsize=(w, h))
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, w)
    ax.set_ylim(0, h)
    ax.axis("off")
    return fig, ax


def save(fig, name):
    fig.savefig(OUT / f"{name}.png", dpi=200, facecolor="white", bbox_inches="tight", pad_inches=0.08)
    plt.close(fig)


def box(ax, x, y, w, h, text="", ec=INK, fc="white", lw=1.0, r=0.06, size=8, bold=False,
        dashed=False, color=INK, align="center", va="center", pad=0.08):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}",
                                ec=ec, fc=fc, lw=lw, ls="--" if dashed else "-"))
    if text:
        tx = x + w / 2 if align == "center" else x + pad
        ty = y + h / 2 if va == "center" else y + h - pad
        ax.text(tx, ty, text, ha=align, va=va, fontsize=size, color=color,
                fontweight="bold" if bold else "normal", linespacing=1.35)


def titled(ax, x, y, w, h, title, lines, ec, fc, size=7.4, title_size=8.5, bullet=True):
    """A box with a coloured title band and a bulleted list."""
    box(ax, x, y, w, h, ec=ec, fc=fc)
    band = 0.32
    ax.add_patch(FancyBboxPatch((x, y + h - band), w, band, boxstyle="round,pad=0,rounding_size=0.06",
                                ec=ec, fc=ec, lw=1.0))
    ax.add_patch(Rectangle((x, y + h - band), w, band / 2, ec="none", fc=ec))
    ax.text(x + w / 2, y + h - band / 2, title, ha="center", va="center", color="white",
            fontsize=title_size, fontweight="bold")
    ty = y + h - band - 0.16
    for line in lines:
        ax.text(x + 0.12, ty, ("•  " if bullet else "") + line, ha="left", va="top", fontsize=size,
                color=INK, linespacing=1.3)
        ty -= 0.2 * (line.count("\n") + 1) + 0.07


def arrow(ax, p1, p2, text=None, color=INK, lw=1.0, dashed=False, both=False, rad=0.0, size=6.8,
          tpos=0.5, toff=(0, 0.07), tcolor=None, ha="center", head=8):
    style = "<|-|>" if both else "-|>"
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=head, color=color, lw=lw,
                                 ls="--" if dashed else "-", connectionstyle=f"arc3,rad={rad}",
                                 shrinkA=1, shrinkB=1))
    if text:
        mx = p1[0] + (p2[0] - p1[0]) * tpos + toff[0]
        my = p1[1] + (p2[1] - p1[1]) * tpos + toff[1]
        ax.text(mx, my, text, ha=ha, va="bottom", fontsize=size, color=tcolor or color,
                linespacing=1.25, bbox=dict(fc="white", ec="none", pad=0.6))


def line(ax, xs, ys, color=INK, lw=1.0, dashed=False):
    ax.plot(xs, ys, color=color, lw=lw, ls="--" if dashed else "-", solid_capstyle="butt")


def header(ax, w, h, title, sub=None):
    ax.text(w / 2, h - 0.22, title, ha="center", va="center", fontsize=10.5, fontweight="bold", color=INK)
    if sub:
        ax.text(w / 2, h - 0.45, sub, ha="center", va="center", fontsize=7.2, color=MUTED)


# ---------------------------------------------------------------- Figure 1: theoretical framework
def fig_theory():
    W, H = 7.0, 5.0
    fig, ax = canvas(W, H)
    header(ax, W, H, "THEORETICAL FRAMEWORK", "NIST Cybersecurity Framework 2.0 and CIS Critical Security Controls v8.1")
    funcs = [("GOVERN", True), ("IDENTIFY", True), ("PROTECT", True), ("DETECT", True),
             ("RESPOND", False), ("RECOVER", False)]
    x0, bw, gap = 0.25, 1.0, 0.1
    for i, (name, inscope) in enumerate(funcs):
        x = x0 + i * (bw + gap)
        box(ax, x, 3.95, bw, 0.42, name, ec=BLUE if inscope else GREY, fc=BLUE if inscope else GREY_BG,
            color="white" if inscope else GREY, bold=True, size=8)
    ax.text(x0 + 4 * (bw + gap) + bw + gap / 2, 3.8, "Outside the scope of the study", ha="center", va="top",
            fontsize=6.8, color=GREY, style="italic")
    roles = [
        ("Versioned requirement\ncatalogue\nAdministrator and\nreviewer roles\nExceptions approved\nby an administrator\nAudit trail per finding"),
        ("Endpoint and asset\nrecords (department,\nlocation)\nSoftware and port\ninventory\nKnown vulnerabilities\nRule-based risk score"),
        ("Group Policy baseline\non WS01 (CIS Level 1)\nBitLocker encryption\nstatus checked\nagainst requirements"),
        ("SCA configuration\nchecks\nWindows security\nevent alerts\nFile integrity\nmonitoring\nScan now action"),
    ]
    for i, txt in enumerate(roles):
        x = x0 + i * (bw + gap)
        arrow(ax, (x + bw / 2, 3.95), (x + bw / 2, 3.72), color=BLUE)
        box(ax, x, 1.95, bw, 1.75, txt, ec=BLUE, fc=BLUE_BG, size=6.6)
    # CIS controls column
    cx = x0 + 4 * (bw + gap)
    box(ax, cx, 1.95, 2 * bw + gap, 1.75, ec=GREEN, fc=GREEN_BG)
    ax.text(cx + (2 * bw + gap) / 2, 3.55, "CIS Controls v8.1 used as\nthe source of sample requirements",
            ha="center", va="top", fontsize=7, fontweight="bold", color=GREEN, linespacing=1.3)
    ax.text(cx + 0.12, 2.95, "Control 4: Secure configuration\nof enterprise assets\n\nControl 3: Data protection,\nincluding encryption of data\non end-user devices",
            ha="left", va="top", fontsize=6.8, color=INK, linespacing=1.3)
    # principles band
    box(ax, 0.25, 0.95, 6.5, 0.8, ec=PURPLE, fc=PURPLE_BG)
    ax.text(0.4, 1.6, "Guiding principles applied to every finding", fontsize=7.6, fontweight="bold",
            color=PURPLE, va="top")
    ax.text(0.4, 1.38, "Verification (Souppaya & Scarfone, 2022): a fix counts only after a later assessment confirms it.\n"
                       "Record keeping (Scarfone & Souppaya, 2023): each result keeps its time, requirement, catalogue version and review history.",
            fontsize=6.8, va="top", color=INK, linespacing=1.4)
    box(ax, 0.25, 0.3, 6.5, 0.48, "Compliance Monitoring System: Wazuh results and BitLocker status turned into tracked, verified findings",
        ec=INK, fc="white", bold=True, size=7.6)
    arrow(ax, (3.5, 0.95), (3.5, 0.79), color=PURPLE)
    save(fig, "f01_theory")


# ---------------------------------------------------------------- Figure 2: IPO
def fig_ipo():
    W, H = 7.0, 4.6
    fig, ax = canvas(W, H)
    header(ax, W, H, "INPUT–PROCESS–OUTPUT (IPO) FRAMEWORK",
           "IT Security Infrastructure and Compliance Monitoring System for ResultsCX")
    cw, ch, y = 2.05, 3.12, 0.85
    cols = [
        (0.2, "INPUT", BLUE, BLUE_BG, [
            "General monitoring needs from\nauthorized IT interviews",
            "Versioned requirement catalogue\n(CIS-based, synthetic)",
            "Wazuh results for WS01: SCA,\nsecurity events, inventory,\nvulnerabilities, file changes",
            "BitLocker status fields from\nthe PowerShell collector",
            "Synthetic asset details\n(department, location)",
            "Defined test cases and criteria"]),
        (2.475, "PROCESS", GREEN, GREEN_BG, [
            "Read the Wazuh indexer with a\nread-only account; receive\ncollector reports",
            "Map each result to a requirement\nand classify it into four states",
            "Create or update findings",
            "Rank open findings with a\nrule-based risk score",
            "Review, exception and\nsimulated-fix workflow",
            "Verify only by a later assessment",
            "Generate dashboard and reports"]),
        (4.75, "OUTPUT", PURPLE, PURPLE_BG, [
            "Working Wazuh-based prototype\n(Flask application, SQLite)",
            "Findings with status and\naudit history",
            "Prioritized fix list, endpoint\nmap and floor plan",
            "Dashboard, compliance report\nand CSV export",
            "Test results for accuracy,\nprocessing time and usability"]),
    ]
    for x, t, ec, fc, lines in cols:
        titled(ax, x, y, cw, ch, t, lines, ec, fc, size=6.7)
    arrow(ax, (2.27, 2.5), (2.46, 2.5), color=MUTED, lw=1.6, head=10)
    arrow(ax, (4.545, 2.5), (4.735, 2.5), color=MUTED, lw=1.6, head=10)
    box(ax, 0.2, 0.25, 6.6, 0.45, "", ec=GREY, fc=GREY_BG)
    ax.text(3.5, 0.55, "RESEARCHER-OWNED ISOLATED LAB  •  SYNTHETIC / TEST-MACHINE DATA ONLY", ha="center",
            fontsize=7, fontweight="bold", color=INK, va="center")
    ax.text(3.5, 0.37, "No connection to, deployment in, or testing against ResultsCX systems", ha="center",
            fontsize=6.5, color=MUTED, va="center")
    save(fig, "f02_ipo")


# ---------------------------------------------------------------- Figure 3: physical lab network
def fig_lab():
    W, H = 7.0, 4.7
    fig, ax = canvas(W, H)
    box(ax, 2.35, 4.05, 2.3, 0.52, "", ec=MUTED, fc=GREY_BG, dashed=True)
    ax.text(3.5, 4.42, "Internet (setup mode only)", ha="center", fontsize=8, fontweight="bold")
    ax.text(3.5, 4.2, "Used only to download installers and updates", ha="center", fontsize=6.5, color=MUTED)
    line(ax, [3.5, 3.5], [4.05, 3.36], color=MUTED, dashed=True)
    ax.text(3.5, 3.78, "X", ha="center", va="center", fontsize=10, color=RED, fontweight="bold",
            bbox=dict(fc="white", ec="none", pad=0.5))
    ax.text(3.62, 3.78, "WAN cable unplugged during testing and demo", va="center", fontsize=6.5, color=RED)
    box(ax, 0.15, 0.55, 6.7, 3.15, "", ec=BLUE, fc="#f6f9fc", dashed=True, r=0.1)
    ax.text(0.3, 3.53, "Isolated lab network  ·  10.20.0.0/24", fontsize=7, color=BLUE, fontweight="bold", va="center")
    ax.text(6.7, 3.53, "no default gateway  ·  domain cxlab.internal", fontsize=7, color=BLUE, fontweight="bold",
            va="center", ha="right")
    box(ax, 2.2, 2.65, 2.6, 0.7, "", ec=INK)
    ax.text(3.5, 3.17, "TP-Link Archer router", ha="center", fontsize=8, fontweight="bold")
    ax.text(3.5, 2.97, "Used as a simple switch  ·  LAN IP 10.20.0.254", ha="center", fontsize=6.4, color=MUTED)
    ax.text(3.5, 2.8, "DHCP, Wi-Fi, WPS, UPnP and remote management off", ha="center", fontsize=6.4, color=MUTED)
    hosts = [(0.3, "Laptop 1  ·  DC01", "Windows Server 2022", "AD DS · DNS · Group Policy", "IP 10.20.0.10", "LAN 1"),
             (2.55, "Laptop 2  ·  SEC01", "Ubuntu Server 24.04 LTS", "Wazuh server · Flask app · SQLite", "IP 10.20.0.20", "LAN 2"),
             (4.8, "Laptop 3  ·  WS01", "Windows 11 Pro (monitored client)", "Wazuh agent · BitLocker collector", "IP 10.20.0.101", "LAN 3")]
    for x, t, os_, role, ip, lan in hosts:
        box(ax, x, 1.55, 1.9, 0.8, "", ec=INK)
        ax.text(x + 0.95, 2.18, t, ha="center", fontsize=7.8, fontweight="bold")
        ax.text(x + 0.95, 1.99, os_, ha="center", fontsize=6.3, color=MUTED)
        ax.text(x + 0.95, 1.82, role, ha="center", fontsize=6.3, color=MUTED)
        ax.text(x + 0.95, 1.65, ip, ha="center", fontsize=6.3, color=MUTED)
        line(ax, [3.5, x + 0.95], [2.65, 2.35], lw=1.4)
        ax.text(x + 0.95 + (0.05 if x != 2.55 else 0.08), 2.42, lan, fontsize=5.8, color=MUTED, ha="left")
    # data flows
    line(ax, [5.75, 5.75], [1.55, 1.15], color=BLUE, dashed=True)
    line(ax, [5.75, 3.5], [1.15, 1.15], color=BLUE, dashed=True)
    arrow(ax, (3.5, 1.15), (3.5, 1.53), color=BLUE, dashed=True)
    ax.text(4.6, 1.21, "Wazuh agent: settings, events, inventory,\nfile changes (TCP 1514/1515)\nBitLocker status (HTTPS 8443)",
            ha="center", fontsize=6.0, color=BLUE, va="bottom", linespacing=1.2)
    line(ax, [1.25, 1.25], [1.55, 0.8], color=BLUE, dashed=True)
    line(ax, [1.25, 6.05], [0.8, 0.8], color=BLUE, dashed=True)
    arrow(ax, (6.05, 0.8), (6.05, 1.53), color=BLUE, dashed=True)
    ax.text(3.65, 0.62, "Group Policy baseline, DNS and Kerberos (DC01 → WS01)", ha="center", fontsize=6.3, color=BLUE)
    line(ax, [0.2, 0.6], [0.25, 0.25], lw=1.4)
    ax.text(0.65, 0.25, "Ethernet cable", fontsize=6.3, va="center")
    line(ax, [1.5, 1.9], [0.25, 0.25], color=BLUE, dashed=True)
    ax.text(1.95, 0.25, "Data flow", fontsize=6.3, va="center")
    ax.text(6.85, 0.25, "Reviewers open the app at https://10.20.0.20:8443 from a lab laptop.", fontsize=6.3,
            va="center", ha="right", color=MUTED)
    save(fig, "f03_lab")


# ---------------------------------------------------------------- Figure 4: reference design
def fig_reference():
    W, H = 7.0, 4.6
    fig, ax = canvas(W, H)

    def dev(x, y, w, t, s, hl=False):
        box(ax, x, y, w, 0.46, "", ec=BLUE if hl else INK, fc=BLUE_BG if hl else "white", lw=1.4 if hl else 1.0)
        ax.text(x + w / 2, y + 0.3, t, ha="center", fontsize=7.4, fontweight="bold")
        ax.text(x + w / 2, y + 0.13, s, ha="center", fontsize=6.0, color=MUTED)
    dev(2.55, 4.0, 1.75, "ISP-RTR · 2911", "Simulated internet")
    dev(4.7, 4.0, 1.75, "WEB-INET", "Test website and DNS")
    line(ax, [4.3, 4.7], [4.23, 4.23])
    line(ax, [3.42, 3.42], [4.0, 3.6]); ax.text(3.5, 3.75, "outside 203.0.113.0/30", fontsize=5.8, color=MUTED)
    dev(2.4, 3.14, 2.05, "FW-EDGE · ASA 5506-X", "NAT · blocks new inbound")
    line(ax, [3.42, 3.42], [3.14, 2.74]); ax.text(3.5, 2.89, "transit 10.10.255.0/30", fontsize=5.8, color=MUTED)
    dev(2.2, 2.28, 2.45, "CORE-SW1 · 3650 L3 switch", "Routes VLANs · ACLs · DHCP")
    line(ax, [3.42, 3.42], [2.28, 2.1]); line(ax, [1.15, 4.55], [2.1, 2.1])
    ax.text(1.25, 2.14, "802.1Q trunks · native VLAN 99", fontsize=5.8, color=MUTED)
    line(ax, [1.15, 1.15], [2.1, 1.93]); line(ax, [4.55, 4.55], [2.1, 1.93])
    dev(0.45, 1.47, 1.4, "ACC-SW1 · 2960", "Agent floor")
    dev(3.7, 1.47, 1.7, "ACC-SW2 · 2960", "Servers, IT, guest")
    line(ax, [1.15, 1.15], [1.47, 1.25])
    line(ax, [4.55, 4.55], [1.47, 1.35]); line(ax, [2.65, 6.25], [1.35, 1.35])
    for xx in (2.65, 4.4, 6.25):
        line(ax, [xx, xx], [1.35, 1.25])
    vlans = [(0.2, "VLAN 40 · AGENTS", "10.10.40.0/24", [("AGENT-PC1, AGENT-PC2", False), ("WS01 · test endpoint", True)], None),
             (1.85, "VLAN 20 · SERVERS", "10.10.20.0/24", [("DC01 · AD, DNS, GPO", True), ("SEC01 · Wazuh + app", True)], None),
             (3.55, "VLAN 50 · IT-ADMIN", "10.10.50.0/24", [("IT-PC1", False)], "SSH to switches"),
             (5.3, "VLAN 60 · GUEST", "10.10.60.0/24", [("GUEST-AP + laptop", False)], "Internet only")]
    for x, t, net, items, note in vlans:
        box(ax, x, 0.35, 1.55, 0.9, "", ec=INK, fc="white")
        ax.text(x + 0.08, 1.12, t, fontsize=6.6, fontweight="bold", va="center")
        ax.text(x + 0.08, 0.98, net, fontsize=5.8, color=MUTED, va="center")
        yy = 0.72
        for name, hl in items:
            box(ax, x + 0.08, yy, 1.39, 0.18, name, ec=BLUE if hl else MUTED, fc=BLUE_BG if hl else "white",
                size=5.8, lw=1.3 if hl else 0.8, r=0.04)
            yy -= 0.24
        if note:
            ax.text(x + 0.775, 0.45, note, ha="center", fontsize=5.8, color=MUTED)
    line(ax, [1.15, 1.15], [1.25, 1.25])
    box(ax, 0.2, 0.08, 0.28, 0.14, "", ec=BLUE, fc=BLUE_BG, lw=1.3, r=0.04)
    ax.text(0.55, 0.15, "Device also used in the physical lab (Figure 3)", fontsize=6, va="center")
    ax.text(6.85, 0.15, "VLAN 10 MGMT holds switch IPs; SSH allowed only from IT-ADMIN.", fontsize=6,
            va="center", ha="right", color=MUTED)
    save(fig, "f04_reference")


# ---------------------------------------------------------------- Figure 5: architecture
def fig_architecture():
    W, H = 7.0, 5.3
    fig, ax = canvas(W, H)
    header(ax, W, H, "SYSTEM ARCHITECTURE", "Physical lab: three laptops on the isolated 10.20.0.0/24 network")
    # DC01
    box(ax, 0.15, 3.95, 1.75, 0.75, "DC01\nActive Directory · DNS\nGroup Policy · BitLocker\nrecovery key (in AD only)",
        ec=MUTED, fc=GREY_BG, size=6.4)
    # WS01
    box(ax, 0.15, 0.55, 1.75, 2.95, "", ec=BLUE, fc=BLUE_BG)
    ax.text(1.02, 3.32, "WS01  ·  Windows 11 Pro", ha="center", fontsize=7.6, fontweight="bold", color=BLUE)
    box(ax, 0.27, 1.75, 1.51, 1.38, "", ec=BLUE, fc="white")
    ax.text(1.02, 2.98, "Wazuh agent", ha="center", fontsize=7.2, fontweight="bold")
    ax.text(0.37, 2.8, "SCA policy checks\nWindows event logs\nSoftware and port\ninventory\nFile integrity (FIM)",
            fontsize=6.3, va="top", linespacing=1.3)
    box(ax, 0.27, 0.7, 1.51, 0.85, "BitLocker collector\n(PowerShell, scheduled\nby GPO; 7 status\nfields only)", ec=BLUE,
        fc="white", size=6.3)
    arrow(ax, (1.02, 3.95), (1.02, 3.52), "Group Policy\nbaseline", color=MUTED, size=6, toff=(0.33, -0.05), ha="left")
    # SEC01 frame
    box(ax, 2.35, 0.3, 3.15, 4.4, "", ec=GREEN, fc="#f7fbf8", dashed=True, r=0.1)
    ax.text(3.92, 4.55, "SEC01  ·  Ubuntu Server 24.04", ha="center", fontsize=7.6, fontweight="bold", color=GREEN)
    box(ax, 2.5, 3.7, 1.35, 0.68, "Wazuh manager\nrules, decoders,\nvulnerability feed", ec=GREEN, fc="white", size=6.3)
    box(ax, 2.5, 2.42, 1.35, 1.0, "Wazuh indexer\nwazuh-alerts-4.x-*\nwazuh-states-\nvulnerabilities-*\nwazuh-states-\ninventory-*", ec=GREEN,
        fc="white", size=5.9)
    arrow(ax, (3.17, 3.7), (3.17, 3.44), color=GREEN)
    # app
    box(ax, 4.0, 1.05, 1.38, 3.33, "", ec=PURPLE, fc=PURPLE_BG)
    ax.text(4.69, 4.22, "Compliance app", ha="center", fontsize=7.2, fontweight="bold", color=PURPLE)
    ax.text(4.69, 4.07, "(Python Flask)", ha="center", fontsize=6.2, color=PURPLE)
    mods = ["Indexer reader", "Collector endpoint", "Mapping and\nfour-state classifier", "Finding sync and\nverification",
            "Rule-based risk score", "Workflow and roles", "Dashboard, reports"]
    yy = 3.78
    for m in mods:
        hgt = 0.36 if "\n" in m else 0.26
        box(ax, 4.1, yy - hgt, 1.18, hgt, m, ec=PURPLE, fc="white", size=5.8, r=0.04)
        yy -= hgt + 0.06
    box(ax, 2.5, 1.05, 1.35, 0.75, "SQLite database\nfindings, events,\nusers, assets, scores", ec=AMBER, fc=AMBER_BG, size=6.1)
    arrow(ax, (4.0, 1.42), (3.86, 1.42), color=AMBER, both=True)
    arrow(ax, (4.0, 2.95), (3.86, 2.95), "read-only\nqueries", color=GREEN, size=5.6, toff=(0.0, 0.06))
    box(ax, 2.5, 0.42, 2.88, 0.45, "Optional local AI (Ollama) · off by default · explains only", ec=GREY, fc="white",
        dashed=True, size=6.0)
    arrow(ax, (4.69, 1.05), (4.69, 0.88), color=GREY, dashed=True, both=True)
    # agent -> manager, collector -> app
    arrow(ax, (1.78, 2.6), (2.49, 3.95), "TCP 1514/1515\nencrypted", color=BLUE, size=5.8, tpos=0.42, toff=(-0.03, 0.02))
    line(ax, [1.78, 2.2], [1.1, 1.1], color=BLUE)
    line(ax, [2.2, 2.2], [1.1, 0.2], color=BLUE)
    line(ax, [2.2, 5.62], [0.2, 0.2], color=BLUE)
    line(ax, [5.62, 5.62], [0.2, 2.15], color=BLUE)
    arrow(ax, (5.62, 2.15), (5.39, 2.15), color=BLUE)
    ax.text(5.68, 0.6, "HTTPS 8443\n+ collector\ntoken", fontsize=5.8, color=BLUE, va="bottom")
    # browser
    box(ax, 5.85, 3.3, 1.0, 1.1, "Reviewer or\nadministrator\nweb browser\n(lab laptop)", ec=INK, fc="white", size=6.3)
    arrow(ax, (5.84, 3.75), (5.39, 3.75), color=INK, both=True)
    ax.text(6.35, 3.22, "HTTPS 8443,\nsign-in required", fontsize=5.8, ha="center", va="top", color=INK)
    save(fig, "f05_architecture")


# ---------------------------------------------------------------- DFD helpers
def entity(ax, x, y, w, h, text, size=6.8):
    ax.add_patch(Rectangle((x + 0.05, y - 0.05), w, h, ec="none", fc="#c9d1da"))
    ax.add_patch(Rectangle((x, y), w, h, ec=INK, fc="white", lw=1.0))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=size, fontweight="bold", linespacing=1.25)


def process(ax, x, y, w, h, num, text, size=6.6):
    box(ax, x, y, w, h, "", ec=GREEN, fc=GREEN_BG, r=0.1)
    line(ax, [x, x + w], [y + h - 0.22, y + h - 0.22], color=GREEN, lw=0.8)
    ax.text(x + w / 2, y + h - 0.11, num, ha="center", va="center", fontsize=6.4, fontweight="bold", color=GREEN)
    ax.text(x + w / 2, y + (h - 0.22) / 2, text, ha="center", va="center", fontsize=size, linespacing=1.25)


def store(ax, x, y, w, ident, text, size=6.4):
    h = 0.28
    line(ax, [x, x + w], [y + h, y + h], color=AMBER)
    line(ax, [x, x + w], [y, y], color=AMBER)
    line(ax, [x, x], [y, y + h], color=AMBER)
    line(ax, [x + 0.32, x + 0.32], [y, y + h], color=AMBER)
    ax.add_patch(Rectangle((x, y), w, h, ec="none", fc=AMBER_BG, zorder=0))
    ax.text(x + 0.16, y + h / 2, ident, ha="center", va="center", fontsize=6.2, fontweight="bold", color=AMBER)
    ax.text(x + 0.4, y + h / 2, text, ha="left", va="center", fontsize=size)


# ---------------------------------------------------------------- Figure 6: context diagram
def fig_context():
    W, H = 7.0, 4.6
    fig, ax = canvas(W, H)
    header(ax, W, H, "CONTEXT DIAGRAM (LEVEL 0 DATA FLOW DIAGRAM)")
    ax.add_patch(Ellipse((3.5, 2.2), 2.0, 1.25, ec=GREEN, fc=GREEN_BG, lw=1.3))
    ax.text(3.5, 2.42, "0", ha="center", fontsize=8, fontweight="bold", color=GREEN)
    ax.text(3.5, 2.12, "Compliance\nMonitoring System", ha="center", va="center", fontsize=8, fontweight="bold")
    entity(ax, 0.2, 3.35, 1.45, 0.55, "Wazuh indexer\n(SEC01)")
    entity(ax, 0.2, 0.55, 1.45, 0.55, "BitLocker collector\n(WS01)")
    entity(ax, 5.35, 3.35, 1.45, 0.55, "Reviewer")
    entity(ax, 5.35, 0.55, 1.45, 0.55, "Administrator")
    entity(ax, 2.78, 3.55, 1.45, 0.45, "Local AI service\n(optional)", size=6.3)
    def lab(x, y, t, ha="center"):
        ax.text(x, y, t, fontsize=5.9, ha=ha, va="top", linespacing=1.25, color=INK)
    arrow(ax, (1.66, 3.4), (2.68, 2.58))
    lab(0.92, 3.22, "SCA results, security-event\nand FIM alerts, inventory,\nvulnerabilities")
    arrow(ax, (1.66, 0.95), (2.72, 1.75))
    lab(0.92, 1.5, "BitLocker status report\n(7 fields, token)")
    arrow(ax, (5.34, 3.45), (4.33, 2.62))
    arrow(ax, (4.5, 2.32), (5.34, 3.3))
    lab(6.07, 3.22, "In: sign-in, Scan now, review\nnotes, status changes")
    lab(6.07, 2.82, "Out: dashboard, findings,\nhistory, report, CSV")
    arrow(ax, (5.34, 0.75), (4.35, 1.7))
    arrow(ax, (4.47, 1.95), (5.34, 0.95))
    lab(6.07, 1.92, "Out: account list,\nfindings, reports")
    lab(6.07, 1.52, "In: accounts, asset locations,\nfloor plans, exception decisions")
    arrow(ax, (3.35, 2.83), (3.35, 3.54), color=GREY, dashed=True, size=5.6)
    arrow(ax, (3.65, 3.54), (3.65, 2.83), color=GREY, dashed=True)
    ax.text(3.0, 3.1, "aggregates\nonly", fontsize=5.6, color=GREY, ha="right", va="center")
    ax.text(4.0, 3.1, "explanation\ntext", fontsize=5.6, color=GREY, ha="left", va="center")
    entity(ax, 0.2, 0.08, 0.22, 0.16, "", size=5)
    ax.text(0.5, 0.16, "External entity", fontsize=6, va="center")
    ax.add_patch(Ellipse((1.85, 0.16), 0.3, 0.17, ec=GREEN, fc=GREEN_BG))
    ax.text(2.05, 0.16, "System", fontsize=6, va="center")
    line(ax, [2.6, 2.95], [0.16, 0.16], color=GREY, dashed=True)
    ax.text(3.0, 0.16, "Optional flow (AI off by default)", fontsize=6, va="center")
    save(fig, "f06_context")


# ---------------------------------------------------------------- Figure 7: level 1 DFD
def fig_dfd1():
    W, H = 7.0, 6.2
    fig, ax = canvas(W, H)
    header(ax, W, H, "LEVEL 1 DATA FLOW DIAGRAM")
    entity(ax, 0.15, 5.0, 1.25, 0.5, "Wazuh indexer")
    entity(ax, 0.15, 3.9, 1.25, 0.5, "BitLocker\ncollector")
    entity(ax, 5.65, 5.0, 1.2, 0.5, "Reviewer or\nadministrator", size=6.4)
    entity(ax, 5.65, 0.35, 1.2, 0.5, "Administrator")
    pw, ph = 1.45, 0.78
    process(ax, 1.9, 4.6, pw, ph, "1.0", "Collect\nresults")
    process(ax, 1.9, 3.05, pw, ph, "2.0", "Map and classify\n(four states)")
    process(ax, 1.9, 1.5, pw, ph, "3.0", "Sync findings\nand verify")
    process(ax, 3.95, 1.5, pw, ph, "4.0", "Score risk\n(rule-based)")
    process(ax, 3.95, 4.6, pw, ph, "5.0", "Review\nworkflow")
    process(ax, 3.95, 3.05, pw, ph, "6.0", "Show dashboard\nand reports")
    process(ax, 3.95, 0.15, pw, ph, "7.0", "Manage accounts\nand assets")
    store(ax, 0.1, 2.15, 1.55, "D1", "Requirement\ncatalogue")
    store(ax, 0.1, 1.55, 1.55, "D2", "Findings")
    store(ax, 0.1, 0.95, 1.55, "D3", "Finding events")
    store(ax, 0.1, 3.05, 1.55, "D7", "BitLocker reports")
    store(ax, 5.55, 2.2, 1.35, "D5", "Risk scores")
    store(ax, 5.55, 1.55, 1.35, "D4", "Assets, floor\nplans")
    store(ax, 1.95, 0.35, 1.4, "D6", "Users")
    arrow(ax, (1.41, 5.25), (1.89, 5.05), "results\nand alerts", size=5.6, toff=(0, 0.02))
    arrow(ax, (1.41, 4.15), (1.89, 4.75), "status\nreport", size=5.6, tpos=0.45, toff=(-0.06, -0.12))
    arrow(ax, (2.4, 4.6), (1.1, 3.34), size=5.6)
    ax.text(1.38, 3.72, "store report", fontsize=5.6, ha="right")
    arrow(ax, (2.62, 4.6), (2.62, 3.84), "normalized\nresults", size=5.6, toff=(0.28, -0.05))
    arrow(ax, (1.1, 2.44), (1.9, 3.2), size=5.6)
    ax.text(1.3, 2.75, "requirement,\nversion", fontsize=5.6, ha="right")
    arrow(ax, (2.62, 3.05), (2.62, 2.29), "classified\nresults", size=5.6, toff=(0.27, -0.05))
    arrow(ax, (1.9, 1.85), (1.66, 1.7), both=True)
    arrow(ax, (1.9, 1.6), (1.66, 1.15))
    ax.text(1.72, 1.32, "audit\nentry", fontsize=5.4, ha="left", va="top")
    arrow(ax, (3.36, 1.75), (3.94, 1.75))
    ax.text(3.65, 1.68, "open\nfindings", fontsize=5.4, ha="center", va="top")
    arrow(ax, (5.41, 1.98), (5.54, 2.3), size=5.6)
    arrow(ax, (5.54, 1.7), (5.41, 1.75), size=5.6)
    ax.text(5.5, 2.55, "score, band,\nreason", fontsize=5.4, ha="center")
    arrow(ax, (5.64, 5.2), (5.41, 5.2))
    ax.text(5.52, 5.6, "notes, status changes,\nexception decisions", fontsize=5.6, ha="center", va="bottom")
    line(ax, [3.94, 3.65], [4.85, 4.85]); line(ax, [3.65, 3.65], [4.85, 2.1])
    arrow(ax, (3.65, 2.1), (3.36, 2.1))
    ax.text(3.65, 3.95, "fixed /\nexception\nstatus", fontsize=5.4, ha="center", va="center",
            bbox=dict(fc="white", ec="none", pad=0.6))
    arrow(ax, (6.23, 2.49), (5.2, 3.04), size=5.6)
    arrow(ax, (4.67, 2.29), (4.67, 3.04), "ranked\nlist", size=5.4, toff=(0.2, -0.05))
    arrow(ax, (5.41, 3.6), (5.95, 4.99), "dashboard,\nreports, CSV", size=5.6, tpos=0.45, toff=(0.33, -0.08))
    arrow(ax, (5.64, 0.6), (5.41, 0.55), "accounts,\nlocations", size=5.4, toff=(0.05, 0.08))
    arrow(ax, (3.94, 0.5), (3.36, 0.5), size=5.6)
    arrow(ax, (5.25, 0.93), (5.8, 1.54), size=5.6)
    save(fig, "f07_dfd1")


# ---------------------------------------------------------------- Figure 8: use case
def actor(ax, x, y, label):
    ax.add_patch(Ellipse((x, y + 0.42), 0.17, 0.17, ec=INK, fc="white", lw=1))
    line(ax, [x, x], [y + 0.33, y + 0.12]); line(ax, [x - 0.14, x + 0.14], [y + 0.27, y + 0.27])
    line(ax, [x, x - 0.11], [y + 0.12, y - 0.04]); line(ax, [x, x + 0.11], [y + 0.12, y - 0.04])
    ax.text(x, y - 0.1, label, ha="center", va="top", fontsize=6.8, fontweight="bold", linespacing=1.2)


def usecase(ax, x, y, text, w=1.75, h=0.36, ec=PURPLE, fc=PURPLE_BG):
    ax.add_patch(Ellipse((x, y), w, h, ec=ec, fc=fc, lw=1))
    ax.text(x, y, text, ha="center", va="center", fontsize=6.2, linespacing=1.15)
    return (x, y, w, h)


def fig_usecase():
    W, H = 7.0, 5.6
    fig, ax = canvas(W, H)
    header(ax, W, H, "USE CASE DIAGRAM")
    box(ax, 1.25, 0.25, 4.5, 4.85, "", ec=INK, fc="white", r=0.04)
    ax.text(3.5, 4.95, "Compliance Monitoring System", ha="center", fontsize=7.6, fontweight="bold")
    shared = ["Sign in", "View dashboard, endpoint\nmap and floor plan", "Run Scan now", "View finding details\nand history",
              "Add review note", "Set finding to in review,\nfixed pending or open", "Print compliance report\nor export CSV",
              "Request plain-language\nexplanation (optional AI)"]
    ys = [4.6 - i * 0.43 for i in range(len(shared))]
    pts = [usecase(ax, 2.55, y, t) for t, y in zip(shared, ys)]
    admin_only = ["Approve or revoke\nan exception", "Manage user accounts", "Manage asset locations\nand floor plans"]
    ays = [1.0, 0.62, 1.38]
    apts = [usecase(ax, 4.45, y, t, ec=BLUE, fc=BLUE_BG) for t, y in zip(admin_only, ays)]
    sys_cases = ["Supply assessment\nresults", "Submit BitLocker\nstatus report"]
    spts = [usecase(ax, 4.45, y, t, ec=GREEN, fc=GREEN_BG) for t, y in zip(sys_cases, (4.35, 3.75))]
    actor(ax, 0.6, 3.0, "Reviewer")
    actor(ax, 0.6, 0.9, "Administrator")
    actor(ax, 6.35, 4.2, "Wazuh\nindexer")
    actor(ax, 6.35, 3.0, "BitLocker\ncollector")
    for (x, y, w, h) in pts:
        line(ax, [0.76, x - w / 2], [3.3, y], lw=0.6, color=MUTED)
    for (x, y, w, h) in apts:
        line(ax, [0.76, x - w / 2], [1.2, y], lw=0.6, color=BLUE)
    arrow(ax, (0.6, 1.5), (0.6, 2.75), color=INK, head=11)
    ax.text(0.66, 2.1, "inherits all\nreviewer\nuse cases", fontsize=5.6, color=MUTED, va="center")
    line(ax, [6.2, 4.45 + 0.875], [4.6, 4.35], lw=0.6, color=GREEN)
    line(ax, [6.2, 4.45 + 0.875], [3.35, 3.75], lw=0.6, color=GREEN)
    arrow(ax, (3.3, 3.88), (3.75, 4.2), color=MUTED, dashed=True)
    ax.text(3.62, 3.98, "«include»", fontsize=5.6, color=MUTED, ha="left")
    save(fig, "f08_usecase")


# ---------------------------------------------------------------- Figure 9: ERD
def table_box(ax, x, y, w, name, cols, ec=INK, fc="white"):
    rh = 0.155
    h = 0.27 + rh * len(cols) + 0.05
    ax.add_patch(Rectangle((x, y - h), w, h, ec=ec, fc=fc, lw=1.0))
    ax.add_patch(Rectangle((x, y - 0.27), w, 0.27, ec=ec, fc=ec, lw=1.0))
    ax.text(x + w / 2, y - 0.135, name, ha="center", va="center", color="white", fontsize=7, fontweight="bold")
    yy = y - 0.27 - rh / 2 - 0.02
    for c in cols:
        key = c.split(" ")[0]
        weight = "bold" if key in ("PK", "PK,FK") else "normal"
        ax.text(x + 0.06, yy, c, fontsize=5.7, va="center", fontweight=weight, color=INK)
        yy -= rh
    return {"l": (x, y - h / 2), "r": (x + w, y - h / 2), "t": (x + w / 2, y), "b": (x + w / 2, y - h),
            "h": h}


def crow(ax, p, direction, many, color=INK):
    """Draw cardinality marks at point p. direction: unit vector pointing away from the entity."""
    dx, dy = direction
    px, py = -dy, dx
    if many:
        for s in (-1, 0, 1):
            line(ax, [p[0] + dx * 0.12, p[0] + px * 0.06 * s], [p[1] + dy * 0.12, p[1] + py * 0.06 * s], color=color, lw=0.8)
    else:
        line(ax, [p[0] + dx * 0.07 + px * 0.06, p[0] + dx * 0.07 - px * 0.06],
             [p[1] + dy * 0.07 + py * 0.06, p[1] + dy * 0.07 - py * 0.06], color=color, lw=0.8)
    line(ax, [p[0] + dx * 0.13 + px * 0.06, p[0] + dx * 0.13 - px * 0.06],
         [p[1] + dy * 0.13 + py * 0.06, p[1] + dy * 0.13 - py * 0.06], color=color, lw=0.8)


def rel(ax, a, b, a_many, b_many, label=None, dashed=False, lpos=None, color=INK):
    line(ax, [a[0], b[0]], [a[1], b[1]], dashed=dashed, color=color, lw=0.9)
    import math
    L = math.hypot(b[0] - a[0], b[1] - a[1])
    u = ((b[0] - a[0]) / L, (b[1] - a[1]) / L)
    crow(ax, a, u, a_many, color)
    crow(ax, b, (-u[0], -u[1]), b_many, color)
    if label:
        lx, ly = lpos or ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
        ax.text(lx, ly, label, fontsize=5.6, color=MUTED, ha="center", va="center",
                bbox=dict(fc="white", ec="none", pad=0.5), linespacing=1.2)


def fig_erd():
    W, H = 7.0, 7.3
    fig, ax = canvas(W, H)
    header(ax, W, H, "ENTITY RELATIONSHIP DIAGRAM", "SQLite database of the compliance application (schema version 2)")
    top = 6.7
    f = table_box(ax, 2.55, top, 1.9, "findings", [
        "PK id", "data_source (sample | wazuh)", "endpoint_id, endpoint_label", "check_key", "requirement_id",
        "catalogue_version", "source (sca, event, inventory,", "   vulnerability, fim, bitlocker)", "title, remediation",
        "state (4 assessment states)", "status (6 workflow statuses)", "severity, cvss, cve_id",
        "opened_at, verified_at, updated_at", "status_changed_at, times_reopened"], ec=PURPLE)
    s_ = table_box(ax, 2.55, f["b"][1] - 0.5, 1.9, "risk_scores", [
        "PK id", "FK finding_id", "score (0–100)", "band", "reason", "weights_version", "computed_at"], ec=PURPLE)
    e = table_box(ax, 5.0, top, 1.85, "finding_events", [
        "PK id", "FK finding_id", "at", "actor (username or system)", "kind (created, status, note, sync)",
        "from_status, to_status", "note"], ec=PURPLE)
    u = table_box(ax, 5.0, e["b"][1] - 0.45, 1.85, "users", [
        "PK id", "username (unique)", "password_hash (scrypt)", "role (admin | reviewer)", "active, failed_logins",
        "locked_until, last_login_at"], ec=BLUE)
    bl = table_box(ax, 5.0, u["b"][1] - 0.45, 1.85, "bitlocker_reports", [
        "PK id", "hostname", "received_at, collected_at", "mount_point, volume_type", "volume_status",
        "protection_status", "encryption_percentage", "encryption_method, lock_status"], ec=AMBER)
    a_ = table_box(ax, 0.15, top, 1.95, "asset_assignments", [
        "PK key_type (agent_id | hostname)", "PK key_value", "department", "building, floor, room", "updated_at"], ec=GREEN)
    m = table_box(ax, 0.15, a_["b"][1] - 0.45, 1.95, "marker_positions", [
        "PK agent_id", "building, floor", "x, y (0–1 on the plan)", "updated_at"], ec=GREEN)
    p_ = table_box(ax, 0.15, m["b"][1] - 0.45, 1.95, "floor_plans", [
        "PK building", "PK floor", "content_type", "image (PNG, JPEG, WebP)", "uploaded_at"], ec=GREEN)
    cat_y = p_["b"][1] - 1.05
    box(ax, 0.15, cat_y, 1.95, 0.62, "Requirement catalogue\n(versioned JSON file, v1.3,\n27 requirements; not a table)",
        ec=MUTED, fc=GREY_BG, dashed=True, size=6.0)
    fy = f["t"][1]
    rel(ax, (4.45, fy - 0.6), (5.0, fy - 0.6), False, True, "has\nhistory", lpos=(4.72, fy - 0.85))
    rel(ax, (3.5, f["b"][1]), (3.5, s_["t"][1]), False, True, "scored as", lpos=(3.95, (f["b"][1] + s_["t"][1]) / 2))
    rel(ax, (5.92, u["t"][1]), (5.92, e["b"][1]), False, True, "writes (by username)", dashed=True,
        lpos=(5.92, (u["t"][1] + e["b"][1]) / 2))
    rel(ax, (5.0, bl["t"][1] - 0.5), (4.45, f["b"][1] + 0.4), True, True, None, dashed=True)
    ax.text(4.72, f["b"][1] - 0.35, "BitLocker\nfindings by\nhostname", fontsize=5.6, color=MUTED, ha="center",
            va="center", bbox=dict(fc="white", ec="none", pad=0.5))
    rel(ax, (2.1, fy - 0.6), (2.55, fy - 0.6), False, True, "located by\nendpoint", dashed=True, lpos=(2.32, fy - 0.9))
    rel(ax, (1.12, a_["b"][1]), (1.12, m["t"][1]), False, False, "placed at", dashed=True,
        lpos=(1.55, (a_["b"][1] + m["t"][1]) / 2))
    rel(ax, (1.12, p_["t"][1]), (1.12, m["b"][1]), False, True, "shown on", dashed=True,
        lpos=(1.55, (p_["t"][1] + m["b"][1]) / 2))
    rel(ax, (2.1, cat_y + 0.31), (2.55, f["b"][1] + 0.25), False, True, None, dashed=True)
    ax.text(2.0, cat_y + 0.8, "requirement_id +\ncatalogue_version", fontsize=5.4, color=MUTED, ha="right", va="center")
    ly = bl["b"][1] - 0.25
    ax.text(5.0, ly, "Solid line: foreign key in the database", fontsize=5.8, va="center")
    ax.text(5.0, ly - 0.17, "Dashed line: logical link by a shared value", fontsize=5.8, va="center")
    ax.text(5.0, ly - 0.34, "Crow's foot: many  ·  bar: one", fontsize=5.8, va="center")
    save(fig, "f09_erd")


# ---------------------------------------------------------------- Figure 10: finding lifecycle
def state(ax, x, y, name, sub, ec, fc, w=1.3, h=0.55):
    box(ax, x - w / 2, y - h / 2, w, h, "", ec=ec, fc=fc, r=0.12, lw=1.2)
    ax.text(x, y + 0.08, name, ha="center", va="center", fontsize=7.4, fontweight="bold", color=INK)
    ax.text(x, y - 0.12, sub, ha="center", va="center", fontsize=5.8, color=MUTED)


def fig_lifecycle():
    W, H = 7.0, 4.9
    fig, ax = canvas(W, H)
    header(ax, W, H, "FINDING LIFECYCLE", "Who can move a finding from one status to another")
    P, SYS = INK, GREEN
    TY, BY = 3.35, 1.35
    ax.add_patch(Ellipse((0.3, TY + 0.1), 0.15, 0.15, ec=INK, fc=INK))
    state(ax, 1.4, TY, "Open", "new failure or reopened", RED, "#fbeceb")
    state(ax, 3.5, TY, "In review", "being checked", BLUE, BLUE_BG)
    state(ax, 5.6, TY, "Fixed, pending", "note required", AMBER, AMBER_BG)
    state(ax, 1.4, BY, "Cleared", "check passed while open\nor in review", GREEN, GREEN_BG, h=0.6)
    state(ax, 3.5, BY, "Exception", "admin only, note required", PURPLE, PURPLE_BG, w=1.45)
    state(ax, 5.6, BY, "Verified", "later scan passed after\nthe fix was recorded", GREEN, GREEN_BG, h=0.6)
    arrow(ax, (0.38, TY + 0.1), (0.74, TY + 0.1), color=SYS)
    ax.text(0.2, TY + 0.38, "failed or\nunknown result", fontsize=5.6, color=SYS, ha="left", va="bottom")
    for x1, x2 in ((2.06, 2.84), (4.16, 4.94)):
        arrow(ax, (x1, TY + 0.09), (x2, TY + 0.09), color=P)
        arrow(ax, (x2, TY - 0.09), (x1, TY - 0.09), color=P)
    arrow(ax, (1.55, TY + 0.28), (5.45, TY + 0.28), color=P, rad=-0.22, both=True)
    ax.text(3.5, TY + 0.52, "mark fixed (note required)  ·  reopen", fontsize=5.9, ha="center", color=P)
    arrow(ax, (3.5, TY - 0.28), (3.5, BY + 0.28), color=P)
    ax.text(3.56, (TY + BY) / 2 + 0.05, "admin\napproves", fontsize=5.7, ha="left", va="center")
    arrow(ax, (1.85, TY - 0.28), (2.95, BY + 0.28), color=P, both=True)
    ax.text(2.25, (TY + BY) / 2 + 0.05, "admin approves\nor revokes", fontsize=5.7, ha="left", va="center",
            bbox=dict(fc="white", ec="none", pad=0.6))
    arrow(ax, (1.15, TY - 0.28), (1.15, BY + 0.31), color=SYS, lw=1.4)
    ax.text(1.08, (TY + BY) / 2, "assessment\npasses", fontsize=5.7, color=SYS, ha="right", va="center")
    arrow(ax, (1.6, BY + 0.31), (1.6, TY - 0.28), color=SYS, dashed=True)
    ax.text(1.66, (TY + BY) / 2 - 0.35, "fails\nagain", fontsize=5.7, color=SYS, ha="left", va="center")
    arrow(ax, (5.6, TY - 0.28), (5.6, BY + 0.31), color=SYS, lw=1.4)
    ax.text(5.67, (TY + BY) / 2, "later assessment\npasses", fontsize=5.7, color=SYS, ha="left", va="center")
    # verified -> open when it fails again: route along the bottom and up the left edge
    line(ax, [5.6, 5.6], [BY - 0.31, 0.78], color=SYS, dashed=True)
    line(ax, [5.6, 0.5], [0.78, 0.78], color=SYS, dashed=True)
    line(ax, [0.5, 0.5], [0.78, TY - 0.12], color=SYS, dashed=True)
    arrow(ax, (0.5, TY - 0.12), (0.74, TY - 0.12), color=SYS, dashed=True)
    ax.text(3.5, 0.83, "fails again: reopened, repeat counted", fontsize=5.7, color=SYS, ha="center", va="bottom")
    line(ax, [0.25, 0.6], [0.42, 0.42], color=P)
    ax.text(0.65, 0.42, "Changed by a person (role rules apply)", fontsize=6, va="center")
    line(ax, [3.2, 3.55], [0.42, 0.42], color=SYS, lw=1.4)
    ax.text(3.6, 0.42, "Changed only by an assessment result", fontsize=6, va="center")
    ax.text(3.5, 0.17, "Nobody can set Cleared or Verified by hand. An exception keeps its status until an admin revokes it.",
            fontsize=5.8, ha="center", va="center", color=MUTED)
    save(fig, "f10_lifecycle")


# ---------------------------------------------------------------- Figure 11: operations flowchart
def fig_flow():
    W, H = 7.0, 8.4
    fig, ax = canvas(W, H)
    header(ax, W, H, "OPERATIONS FLOWCHART")
    cx = 2.6

    def term(y, t):
        box(ax, cx - 0.8, y - 0.2, 1.6, 0.4, t, ec=INK, fc=GREY_BG, r=0.2, bold=True, size=7)

    def step(y, t, x=cx, w=2.4, h=0.42, ec=GREEN, fc=GREEN_BG, n=None):
        box(ax, x - w / 2, y - h / 2, w, h, t, ec=ec, fc=fc, r=0.03, size=6.4)
        if n:
            ax.text(x - w / 2 - 0.08, y, n, ha="right", va="center", fontsize=6, color=MUTED, fontweight="bold")

    def decision(y, t, x=cx, w=1.9, h=0.62):
        ax.add_patch(plt.Polygon([(x, y + h / 2), (x + w / 2, y), (x, y - h / 2), (x - w / 2, y)], ec=AMBER,
                                 fc=AMBER_BG, lw=1))
        ax.text(x, y, t, ha="center", va="center", fontsize=6.2, linespacing=1.15)

    ys = {}
    term(7.8, "Start")
    steps = [("1", "Prepare the versioned baseline (requirement catalogue)"),
             ("2", "Start the lab in lab mode; confirm no internet route"),
             ("3", "DC01 applies the Group Policy baseline to WS01"),
             ("4–5", "Wazuh agent sends SCA results, events, inventory and\nfile changes; manager stores them in the indexer"),
             ("6", "Collector sends BitLocker status to the app over HTTPS")]
    y = 7.25
    for n, t in steps:
        step(y, t, w=3.3, n=n)
        arrow(ax, (cx, y + 0.5 - (0.12 if n == "1" else 0) + (0.0)), (cx, y + 0.22), color=INK) if n != "1" else None
        ys[n] = y
        y -= 0.62
    arrow(ax, (cx, 7.6), (cx, 7.47))
    step(4.15, "Reviewer opens the dashboard or clicks Scan now", w=3.3, ec=BLUE, fc=BLUE_BG, n="7")
    arrow(ax, (cx, ys["6"] - 0.22), (cx, 4.37))
    step(3.5, "App reads the Wazuh indexer (read-only) and the latest\nBitLocker report; maps each result to the catalogue version", w=3.3, n="7–8")
    arrow(ax, (cx, 3.93), (cx, 3.72))
    decision(2.72, "Source\nreadable?")
    arrow(ax, (cx, 3.28), (cx, 3.04))
    step(2.72, "Show a warning; skip that\nsource (findings unchanged)", x=5.4, w=1.9, ec=GREY, fc=GREY_BG)
    arrow(ax, (cx + 0.95, 2.72), (4.44, 2.72), "No", size=6)
    decision(1.85, "Result\nstate?")
    arrow(ax, (cx, 2.41), (cx, 2.17), "Yes", size=6, toff=(0.14, -0.08))
    step(1.05, "Create or reopen finding;\nscore its risk", x=1.15, w=1.85, h=0.48, n="9")
    step(1.05, "Pending fix becomes Verified;\nopen finding becomes Cleared", x=4.15, w=2.05, h=0.48, n="11")
    arrow(ax, (cx - 0.95, 1.85), (1.15, 1.85), color=INK)
    arrow(ax, (1.15, 1.85), (1.15, 1.3), "non-compliant\nor unknown", size=5.6, toff=(-0.62, 0.02))
    arrow(ax, (cx + 0.95, 1.85), (4.15, 1.85))
    arrow(ax, (4.15, 1.85), (4.15, 1.3), "compliant", size=5.6, toff=(0.4, 0.05))
    ax.text(cx, 1.38, "not applicable:\nstate only", fontsize=5.6, ha="center", color=MUTED)
    step(0.3, "Reviewer records review, simulated fix or exception (10); generate report (12)", w=4.6, h=0.36,
         ec=BLUE, fc=BLUE_BG, x=2.75)
    arrow(ax, (1.15, 0.81), (1.15, 0.49))
    arrow(ax, (4.15, 0.81), (4.15, 0.49))
    # loop back
    line(ax, [5.05, 6.6], [0.3, 0.3], color=PURPLE)
    line(ax, [6.6, 6.6], [0.3, 4.15], color=PURPLE)
    arrow(ax, (6.6, 4.15), (4.26, 4.15), color=PURPLE)
    ax.text(6.52, 3.5, "Fix applied on WS01 (GPO refresh,\nresume BitLocker, remove software,\nrestore file); next assessment",
            fontsize=5.8, color=PURPLE, ha="right", va="center")
    arrow(ax, (5.4, 2.5), (3.2, 1.98), color=GREY)
    save(fig, "f11_flow")


if __name__ == "__main__":
    for f in (fig_theory, fig_ipo, fig_lab, fig_reference, fig_architecture, fig_context, fig_dfd1, fig_usecase,
              fig_erd, fig_lifecycle, fig_flow):
        f()
    print("figures:", sorted(p.name for p in OUT.glob("*.png")))
