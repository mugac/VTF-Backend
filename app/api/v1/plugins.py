"""
Konfigurace a metadata dostupných Volatility pluginů.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class PluginInfo(BaseModel):
    name: str
    category: str
    description: str
    supported_os: List[str]  # ["windows"], ["linux"], nebo ["windows", "linux"]
    output_format: str = "json"
    accepts_pid: bool = False   # Plugin can be filtered by --pid
    requires_pid: bool = False  # Plugin MUST have --pid to run


# Seznam dostupných pluginů s metadaty
AVAILABLE_PLUGINS: Dict[str, PluginInfo] = {
    # ========== WINDOWS PLUGINS ==========
    
    # Process Analysis - Windows
    "windows.psscan.PsScan": PluginInfo(
        name="windows.psscan.PsScan",
        category="Process Analysis",
        description="Scans for process structures in memory (including terminated processes)",
        supported_os=["windows"]
    ),
    "windows.pslist.PsList": PluginInfo(
        name="windows.pslist.PsList",
        category="Process Analysis",
        description="Lists currently running processes from the active process list",
        supported_os=["windows"]
    ),
    "windows.pstree.PsTree": PluginInfo(
        name="windows.pstree.PsTree",
        category="Process Analysis",
        description="Displays process tree showing parent-child relationships",
        supported_os=["windows"]
    ),
    "windows.cmdline.CmdLine": PluginInfo(
        name="windows.cmdline.CmdLine",
        category="Process Analysis",
        description="Extracts command line arguments for running processes",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.dlllist.DllList": PluginInfo(
        name="windows.dlllist.DllList",
        category="Process Analysis",
        description="Lists loaded DLLs for each process",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.handles.Handles": PluginInfo(
        name="windows.handles.Handles",
        category="Process Analysis",
        description="Lists open handles for processes",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.envars.Envars": PluginInfo(
        name="windows.envars.Envars",
        category="Process Analysis",
        description="Displays environment variables for processes",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.privileges.Privs": PluginInfo(
        name="windows.privileges.Privs",
        category="Process Analysis",
        description="Lists process privileges and their status",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.sessions.Sessions": PluginInfo(
        name="windows.sessions.Sessions",
        category="Process Analysis",
        description="Lists login sessions and their associated processes",
        supported_os=["windows"]
    ),
    
    # Network Analysis - Windows
    "windows.netscan.NetScan": PluginInfo(
        name="windows.netscan.NetScan",
        category="Network Analysis",
        description="Scans for network connections and listening sockets",
        supported_os=["windows"]
    ),
    "windows.netstat.NetStat": PluginInfo(
        name="windows.netstat.NetStat",
        category="Network Analysis",
        description="Lists active network connections (similar to netstat command)",
        supported_os=["windows"]
    ),
    
    # File System - Windows
    "windows.filescan.FileScan": PluginInfo(
        name="windows.filescan.FileScan",
        category="File System",
        description="Scans for file objects in memory",
        supported_os=["windows"]
    ),
    
    # Registry - Windows
    "windows.registry.hivelist.HiveList": PluginInfo(
        name="windows.registry.hivelist.HiveList",
        category="Registry Analysis",
        description="Lists registry hives in memory",
        supported_os=["windows"]
    ),
    "windows.registry.printkey.PrintKey": PluginInfo(
        name="windows.registry.printkey.PrintKey",
        category="Registry Analysis",
        description="Prints registry keys and their values",
        supported_os=["windows"]
    ),
    "windows.registry.userassist.UserAssist": PluginInfo(
        name="windows.registry.userassist.UserAssist",
        category="Registry Analysis",
        description="Displays UserAssist registry keys (tracks executed programs)",
        supported_os=["windows"]
    ),
    
    # Malware Detection - Windows
    "windows.malfind.Malfind": PluginInfo(
        name="windows.malfind.Malfind",
        category="Malware Detection",
        description="Finds suspicious memory regions that may contain injected code",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.vadinfo.VadInfo": PluginInfo(
        name="windows.vadinfo.VadInfo",
        category="Malware Detection",
        description="Displays Virtual Address Descriptor (VAD) information",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.ldrmodules.LdrModules": PluginInfo(
        name="windows.ldrmodules.LdrModules",
        category="Malware Detection",
        description="Detects unlinked DLLs (hidden from module lists)",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.ssdt.SSDT": PluginInfo(
        name="windows.ssdt.SSDT",
        category="Malware Detection",
        description="Displays System Service Descriptor Table (SSDT) for rootkit detection",
        supported_os=["windows"]
    ),
    
    # System Information - Windows
    "windows.info.Info": PluginInfo(
        name="windows.info.Info",
        category="System Information",
        description="Displays basic information about the memory dump",
        supported_os=["windows"]
    ),
    "windows.modules.Modules": PluginInfo(
        name="windows.modules.Modules",
        category="System Information",
        description="Lists loaded kernel modules (drivers)",
        supported_os=["windows"]
    ),
    "windows.driverscan.DriverScan": PluginInfo(
        name="windows.driverscan.DriverScan",
        category="System Information",
        description="Scans for driver objects in memory",
        supported_os=["windows"]
    ),
    "windows.svcscan.SvcScan": PluginInfo(
        name="windows.svcscan.SvcScan",
        category="System Information",
        description="Scans for Windows services",
        supported_os=["windows"]
    ),
    "windows.callbacks.Callbacks": PluginInfo(
        name="windows.callbacks.Callbacks",
        category="System Information",
        description="Lists kernel callbacks (useful for rootkit detection)",
        supported_os=["windows"]
    ),
    
    # Memory Analysis - Windows
    "windows.memmap.Memmap": PluginInfo(
        name="windows.memmap.Memmap",
        category="Memory Analysis",
        description="Displays memory map for a specific process",
        supported_os=["windows"],
        accepts_pid=True,
        requires_pid=True
    ),
    "windows.dumpfiles.DumpFiles": PluginInfo(
        name="windows.dumpfiles.DumpFiles",
        category="Memory Analysis",
        description="Extracts memory-resident files to disk",
        supported_os=["windows"],
        accepts_pid=True
    ),
    
    # Security & Credentials - Windows
    "windows.getsids.GetSIDs": PluginInfo(
        name="windows.getsids.GetSIDs",
        category="Security",
        description="Lists Security Identifiers (SIDs) for each process",
        supported_os=["windows"],
        accepts_pid=True
    ),
    "windows.registry.certificates.Certificates": PluginInfo(
        name="windows.registry.certificates.Certificates",
        category="Security",
        description="Lists certificates stored in the registry",
        supported_os=["windows"]
    ),
    "windows.skeleton_key_check.Skeleton_Key_Check": PluginInfo(
        name="windows.skeleton_key_check.Skeleton_Key_Check",
        category="Security",
        description="Checks for Skeleton Key malware in LSASS",
        supported_os=["windows"]
    ),
    
    # Timeline & Events - Windows
    "windows.getservicesids.GetServiceSIDs": PluginInfo(
        name="windows.getservicesids.GetServiceSIDs",
        category="Timeline & Events",
        description="Lists service SIDs from the registry",
        supported_os=["windows"]
    ),
    "windows.bigpools.BigPools": PluginInfo(
        name="windows.bigpools.BigPools",
        category="Timeline & Events",
        description="Lists big page pool allocations",
        supported_os=["windows"]
    ),
    
    # ========== LINUX PLUGINS ==========
    
    # Process Analysis - Linux
    "linux.pslist.PsList": PluginInfo(
        name="linux.pslist.PsList",
        category="Process Analysis",
        description="Lists currently running processes on Linux",
        supported_os=["linux"]
    ),
    "linux.pstree.PsTree": PluginInfo(
        name="linux.pstree.PsTree",
        category="Process Analysis",
        description="Displays process tree showing parent-child relationships on Linux",
        supported_os=["linux"]
    ),
    "linux.psaux.PsAux": PluginInfo(
        name="linux.psaux.PsAux",
        category="Process Analysis",
        description="Lists processes with detailed information (similar to ps aux)",
        supported_os=["linux"]
    ),
    "linux.bash.Bash": PluginInfo(
        name="linux.bash.Bash",
        category="Process Analysis",
        description="Recovers bash history and command line from memory",
        supported_os=["linux"]
    ),
    "linux.envars.Envars": PluginInfo(
        name="linux.envars.Envars",
        category="Process Analysis",
        description="Displays environment variables for Linux processes",
        supported_os=["linux"]
    ),
    
    # Network Analysis - Linux
    "linux.sockstat.Sockstat": PluginInfo(
        name="linux.sockstat.Sockstat",
        category="Network Analysis",
        description="Lists open sockets and active network connections on Linux",
        supported_os=["linux"]
    ),
    "linux.ip.Addr": PluginInfo(
        name="linux.ip.Addr",
        category="Network Analysis",
        description="Lists network interface IP addresses and configurations",
        supported_os=["linux"]
    ),
    "linux.ip.Link": PluginInfo(
        name="linux.ip.Link",
        category="Network Analysis",
        description="Lists network interface link-layer information",
        supported_os=["linux"]
    ),
    "linux.netfilter.Netfilter": PluginInfo(
        name="linux.netfilter.Netfilter",
        category="Network Analysis",
        description="Lists Netfilter hooks (firewall rules and packet filtering)",
        supported_os=["linux"]
    ),
    
    # File System - Linux
    "linux.lsof.Lsof": PluginInfo(
        name="linux.lsof.Lsof",
        category="File System",
        description="Lists open files for processes on Linux",
        supported_os=["linux"]
    ),
    "linux.mountinfo.MountInfo": PluginInfo(
        name="linux.mountinfo.MountInfo",
        category="File System",
        description="Lists mounted filesystems and mount details",
        supported_os=["linux"]
    ),
    "linux.lsmod.Lsmod": PluginInfo(
        name="linux.lsmod.Lsmod",
        category="File System",
        description="Lists loaded kernel modules on Linux",
        supported_os=["linux"]
    ),
    
    # Malware Detection - Linux
    "linux.check_afinfo.Check_afinfo": PluginInfo(
        name="linux.check_afinfo.Check_afinfo",
        category="Malware Detection",
        description="Checks for rootkit modifications in network protocol structures",
        supported_os=["linux"]
    ),
    "linux.check_syscall.Check_syscall": PluginInfo(
        name="linux.check_syscall.Check_syscall",
        category="Malware Detection",
        description="Checks system call table for hooks (rootkit detection)",
        supported_os=["linux"]
    ),
    "linux.check_modules.Check_modules": PluginInfo(
        name="linux.check_modules.Check_modules",
        category="Malware Detection",
        description="Checks for hidden kernel modules",
        supported_os=["linux"]
    ),
    "linux.check_creds.Check_creds": PluginInfo(
        name="linux.check_creds.Check_creds",
        category="Malware Detection",
        description="Checks process credentials for privilege escalation",
        supported_os=["linux"]
    ),
    "linux.malfind.Malfind": PluginInfo(
        name="linux.malfind.Malfind",
        category="Malware Detection",
        description="Finds suspicious memory regions on Linux",
        supported_os=["linux"]
    ),
    
    # System Information - Linux
    "linux.kmsg.Kmsg": PluginInfo(
        name="linux.kmsg.Kmsg",
        category="System Information",
        description="Extracts kernel messages (dmesg)",
        supported_os=["linux"]
    ),
    "linux.tty_check.tty_check": PluginInfo(
        name="linux.tty_check.tty_check",
        category="System Information",
        description="Checks TTY devices for tampering",
        supported_os=["linux"]
    ),
    "linux.keyboard_notifiers.Keyboard_notifiers": PluginInfo(
        name="linux.keyboard_notifiers.Keyboard_notifiers",
        category="System Information",
        description="Lists keyboard notifier callbacks (keylogger detection)",
        supported_os=["linux"]
    ),

    # Additional Linux Plugins
    "linux.psscan.PsScan": PluginInfo(
        name="linux.psscan.PsScan",
        category="Process Analysis",
        description="Scans for process structures in memory (finds hidden/terminated processes)",
        supported_os=["linux"]
    ),
    "linux.elfs.Elfs": PluginInfo(
        name="linux.elfs.Elfs",
        category="Process Analysis",
        description="Lists ELF binaries loaded in process memory",
        supported_os=["linux"]
    ),
    "linux.library_list.LibraryList": PluginInfo(
        name="linux.library_list.LibraryList",
        category="Process Analysis",
        description="Lists shared libraries loaded by each process",
        supported_os=["linux"]
    ),
    "linux.proc.Maps": PluginInfo(
        name="linux.proc.Maps",
        category="Process Analysis",
        description="Lists process memory mappings (similar to /proc/pid/maps)",
        supported_os=["linux"]
    ),
    "linux.capabilities.Capabilities": PluginInfo(
        name="linux.capabilities.Capabilities",
        category="Security",
        description="Lists Linux capabilities for each process (privilege analysis)",
        supported_os=["linux"]
    ),
    "linux.check_idt.Check_idt": PluginInfo(
        name="linux.check_idt.Check_idt",
        category="Malware Detection",
        description="Checks Interrupt Descriptor Table for hooks (rootkit detection)",
        supported_os=["linux"]
    ),
    "linux.hidden_modules.Hidden_modules": PluginInfo(
        name="linux.hidden_modules.Hidden_modules",
        category="Malware Detection",
        description="Detects hidden kernel modules not visible via lsmod",
        supported_os=["linux"]
    ),
    "linux.ptrace.Ptrace": PluginInfo(
        name="linux.ptrace.Ptrace",
        category="Malware Detection",
        description="Lists processes being traced via ptrace (debugger/injection detection)",
        supported_os=["linux"]
    ),

    # ========== Regex/Pattern Scanning ==========
    "windows.vadregexscan.VadRegExScan": PluginInfo(
        name="windows.vadregexscan.VadRegExScan",
        category="Malware Detection",
        description="Scans process memory VADs with regex patterns for suspicious strings",
        supported_os=["windows"]
    ),
    "linux.vmaregexscan.VmaRegExScan": PluginInfo(
        name="linux.vmaregexscan.VmaRegExScan",
        category="Malware Detection",
        description="Scans process memory VMAs with regex patterns for suspicious strings",
        supported_os=["linux"]
    ),
}


# ─── Plugin Presets ─────────────────────────────────────────────────────

PLUGIN_PRESETS: Dict[str, dict] = {
    "quick_triage": {
        "description": "Fast initial triage — processes, network, command lines, malware indicators",
        "plugins": [
            "windows.psscan.PsScan",
            "windows.cmdline.CmdLine",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind",
        ],
    },
    "full_process": {
        "description": "Complete process analysis — all process-related plugins",
        "plugins": [
            "windows.psscan.PsScan",
            "windows.pslist.PsList",
            "windows.pstree.PsTree",
            "windows.cmdline.CmdLine",
            "windows.dlllist.DllList",
            "windows.envars.Envars",
            "windows.handles.Handles",
            "windows.privileges.Privs",
        ],
    },
    "malware_hunt": {
        "description": "Malware hunting — injections, hidden modules, rootkit hooks",
        "plugins": [
            "windows.malfind.Malfind",
            "windows.vadinfo.VadInfo",
            "windows.ldrmodules.LdrModules",
            "windows.ssdt.SSDT",
            "windows.callbacks.Callbacks",
            "windows.filescan.FileScan",
        ],
    },
    "network_forensics": {
        "description": "Network forensics — connections, sockets, related processes",
        "plugins": [
            "windows.netscan.NetScan",
            "windows.netstat.NetStat",
            "windows.psscan.PsScan",
        ],
    },
    "credential_extraction": {
        "description": "Credential & security analysis — SIDs, certificates, skeleton key",
        "plugins": [
            "windows.getsids.GetSIDs",
            "windows.registry.certificates.Certificates",
            "windows.skeleton_key_check.Skeleton_Key_Check",
            "windows.registry.userassist.UserAssist",
        ],
    },
    "linux_quick_triage": {
        "description": "Linux quick triage — processes, network, bash history, malware",
        "plugins": [
            "linux.pslist.PsList",
            "linux.bash.Bash",
            "linux.sockstat.Sockstat",
            "linux.malfind.Malfind",
            "linux.check_modules.Check_modules",
        ],
    },
    "linux_rootkit_hunt": {
        "description": "Linux rootkit detection — syscalls, modules, credentials",
        "plugins": [
            "linux.check_syscall.Check_syscall",
            "linux.check_modules.Check_modules",
            "linux.check_creds.Check_creds",
            "linux.check_afinfo.Check_afinfo",
            "linux.malfind.Malfind",
        ],
    },
}


def get_plugin_list(os_type: Optional[str] = None) -> List[str]:
    """
    Vrátí seznam názvů dostupných pluginů.
    Pokud je zadán os_type, filtruje pouze pluginy pro daný OS.
    """
    if os_type:
        return [
            name for name, info in AVAILABLE_PLUGINS.items()
            if os_type in info.supported_os
        ]
    return list(AVAILABLE_PLUGINS.keys())


def get_plugin_info(plugin_name: str) -> Optional[PluginInfo]:
    """Vrátí informace o konkrétním pluginu."""
    return AVAILABLE_PLUGINS.get(plugin_name)


def is_valid_plugin(plugin_name: str) -> bool:
    """Zkontroluje, zda je plugin validní."""
    return plugin_name in AVAILABLE_PLUGINS


def get_plugins_by_category(category: str, os_type: Optional[str] = None) -> List[PluginInfo]:
    """
    Vrátí pluginy podle kategorie.
    Pokud je zadán os_type, filtruje pouze pluginy pro daný OS.
    """
    plugins = [
        plugin for plugin in AVAILABLE_PLUGINS.values()
        if plugin.category == category
    ]
    
    if os_type:
        plugins = [p for p in plugins if os_type in p.supported_os]
    
    return plugins


def get_all_categories(os_type: Optional[str] = None) -> List[str]:
    """
    Vrátí seznam všech kategorií pluginů.
    Pokud je zadán os_type, vrátí pouze kategorie obsahující pluginy pro daný OS.
    """
    if os_type:
        categories = set(
            plugin.category for plugin in AVAILABLE_PLUGINS.values()
            if os_type in plugin.supported_os
        )
    else:
        categories = set(plugin.category for plugin in AVAILABLE_PLUGINS.values())
    
    return list(categories)
