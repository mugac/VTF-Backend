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
        supported_os=["windows"]
    ),
    "windows.dlllist.DllList": PluginInfo(
        name="windows.dlllist.DllList",
        category="Process Analysis",
        description="Lists loaded DLLs for each process",
        supported_os=["windows"]
    ),
    "windows.handles.Handles": PluginInfo(
        name="windows.handles.Handles",
        category="Process Analysis",
        description="Lists open handles for processes",
        supported_os=["windows"]
    ),
    "windows.envars.Envars": PluginInfo(
        name="windows.envars.Envars",
        category="Process Analysis",
        description="Displays environment variables for processes",
        supported_os=["windows"]
    ),
    "windows.privileges.Privs": PluginInfo(
        name="windows.privileges.Privs",
        category="Process Analysis",
        description="Lists process privileges and their status",
        supported_os=["windows"]
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
        supported_os=["windows"]
    ),
    "windows.vadinfo.VadInfo": PluginInfo(
        name="windows.vadinfo.VadInfo",
        category="Malware Detection",
        description="Displays Virtual Address Descriptor (VAD) information",
        supported_os=["windows"]
    ),
    "windows.ldrmodules.LdrModules": PluginInfo(
        name="windows.ldrmodules.LdrModules",
        category="Malware Detection",
        description="Detects unlinked DLLs (hidden from module lists)",
        supported_os=["windows"]
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
        supported_os=["windows"]
    ),
    "windows.dumpfiles.DumpFiles": PluginInfo(
        name="windows.dumpfiles.DumpFiles",
        category="Memory Analysis",
        description="Extracts memory-resident files to disk",
        supported_os=["windows"]
    ),
    
    # Security - Windows
    "windows.hashdump.Hashdump": PluginInfo(
        name="windows.hashdump.Hashdump",
        category="Security",
        description="Extracts password hashes from registry",
        supported_os=["windows"]
    ),
    "windows.cachedump.Cachedump": PluginInfo(
        name="windows.cachedump.Cachedump",
        category="Security",
        description="Extracts cached domain credentials",
        supported_os=["windows"]
    ),
    "windows.lsadump.Lsadump": PluginInfo(
        name="windows.lsadump.Lsadump",
        category="Security",
        description="Extracts LSA secrets from registry",
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
    "linux.netstat.NetStat": PluginInfo(
        name="linux.netstat.NetStat",
        category="Network Analysis",
        description="Lists active network connections on Linux",
        supported_os=["linux"]
    ),
    "linux.sockstat.Sockstat": PluginInfo(
        name="linux.sockstat.Sockstat",
        category="Network Analysis",
        description="Lists open sockets on Linux",
        supported_os=["linux"]
    ),
    "linux.ifconfig.Ifconfig": PluginInfo(
        name="linux.ifconfig.Ifconfig",
        category="Network Analysis",
        description="Lists network interfaces and their configurations",
        supported_os=["linux"]
    ),
    
    # File System - Linux
    "linux.lsof.Lsof": PluginInfo(
        name="linux.lsof.Lsof",
        category="File System",
        description="Lists open files for processes on Linux",
        supported_os=["linux"]
    ),
    "linux.mount.Mount": PluginInfo(
        name="linux.mount.Mount",
        category="File System",
        description="Lists mounted filesystems",
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
