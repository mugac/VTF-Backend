"""
Konfigurace a metadata dostupných Volatility pluginů.
"""

from typing import Dict, List
from pydantic import BaseModel


class PluginInfo(BaseModel):
    name: str
    category: str
    description: str
    output_format: str = "json"


# Seznam dostupných pluginů s metadaty
AVAILABLE_PLUGINS: Dict[str, PluginInfo] = {
    # Process Analysis
    "windows.psscan.PsScan": PluginInfo(
        name="windows.psscan.PsScan",
        category="Process Analysis",
        description="Scans for process structures in memory (including terminated processes)"
    ),
    "windows.pslist.PsList": PluginInfo(
        name="windows.pslist.PsList",
        category="Process Analysis",
        description="Lists currently running processes from the active process list"
    ),
    "windows.pstree.PsTree": PluginInfo(
        name="windows.pstree.PsTree",
        category="Process Analysis",
        description="Displays process tree showing parent-child relationships"
    ),
    "windows.cmdline.CmdLine": PluginInfo(
        name="windows.cmdline.CmdLine",
        category="Process Analysis",
        description="Extracts command line arguments for running processes"
    ),
    "windows.dlllist.DllList": PluginInfo(
        name="windows.dlllist.DllList",
        category="Process Analysis",
        description="Lists loaded DLLs for each process"
    ),
    "windows.handles.Handles": PluginInfo(
        name="windows.handles.Handles",
        category="Process Analysis",
        description="Lists open handles for processes"
    ),
    "windows.envars.Envars": PluginInfo(
        name="windows.envars.Envars",
        category="Process Analysis",
        description="Displays environment variables for processes"
    ),
    "windows.privileges.Privs": PluginInfo(
        name="windows.privileges.Privs",
        category="Process Analysis",
        description="Lists process privileges and their status"
    ),
    "windows.sessions.Sessions": PluginInfo(
        name="windows.sessions.Sessions",
        category="Process Analysis",
        description="Lists login sessions and their associated processes"
    ),
    
    # Network Analysis
    "windows.netscan.NetScan": PluginInfo(
        name="windows.netscan.NetScan",
        category="Network Analysis",
        description="Scans for network connections and listening sockets"
    ),
    "windows.netstat.NetStat": PluginInfo(
        name="windows.netstat.NetStat",
        category="Network Analysis",
        description="Lists active network connections (similar to netstat command)"
    ),
    
    # File System
    "windows.filescan.FileScan": PluginInfo(
        name="windows.filescan.FileScan",
        category="File System",
        description="Scans for file objects in memory"
    ),
    
    # Registry
    "windows.registry.hivelist.HiveList": PluginInfo(
        name="windows.registry.hivelist.HiveList",
        category="Registry Analysis",
        description="Lists registry hives in memory"
    ),
    "windows.registry.printkey.PrintKey": PluginInfo(
        name="windows.registry.printkey.PrintKey",
        category="Registry Analysis",
        description="Prints registry keys and their values"
    ),
    "windows.registry.userassist.UserAssist": PluginInfo(
        name="windows.registry.userassist.UserAssist",
        category="Registry Analysis",
        description="Displays UserAssist registry keys (tracks executed programs)"
    ),
    
    # Malware Detection
    "windows.malfind.Malfind": PluginInfo(
        name="windows.malfind.Malfind",
        category="Malware Detection",
        description="Finds suspicious memory regions that may contain injected code"
    ),
    "windows.vadinfo.VadInfo": PluginInfo(
        name="windows.vadinfo.VadInfo",
        category="Malware Detection",
        description="Displays Virtual Address Descriptor (VAD) information"
    ),
    "windows.ldrmodules.LdrModules": PluginInfo(
        name="windows.ldrmodules.LdrModules",
        category="Malware Detection",
        description="Detects unlinked DLLs (hidden from module lists)"
    ),
    "windows.ssdt.SSDT": PluginInfo(
        name="windows.ssdt.SSDT",
        category="Malware Detection",
        description="Displays System Service Descriptor Table (SSDT) for rootkit detection"
    ),
    
    # System Information
    "windows.info.Info": PluginInfo(
        name="windows.info.Info",
        category="System Information",
        description="Displays basic information about the memory dump"
    ),
    "windows.modules.Modules": PluginInfo(
        name="windows.modules.Modules",
        category="System Information",
        description="Lists loaded kernel modules (drivers)"
    ),
    "windows.driverscan.DriverScan": PluginInfo(
        name="windows.driverscan.DriverScan",
        category="System Information",
        description="Scans for driver objects in memory"
    ),
    "windows.svcscan.SvcScan": PluginInfo(
        name="windows.svcscan.SvcScan",
        category="System Information",
        description="Scans for Windows services"
    ),
    "windows.callbacks.Callbacks": PluginInfo(
        name="windows.callbacks.Callbacks",
        category="System Information",
        description="Lists kernel callbacks (useful for rootkit detection)"
    ),
    
    # Memory Analysis
    "windows.memmap.Memmap": PluginInfo(
        name="windows.memmap.Memmap",
        category="Memory Analysis",
        description="Displays memory map for a specific process"
    ),
    "windows.dumpfiles.DumpFiles": PluginInfo(
        name="windows.dumpfiles.DumpFiles",
        category="Memory Analysis",
        description="Extracts memory-resident files to disk"
    ),
    
    # Security
    "windows.hashdump.Hashdump": PluginInfo(
        name="windows.hashdump.Hashdump",
        category="Security",
        description="Extracts password hashes from registry"
    ),
    "windows.cachedump.Cachedump": PluginInfo(
        name="windows.cachedump.Cachedump",
        category="Security",
        description="Extracts cached domain credentials"
    ),
    "windows.lsadump.Lsadump": PluginInfo(
        name="windows.lsadump.Lsadump",
        category="Security",
        description="Extracts LSA secrets from registry"
    ),
    
    # Timeline & Events
    "windows.getservicesids.GetServiceSIDs": PluginInfo(
        name="windows.getservicesids.GetServiceSIDs",
        category="Timeline & Events",
        description="Lists service SIDs from the registry"
    ),
    "windows.bigpools.BigPools": PluginInfo(
        name="windows.bigpools.BigPools",
        category="Timeline & Events",
        description="Lists big page pool allocations"
    ),
}


def get_plugin_list() -> List[str]:
    """Vrátí seznam názvů všech dostupných pluginů."""
    return list(AVAILABLE_PLUGINS.keys())


def get_plugin_info(plugin_name: str) -> PluginInfo:
    """Vrátí informace o konkrétním pluginu."""
    return AVAILABLE_PLUGINS.get(plugin_name)


def is_valid_plugin(plugin_name: str) -> bool:
    """Zkontroluje, zda je plugin validní."""
    return plugin_name in AVAILABLE_PLUGINS


def get_plugins_by_category(category: str) -> List[PluginInfo]:
    """Vrátí pluginy podle kategorie."""
    return [
        plugin for plugin in AVAILABLE_PLUGINS.values()
        if plugin.category == category
    ]


def get_all_categories() -> List[str]:
    """Vrátí seznam všech kategorií pluginů."""
    return list(set(plugin.category for plugin in AVAILABLE_PLUGINS.values()))
