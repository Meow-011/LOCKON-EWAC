"""LOCKON EWAC — OUI (Organizationally Unique Identifier) Vendor Lookup

Uses Scapy's built-in manufdb which contains a comprehensive offline
database of IEEE OUI assignments.
"""

from scapy.all import conf

def lookup_vendor(bssid: str) -> str:
    """Look up the manufacturer from a BSSID/MAC address.
    
    Args:
        bssid: MAC address in format "AA:BB:CC:DD:EE:FF"
    
    Returns:
        Vendor name string, or "Unknown" if not found.
    """
    if not bssid or len(bssid) < 8:
        return "Unknown"
    
    # Scapy's manufdb returns the MAC string itself if not found
    vendor = conf.manufdb._get_manuf(bssid)
    
    if vendor == bssid or not vendor:
        # Check if locally administered (randomized MAC)
        # 2nd character is 2, 6, A, or E
        if len(bssid) >= 2 and bssid[1].upper() in ['2', '6', 'A', 'E']:
            return "Randomized (Local)"
        return "Unknown"
        
    return vendor
