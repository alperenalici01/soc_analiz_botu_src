from models.schemas import APILogCreate
from typing import Tuple, Optional

# CTF laboratuvarlarından aşina olduğumuz zararlı payload imzaları
MALICIOUS_SIGNATURES = [
    # SQL Injection (SQLi)
    "' OR 1=1", "UNION SELECT", "DROP TABLE", "--", "' OR '1'='1", 
    "WAITFOR DELAY", "SLEEP(", "EXEC xp_cmdshell",
    
    # Cross-Site Scripting (XSS)
    "<script>", "javascript:", "onerror=", "onload=", "document.cookie",
    "<img src=", "alert(1)",
    
    # Local File Inclusion (LFI) & Path Traversal
    "../", "..\\", "/etc/passwd", "C:\\Windows\\System32", "/etc/shadow",
    
    # OS Command Injection
    "; ls", "| whoami", "&& cat", "$(whoami)", "|| dir",
    
    # Modern / Çeşitli Zafiyetler (Log4j, NoSQL Injection, XXE)
    "${jndi:", '{"$gt":', '{"$ne":', "<!ENTITY"
]

def analyze_log(log: APILogCreate) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Gelen API logunu analiz eder ve tehdit durumunu döndürür.
    Dönüş: (Tehdit_Var_Mi (bool), Tehdit_Turu (str), Seviye (str))
    """
    threat_found = False
    threat_type = None
    severity = None

    # KURAL 1: Rate Limit ve Brute Force İhlali
    if log.status_code == 429:
        threat_found = True
        threat_type = "Brute Force / Rate Limit İhlali"
        severity = "Orta"

    # KURAL 2: Yetkisiz Erişim (Broken Access Control)
    elif ("/admin" in log.endpoint or "/iptal" in log.endpoint) and log.status_code in [401, 403]:
        threat_found = True
        threat_type = "Yetki Aşımı Denemesi (Broken Access Control)"
        severity = "Yüksek"

    # KURAL 3: Zararlı Payload Tespiti (SQLi, XSS)
    elif log.payload_data:
        for signature in MALICIOUS_SIGNATURES:
            if signature in log.payload_data:
                threat_found = True
                threat_type = f"Zararlı Payload ({signature})"
                severity = "Kritik"
                break  # Bir tane zafiyet bulmamız alarm için yeterli

    return threat_found, threat_type, severity