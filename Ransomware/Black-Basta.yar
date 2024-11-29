Last Update = "2024-11-24"

rule BlackBasta_Malicious_IPs {
    meta:
        description = "Detects known malicious IPv4 addresses associated with Black Basta ransomware"
    strings:
        $ip1 = "66.42.118.54"
        $ip2 = "170.130.165.73"
        $ip3 = "45.11.181.44"
        $ip4 = "79.132.130.211"
    condition:
        any of them
}

rule BlackBasta_Malicious_Domains {
    meta:
        description = "Detects known malicious domains used by Black Basta ransomware"
    strings:
        $domain1 = "moereng.com"
        $domain2 = "exckicks.com"
    condition:
        any of them
}

rule BlackBasta_MITRE_TTPs {
    meta:
        description = "Detects behavioral patterns based on Black Basta's MITRE ATT&CK techniques"
    strings:
        $powershell_disable = "PowerShell to disable antivirus products"
        $vssadmin_delete = "vssadmin.exe delete shadows /all /quiet"
        $encryption = "Data Encrypted for Impact"
        $cve_zero_logon = "CVE-2020-1472" // ZeroLogon vulnerability
        $cve_nopac = "CVE-2021-42278" // NoPac vulnerability
        $cve_printnightmare = "CVE-2021-34527" // PrintNightmare vulnerability
    condition:
        any of them
}

rule BlackBasta_Indicators {
    meta:
        description = "Comprehensive rule for detecting Black Basta ransomware indicators"
    strings:
        $ip1 = "66.42.118.54"
        $ip2 = "170.130.165.73"
        $domain1 = "moereng.com"
        $powershell_disable = "PowerShell to disable antivirus products"
        $vssadmin_delete = "vssadmin.exe delete shadows /all /quiet"
        $cve_zero_logon = "CVE-2020-1472"
        $cve_nopac = "CVE-2021-42278"
        $cve_printnightmare = "CVE-2021-34527"
    condition:
        any of ($ip*, $domain*, $powershell_disable, $vssadmin_delete, $cve_zero_logon, $cve_nopac, $cve_printnightmare)
}

rule BlackBasta_Ransomware_ChatSite {
    meta:
        description = "Detection for the ransom chat site URL for Black Basta ransomware"
        hash = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
        version = "0.1"
    strings:
        $ = "aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion"
    condition:
        all of them
}

rule BlackBasta_Ransomware_Note {
    meta:
        description = "Detection for the ransom note in Black Basta ransomware"
        hash = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
        version = "0.1"
    strings:
        $msg1 = "Your data are stolen and encrypted"
        $msg2 = "The data will be published on TOR website if you do not pay the ransom"
        $msg3 = "You can contact us and decrypt one file for free on this TOR site"
        $msg4 = "https://torproject.org"
        $url = "aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion"
    condition:
        4 of them
}

rule BlackBasta_Ransomware_Executable {
    meta:
        description = "Detection for Black Basta executable behavior"
        hash = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
        version = "0.1"
    strings:
        $command1 = "vssadmin.exe delete shadows /all /quiet"
        $log = "Done time: %.4f seconds, encrypted: %.4f gb"
        $error1 = "ERRRROR with file "
        $error2 = "Error 755: "
    condition:
        any of ($command*, $log, $error*)
}

rule BlackBasta_Ransomware_Linux {
    meta:
        description = "Linux-specific Black Basta ransomware behavior"
        hash = "7883f01096db9bcf090c2317749b6873036c27ba92451b212b8645770e1f0b8a"
        version = "0.1"
    strings:
        $path1 = "/vmfs/volumes"
        $config = "CandiesPlus.cpp"
        $error_msg = "mpz_rootrem: Negative argument, with even root."
    condition:
        2 of ($path1, $config, $error_msg)
}

rule BlackBasta_FileIndicators {
    meta:
        description = "Detects file artifacts created by Black Basta"
        version = "1.1"
    strings:
        $ext1 = ".basta" fullword
        $file1 = "readme.txt" fullword
    condition:
        any of ($ext1, $file1)
}

rule BlackBasta_Ransomware {
    meta:
        description = "Black Basta ransomware general detection"
        hash_001 = "203d2807df6ef531efbec7bfd109986de3e23df64c01ea4e337cbe5ba675248b"
        hash_002 = "affcb453760dbc48b39f8d4defbcc4fc65d00df6fae395ee27f031c1833abada"
    strings:
        $a_0 = "(you should download and install TOR browser first https://torproject.org)"
        $a_1 = "The data will be published on TOR website if you do not pay the ransom"
        $a_2 = "You can contact us and decrypt one file for free on this TOR site"
        $a_3 = "C:\\Windows\\SysNative\\vssadmin.exe delete shadows /all /quiet"
        $a_4 = "C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet"
        $a_5 = "mpz_powm: Negative exponent and non-invertible base."
        $a_6 = ".?AVfilesystem_error@filesystem@ghc@@"
        $a_7 = "Your data are stolen and encrypted"
        $a_8 = "serviceHub.testWindowstorehost.exe"
        $a_9 = "serviceHub.dataWarehouseHost.exe"
        $a_10 = "serviceHub.vsdetouredhost.exe"
    condition:
        8 of them
}

rule BlackBasta_Tools {
    meta:
        description = "Detection for tools used by Black Basta affiliates"
    strings:
        // Tools for initial access, lateral movement, and data exfiltration
        $anydesk = "AnyDesk"
        $quickassist = "Microsoft Quick Assist"
        $mimikatz = "Mimikatz"
        $softperfect = "SoftPerfect"
        $bitsadmin = "BITSAdmin"
        $psexec = "PsExec"
        $splashtop = "Splashtop"
        $screenconnect = "ScreenConnect"
        $cobaltstrike = "Cobalt Strike"
        $rclone = "RClone"
        $backstab = "Backstab"
    condition:
        any of them
}

