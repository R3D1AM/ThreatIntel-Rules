import "pe"
import "hash"
import "math"
import "cuckoo"

rule Akira_Ransomware_Detection 
{
    meta:
        description = "Detects Akira ransomware based on file structure, strings, and behavioral indicators"
        author = "R3D1AM"
        date = "2024-09-16"
        version = "1.1"
        hash = "<Specific known Akira ransomware file hash>"
        reference = "https://threatintel.example.com/Akira"
        malware_family = "Akira Ransomware"
        severity = "High"
        target_system = "Windows"

    strings:
        // Known ransom note and extensions used by Akira ransomware
        $ransom_note = "akira_readme.txt" ascii
        $ransom_note_content = "Your network has been hacked and encrypted" ascii
        $encrypted_extension = ".akira" ascii
        
        // Known URLs or IPs associated with Akira ransomware C2 infrastructure
        $c2_ip = "77.247.126.158" ascii
        $c2_domain = "akira-c2.example.com" ascii

        // Registry keys or other system changes made by Akira
        $registry_key = "HKEY_LOCAL_MACHINE\\Software\\AkiraRansomware" ascii
        $mutex_name = "Global\\AkiraMutex" ascii

        // Known Exclusions and File Extensions
        $exclude_paths = "$Recycle.Bin" ascii
        $exclude_paths_2 = "System Volume Information" ascii

        // ChaCha8 encryption algorithm usage and suspicious byte sequences
        $hex_pattern_1 = { E8 ?? ?? ?? ?? 8B F8 85 C0 74 18 8B }  

        // Known encrypted file extensions in observed Akira samples
        $encrypted_ext_2 = ".powerranges" ascii
        $encrypted_ext_3 = ".akiranew" ascii
        $encrypted_ext_4 = ".abd" ascii
        
    condition:
        // 1. PE file format check (for Windows executables)
        uint16(0) == 0x5A4D and

        // 2. File size restrictions (Akira samples are typically not larger than 10MB)
        filesize < 10MB and

        // 3. Check for known ransom note file names or strings
        (any of ($ransom_note, $ransom_note_content, $encrypted_extension)) or

        // 4. Known C2 communication indicators (IP or domain)
        (any of ($c2_ip, $c2_domain)) or

        // 5. Check for system changes like registry keys or mutexes
        (any of ($registry_key, $mutex_name)) or

        // 6. Detect based on MD5, SHA1, or SHA256 hashes of known Akira ransomware samples
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" or
        hash.sha1(0, filesize) == "8d4f19b221751297b0c3a10f105772d7286c9411" or
        hash.sha256(0, filesize) == "1f4e7f21e909f59fd849bd5214af8b7d05cd7e09e6585657bf72ed4f1ecdcf43" or
        hash.sha256(0, filesize) == "3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c" or
        hash.sha256(0, filesize) == "5c62626731856fb5e669473b39ac3deb0052b32981863f8cf697ae01c80512e5" or
        hash.sha256(0, filesize) == "678ec8734367c7547794a604cc65e74a0f42320d85a6dce20c214e3b4536bb33" or
        hash.sha256(0, filesize) == "7b295a10d54c870d59fab3a83a8b983282f6250a0be9df581334eb93d53f3488" or

        // 7. Analyze PE imports (common in ransomware)
        pe.imports("advapi32.dll", "RegOpenKeyExA") and

        // 8. Check for abnormal file characteristics (high entropy)
        math.entropy(0, filesize) > 7.0 and

        // 9. Exclude known system directories from encryption
        (any of ($exclude_paths, $exclude_paths_2)) and

        // 10. (Optional) Dynamic analysis results from Cuckoo sandbox (if available)
        cuckoo.network.http_request(/akira-c2.example.com/) or
        cuckoo.network.dns_request(/akira-c2.example.com/)
}
