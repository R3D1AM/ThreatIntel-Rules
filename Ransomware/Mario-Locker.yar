rule MarioLocker_Ransomware
{
    meta:
        description = "Detects MarioLocker ransomware using updated IOCs"
        author = "R3D1AM"
        date = "2024-09-16"
        version = "1.1"
        hash = "0a6757bea01c2c48b50b7ec2bc39e31c"
        malware_family = "MarioLocker"
        severity = "High"
        target_system = "Windows"
        reference = "https://malware-report.com/mariolocker"
    
    strings:
        // Ransom note related strings
        $ransom_note_1 = "YOUR FILES HAVE BEEN LOCKED" ascii
        $ransom_note_2 = "All your important files are encrypted" ascii
        $ransom_note_3 = "Send Bitcoin to the following address" ascii
        $ransom_extension = ".wasted" ascii

        // Specific strings found in MarioLocker binaries
        $string_1 = "Mario Locker" ascii
        $string_2 = "Decrypt files" ascii
        $string_3 = "Unlock your files" ascii

        // Hardcoded C2 or URL patterns
        $c2_domain_1 = "mariolocker-hackers.com" ascii

        // Specific file paths or filenames used by MarioLocker
        $file_name_1 = "C:\\Users\\%USERNAME%\\Desktop\\Readme.txt" ascii
        $file_name_2 = "C:\\Encrypted_Files\\mario_readme.txt" ascii

        // Hex patterns observed in MarioLocker executables
        $hex_pattern_1 = { E8 ?? ?? ?? ?? 8B F8 85 C0 74 18 8B }  
        $hex_pattern_2 = { 55 8B EC 83 E4 F0 6A }  

    condition:
        uint16(0) == 0x5A4D and                         
        filesize < 10MB and                             
        (any of ($ransom_note_*, $ransom_extension, $string_*, $file_name_*) or
        any of ($c2_domain_*) or
        any of ($hex_pattern_*)) and                    

        (
            hash.md5(0, filesize) == "0a6757bea01c2c48b50b7ec2bc39e31c" or  
            hash.md5(0, filesize) == "6615ea2fa3b879d27687a7ce917e93b0" or  
            hash.sha1(0, filesize) == "8d4f19b221751297b0c3a10f105772d7286c9411" 
        ) and

        pe.imports("advapi32.dll", "CryptEncrypt") and      
        pe.number_of_sections > 5 and                      
        math.entropy(0, filesize) > 7.0                    

        or cuckoo.network.http_request(/mariolocker-hackers.com/) or   
        cuckoo.file.string(/Your files have been encrypted/ or /Send Bitcoin to the following address/)   
}
