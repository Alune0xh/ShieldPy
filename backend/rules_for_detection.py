import os
import time
import magic 
import re
import sqlite3
import math


class RulesForViruses:
    
    def __init__(self, db_path):
       self.db_path = db_path


    max_file_size = 500 * 1024 * 1024    

    SUSPICIOS_KEYWORDS = [
        "crack", "keygen", "cheat", "bypass", "warez", "loader", "activator"
    ]

    PHISHING_KEYWORDS = [
        "invoice", "receipt", "statement", "overdue", "e-signed",
        "payment", "refund", "voicemail", "scan_doc"
    ]

    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".msi",
        ".lnk", ".scr", ".hta", ".js", ".jse", ".wsf", ".vbe"
    ]

    SUSPICIOUS_STRINGS = [
        # Network and Data Exfiltration
        "downloadstring", "downloadfile", "requests.get", "curl", "wget",
        "urllib.request", "socket.connect", "ftp.storlines",

        # Obfuscation and Evasion
        "frombase64string", "xor", "eval(", "exec(",
        "cryptstring", "virtualalloc", "rtlmovememory", 

        # Process Execution and Shells
        "wscript.shell", "os.system", "subprocess", "cmd.exe", "powershell",
        "createremotethread", "shellexecute",

        # Target Environment Recon
        "whoami", "ipconfig", "net user", "systeminfo", "netstat", "tasklist"
    ]

    SUSPICIOUS_MIMICS = ["svch0st", "scvhost", "lsasss", "crss", "smssnc", "winlog0n", "explor3r"]

    SILENT_EXECUTION_FLAGS = [
        "-nop", "-noprofile", "-windowstyle hidden", "-ep bypass",
        "-executionpolicy bypass", "-encodedcommand", "-enc", "-w hidden"
    ] 

    SUSPICIOUS_PORTS = [
        "445",    
        "137", "139", 
        "3389",   
        "23",    
        "21",     
        "4444",   
    ]
   
    LOW_ENTROPY_EXPECTED_TYPES = [".exe", ".dll", ".bat", ".vbs", ".ps1", ".scr", ".txt", ".docx", ".pdf"]


    def analyzing(self,  filepath,    stored_hash=None,   hash_checker=None, current_hash=None):
        score = 0
        reasons = []
        filename = os.path.basename(filepath)
        base_name, extension = os.path.splitext(filename)
        extension = extension.lower()

        if not os.path.exists(filepath):
            return {"score": 0, "status": "error", "reasons": ["File not found"]}

        size = os.path.getsize(filepath)

        if hash_checker and current_hash is None and size:
            current_hash = hash_checker.new_hash(filepath)

    # known malware hashes in db
        if current_hash:
            with sqlite3.connect(self.db_path) as conn:
                row = conn.execute(
                    "SELECT rule_name FROM signatures WHERE file_hash = ?", 
                    (current_hash,)
                ).fetchone()
            if row:
                return {
                    "score": 100, 
                    "status": "fatal", 
                    "reasons": [f"Database Signature Match: Matches malicious profile rule '{row[0]}'"]
                } 

    #1 double extension
        actual_ext = filename.split(".")[-1].lower()
        if len(filename.split(".")) > 2 and actual_ext in self.SUSPICIOUS_EXTENSIONS: 
            score += 35
            reasons.append(f"Suspicious double extension masking a dangerous file type: {actual_ext}")

        if "\u202e" in filename: 
            score += 50 
            reasons.append("Critical Evasion Alert: Filename contains a hidden Right-to-Left Override (RLO) character used to spoof file extensions!")

    #2a if suspcs keywords are in filename
        for keywords in self.SUSPICIOS_KEYWORDS:
            if keywords in filename.lower():
                score += 15
                reasons.append(f"Suspicious keyword found in filename: {keywords}")
                break

    #2b phishing style keywords 
        for keywords in self.PHISHING_KEYWORDS:
            if keywords in filename.lower() and extension in self.SUSPICIOUS_EXTENSIONS:
                score += 15
                reasons.append(f"Phishing-style keyword found in filename: {keywords}")
                break

    #3 files real type
        if os.path.exists(filepath) and size > 0:
            try:
                real_type = magic.from_file(filepath).lower()
                is_windows_binary = "executable" in real_type or "pe32" in real_type

                if is_windows_binary and "script" not in real_type:
                    if extension not in [".exe", ".dll", ".sys", ".scr", ".cpl", ".msi"]:
                        score += 50
                        reasons.append("Mismatched File Type: Windows binary file mimics a safe format but contains compiled executable code")
            
                elif "text" in real_type and extension in [".jpg", ".jpeg", ".png", ".pdf", ".docx"]:
                     score += 40 
                     reasons.append(f"Mismatched File Type: Document or media file '{extension}' hiddenly contains raw script/text data")
            except Exception as e:
                pass

    #4 size 
        if size == 0:
            score += 10
            reasons.append("File structural size is completely empty (0 bytes)")
        elif size > self.max_file_size:
            score += 10
            reasons.append("File is abnormally large")

    #5 location
        path_parts = filepath.lower().split("/")

        if any(loc in path_parts for loc in ["temp", "tmp", "downloads"]):
            if extension in self.SUSPICIOUS_EXTENSIONS:
                score += 35
                reasons.append(f"High-risk location alert: Executable file type ({extension}) detected inside an untrusted user directory")

            if len(base_name) <= 2:
                score += 25
                reasons.append(f"Suspicious Name: Abnormally short filename ({len(base_name)} chars) inside an untrusted staging directory")

    #6 hash change 
        if stored_hash and hash_checker:
            if stored_hash != current_hash:
                score += 25
                reasons.append("Integrity Alert: File content signatures altered since last database check record")


            
    #7,8,9 suspcs string and silent flags and suspcs ports
        matched_strings = set()
        matched_ports = set()
        silent_flags_found = False
        full = b""
        if 0 < size <= self.max_file_size:
            try:
                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        current_chunk = full + chunk
                        current_chunk_lower = current_chunk.lower()

                        for sus_str in self.SUSPICIOUS_STRINGS:
                            sus_bytes = sus_str.lower().encode()
                            if sus_str not in matched_strings and sus_bytes in current_chunk_lower:
                                matched_strings.add(sus_str)


                        if not silent_flags_found:
                            for flag in self.SILENT_EXECUTION_FLAGS:
                                flag_bytes = flag.lower().encode()
                                if flag_bytes in current_chunk:
                                    silent_flags_found = True
                                    score += 45
                                    reasons.append(f"Evasion Heuristic: Script tries to invoke silent/bypassed system execution via flag ({flag})")
                                    break

                        for port in self.SUSPICIOUS_PORTS:
                            if port not in matched_ports:
                                port_bytes = f":{port}".encode()
                                if port_bytes in current_chunk:
                                    matched_ports.add(port)

                        full = chunk.lower()[-100:] 

            except Exception as e:
                print(f"Error checking file content: {e}")

        if matched_strings:
            score += min((10 * len(matched_strings)),40)
            reasons.append(f"Heuristics Match: Found {len(matched_strings)} dangerous scripting strings in binary block content")
        if matched_ports:
            score += min(10 * len(matched_ports), 30) 
            ports_str = ', '.join(str(p) for p in matched_ports)
            reasons.append(f"Network Risk: Found {len(matched_ports)} suspicious port signature(s): {ports_str}")


    #10 age of file
        file_age_time = time.time() - os.path.getmtime(filepath)
        if file_age_time < 60 * 60 * 24 and extension in self.SUSPICIOUS_EXTENSIONS:
            score += 10
            reasons.append("New File Warning: This suspicious file was created or modified within the last 24 hours")

    #11 large name
        if len(filename) > 50:
            score += 15
            reasons.append(f"Warning: Filename is suspiciously long ({len(filename)} characters)")

    #12 all caps filename+ext
        base_name, extension = os.path.splitext(filename)
        if base_name.isupper() and extension.isupper():
            if extension.lower() in self.SUSPICIOUS_EXTENSIONS:
                score += 20
                reasons.append("Security Warning: Filename stands out with all capital letters, a tactic often used to make malicious programs look like official system updates.")


    #13 suspicious path username
        if any(name in path_parts for name in ["guest", "public", "anonymous"]):
            if "public" in path_parts:
                score += 15
                reasons.append("Warning: File found in Windows Public user directory (Shared Location)")
            else:
                score += 40
                reasons.append("Warning: File found in suspicious untrusted user directory (Guest/Anonymous)")

    #14 doesnt have enough vowels to pronounce
        letters_only = [i for i in base_name.lower() if i.isalpha()]
        digit_count = sum(i.isdigit() for i in base_name)
        has_alpha = len(letters_only) > 0

        randomness = False

        if has_alpha and digit_count >= 3:
            randomness = True

        # low vowel ratio
        if len(letters_only) >= 5:
            vowels = sum(1 for c in letters_only if c in "aeiou")
            vowel_ratio = vowels / len(letters_only)
            if vowel_ratio < 0.2:
                randomness = True

        if randomness and extension in self.SUSPICIOUS_EXTENSIONS:
            score += 20
            reasons.append("Suspicious Name: Filename pattern suggests random/algorithmic generation.")


    #15 spaces between extensions 
        if " " in filename and extension in self.SUSPICIOUS_EXTENSIONS:
            if re.search(r'\s{5,}', filename): 
                score += 40
                reasons.append("Evasion Alert: Filename contains abnormal spacing, likely trying to hide the real executable extension")

    #16 Masquerading 
        if any(mimic in base_name.lower() for mimic in self.SUSPICIOUS_MIMICS):
            score += 50
            reasons.append("Masquerading Alert: Filename closely mimics a critical Windows system process to evade human detection")
          

  
    #17 entropy check for files that are expected to have it low
        if 0 < size <= self.max_file_size:
            try:
                byte_counts = [0] * 256
                length = 0
                entropy = 0.0

                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        length += len(chunk)
                        for byte in chunk:
                            byte_counts[byte] += 1
                if length > 0:
                    for count in byte_counts:
                        if count == 0:
                            continue
                        p = count / length
                        entropy -= p * math.log2(p)

                if entropy >= 7.2 and extension in self.LOW_ENTROPY_EXPECTED_TYPES:
                        score += 35
                        reasons.append(f"High Entropy Warning: File content shows entropy of {entropy:.2f}, suggesting packing, encryption, or obfuscation")
            except Exception as e:
                print(f"Error calculating entropy: {e}")

    #18  multi-user path targeting
        script_extensions = [".bat", ".ps1", ".vbs", ".py", ".cmd"]
        if extension in script_extensions and 0 < size <= self.max_file_size:
            try:
                unique_usernames = set()
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        clean_line = line.lower()
                    
                        matches = re.findall(r'c:[/\\]users[/\\]([a-z0-9_]+)', clean_line)
                        if matches:
                            unique_usernames.update(matches)

                    if len(unique_usernames) >= 3:
                        score += 35
                        reasons.append(
                            f"Multi-Target Script: File references {len(unique_usernames)} different "
                            f"Windows user accounts, suggesting a generic/distributed attack script "
                            f"rather than legitimate personal code")
            except Exception as e:
                print(f"Error analyzing script paths: {e}")   

    #19 more than 2 URL in file
        if 0 < size <= self.max_file_size:
            try:
                url_count = 0
                with open(filepath, "rb") as f:
                    while True:
                        chunk = f.read(4096)
                        if not chunk:
                            break
                        
                        urls_http = chunk.lower().count(b"http://")
                        urls_https = chunk.lower().count(b"https://")
                        url_count += (urls_http + urls_https)

                if url_count >= 4:
                    score += 25
                    reasons.append(f"Network Risk: File contains an unusually high number of external web links ({url_count} URLs)")
            except Exception as e:
                print(f"Error counting URLs: {e}")      


        
        score = min(score, 100)

        if score >= 90: status = "fatal"
        elif score >= 70 : status = "dangerous"
        elif score >= 50: status = "suspicious"
        else: status = "safe"


        return {"score": score, "status": status, "reasons": reasons }