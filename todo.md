# Feroxbuster not handling SSL errors

## Expexted behavior

Detects the SSL error and adds the needed --insecure flag

## Actual behavior

[feroxbuster] press Ctrl+C once to skip and continue the scan
[*] Starting: feroxbuster
[debug] feroxbuster --url https://kobold.htb --wordlist /tmp/.tmp5g1SKB --json --silent --no-state --timeout 10 --threads 50 --filter-status 404
[debug] feroxbuster --url https://bin.kobold.htb --wordlist /tmp/.tmp5g1SKB --json --silent --no-state --timeout 10 --threads 50 --filter-status 404
[debug] feroxbuster --url https://mcp.kobold.htb --wordlist /tmp/.tmp5g1SKB --json --silent --no-state --timeout 10 --threads 50 --filter-status 404
[debug|feroxbuster stderr] ERROR: Could not connect to any target provided

[debug|feroxbuster stderr] ERROR: Could not connect to any target provided

[debug|feroxbuster stderr] ERROR: Could not connect to any target provided

[*] Finished: feroxbuster


## --silent kills the SSL warning

feroxbuster -u https://mcp.kobold.htb:443 -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://mcp.kobold.htb/
 🚩  In-Scope Url          │ mcp.kobold.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.0
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
Could not connect to https://mcp.kobold.htb/ due to SSL errors (run with --insecure to ignore), skipping...
  => :SSL: error sending request for url (https://mcp.kobold.htb/)                                                                                                                                                                
  ERROR: Could not connect to any target provided


[Mar 30, 2026 - 17:44:35 (CEST)] exegol-main /workspace # feroxbuster -u https://mcp.kobold.htb:443 -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt --silent
                                                                                                                                                                                                                                  ERROR: Could not connect to any target provided