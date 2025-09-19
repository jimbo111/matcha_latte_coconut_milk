# matcha_latte_coconut_milk

Hey — I’m Jimmy. This repo contains a simple, static-only malware indicator scanner I wrote in C.
It inspects files (hash, entropy, strings, PE import hints, packer markers) and gives a heuristic risk score.
Important: this tool does not execute the scanned file — it only reads bytes and analyzes them.
I built this for learning and quick triage. It’s not an antivirus or a replacement for a real sandbox/EDR. Use it to help decide whether a file needs deeper analysis (YARA, dynamic sandboxing, VirusTotal, etc.).

Safety & limitations (read this)
This is a static analysis tool only. It purposely does not run or emulate the target file. That reduces danger but also limits detection (obfuscated or fileless malware can evade it).
Heuristics produce false positives and false negatives. Treat the score as a guide — not a verdict.
Do not upload sensitive or private files to public services without permission. If you use VirusTotal or similar, be mindful of privacy and sharing.
For real-world suspicious files, use a snapshotable VM or an isolation sandbox and consult professional tools/teams.

