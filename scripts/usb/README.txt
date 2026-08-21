KovanicaDAG node — USB stick
============================

Copy this whole "usb" folder onto a FAT32 USB stick.
No need to flash an image. Do not reformat the stick as ISO.

Linux / macOS
-------------
  1. Plug in the stick.
  2. Open Terminal in this folder.
  3. bash install.sh
     (or: bash install.sh --systemd   to start on login)

  One-click if you have network and do not want the stick copy:
    curl -sSfL https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.sh | bash

Windows
-------
  1. Plug in the stick.
  2. Right-click install.ps1 → Run with PowerShell
     (if blocked: powershell -ExecutionPolicy Bypass -File install.ps1)

  One-click:
    irm https://raw.githubusercontent.com/KovanicaDAG/kovanica-node/main/scripts/install.ps1 | iex

After install, genesis on your machine must match:
  curl -s http://127.0.0.1:8080/api/head
  curl -s https://explorer.kovanica.online/api/head

Join: TCP 9000 to seed.kovanica.online (or 145.223.116.178 if DNS prefers IPv6).
Do not enable KOVANICA_MINE unless you intend to mint. Default mine interval is 120s.

Docs: https://github.com/KovanicaDAG/kovanica-node/blob/main/JOIN.md
