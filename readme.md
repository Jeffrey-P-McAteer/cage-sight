
# Cage-Sight

`cage-sight` provides a fully-automated method of installing software, running commands, and recording system
modifications within a VM.

`cage-sight` is designed to run on both Windows and Linux hosts, and execute software within
both Windows and Linux VMs.

# Stage 1 Goals

 - [ ] Build static binary on Linux w/ QEMU VM manager embedded
 - [ ] Build static binary on Windows w/ QEMU VM manager embedded
 - [ ] Design "Analysis Configuration" of some kind, likely a `.toml` file which tells `cage-sight`:
    - [ ] What type of VM to run (hard-drive locations, RAM allotment, EFI/BIOS, TPU/no TPU, user accounts to run SW as, etc.)
    - [ ] Where to grab software from (files, URLs)
    - [ ] Software initialization steps (eg run `.msi` w/ a headless install command) - INTERACTIVE SETUP CANNOT BE SUPPORTED!
    - [ ] Software excersize steps (eg run `./dangerous-program.exe C:\Temp\Data-to-Process.csv`)
 - [ ] Add GUI debug/interactive capability; this may someday be used to replace ^^ interactive steps above, but for now the purpose is to confirm s/w installs and executed command outputs.

Result: static builds on windows + linux which can run commands from a config file in a VM

# Stage 2 Goals

 - [ ] Design file-change tracking system; either by `sha256`-ing all files before/after boot or registering w/ OS to report file changes in-place.
 - [ ] Design a network I/O tracking system; ideally we capture DNS requests and can read all input/output across the default LAN connection.
 - [ ] Design system change tracking system. Using the collected file and network data to report what the program is doing (high-level).

Result: Reports of filesystem and network activity caused by the new software.

# Stage 3 Goals

 - [ ] Given the corpus of analysis data, scan `cve`s and other databases of vulnerabilities to identify displayed vulnerabilities.
 - [ ] We can also keep a list of secure/insecure behavior heuristics, such as programs reaching out to systems over `HTTP`.

Result: Vulnerability reports from filesystem and network activity caused by the new software.




