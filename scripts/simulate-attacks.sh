#!/usr/bin/env bash
# Lab-only attack simulation. Run ONLY inside your own isolated lab.
# Part A (run on the Mac / attacker): SSH brute force with a non-existent user
#   for i in {1..8}; do ssh -o PreferredAuthentications=password fakeuser@192.168.64.10; done
#
# Part B (run on the Kali agent): persistence, privilege escalation, file tampering
set -e
echo "[*] Persistence: create and remove a local account"
sudo useradd hacker && sudo userdel hacker

echo "[*] Privilege escalation: sudo to root"
sudo -i true

echo "[*] File Integrity Monitoring test"
mkdir -p ~/secret
echo "salary data" > ~/secret/payroll.txt;               sleep 15   # -> rule 554 added
echo "salary changed to 1,000,000" >> ~/secret/payroll.txt; sleep 15  # -> rule 550 checksum changed
chmod 777 ~/secret/payroll.txt;                          sleep 15   # -> rule 550 permissions changed
rm ~/secret/payroll.txt                                              # -> rule 553 deleted
echo "[+] Done. Check Wazuh Threat Hunting and FIM dashboards."
