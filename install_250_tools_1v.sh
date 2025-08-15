#!/bin/bash
# Termux 250+ Cybersecurity Tools Auto-Installer
# Saves everything into ~/S_TOOLS

set -Eeuo pipefail

# ---------- Config ----------
TOOLS_DIR="$HOME/S_TOOLS"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"   # change if you want more/fewer parallel clones
RETRY_MAX=2

# ---------- Pre-Reqs for Termux ----------
echo "[*] Updating Termux packages & installing dependencies..."
pkg update -y && pkg upgrade -y
pkg install -y git curl wget python python2 python3 php ruby perl nodejs \
  clang make cmake golang rust cargo openssl-tool \
  tar unzip zip coreutils findutils grep sed awk util-linux \
  libffi libsqlite libxml2 libxslt ncurses binutils

mkdir -p "$TOOLS_DIR"

# ---------- Clone helper (with retry) ----------
clone_one() {
  local name="$1"
  local url="$2"
  local dest="$TOOLS_DIR/$name"

  if [ -d "$dest/.git" ] || [ -d "$dest" ]; then
    echo "[-] $name already exists -> skip"
    return 0
  fi

  local tries=0
  until [ $tries -gt $RETRY_MAX ]; do
    echo "[+] Cloning $name  (try=$((tries+1)))"
    if git clone --depth=1 "$url" "$dest" >/dev/null 2>&1; then
      echo "[✓] $name"
      return 0
    fi
    tries=$((tries+1))
    sleep 2
  done
  echo "[x] $name -> FAILED ($url)"
  return 1
}

# ---------- Tools master list (name<space>url) ----------
# Kali categories + PD suite + Bug bounty + Wireless + Forensics + RE + Cloud + Social + Misc + Your repos.
read -r -d '' TOOLS <<"EOF"
# --- Information Gathering / Recon ---
recon-ng https://github.com/lanmaster53/recon-ng.git
theHarvester https://github.com/laramies/theHarvester.git
OSRFramework https://github.com/i3visio/osrframework.git
Amass https://github.com/owasp-amass/amass.git
Sublist3r https://github.com/aboul3la/Sublist3r.git
KnockPy https://github.com/guelfoweb/knock.git
findomain https://github.com/findomain/findomain.git
assetfinder https://github.com/tomnomnom/assetfinder.git
subfinder https://github.com/projectdiscovery/subfinder.git
dnsx https://github.com/projectdiscovery/dnsx.git
puredns https://github.com/d3mondev/puredns.git
massdns https://github.com/blechschmidt/massdns.git
dnsrecon https://github.com/darkoperator/dnsrecon.git
dnsenum https://github.com/fwaeytens/dnsenum.git
shuffledns https://github.com/projectdiscovery/shuffledns.git
naabu https://github.com/projectdiscovery/naabu.git
httpx https://github.com/projectdiscovery/httpx.git
httprobe https://github.com/tomnomnom/httprobe.git
hakrawler https://github.com/hakluke/hakrawler.git
katana https://github.com/projectdiscovery/katana.git
gau https://github.com/lc/gau.git
waybackurls https://github.com/tomnomnom/waybackurls.git
kxss https://github.com/tomnomnom/hacks/tree/master/kxss
qsreplace https://github.com/tomnomnom/qsreplace.git
unfurl https://github.com/tomnomnom/unfurl.git
getJS https://github.com/003random/getJS.git
linkfinder https://github.com/GerbenJavado/LinkFinder.git
paramspider https://github.com/devanshbatham/ParamSpider.git
xnLinkFinder https://github.com/xnl-h4ck3r/xnLinkFinder.git
github-search https://github.com/gwen001/github-search.git
github-endpoints https://github.com/gwen001/github-endpoints.git
github-subdomains https://github.com/gwen001/github-subdomains.git
git-dumper https://github.com/arthaud/git-dumper.git
gitgraber https://github.com/hisxo/gitGraber.git
bucketscanner https://github.com/ghostlulzhacks/bucketscanner.git
cloud_enum https://github.com/initstring/cloud_enum.git
CMSeeK https://github.com/Tuhinshubhra/CMSeeK.git
whatweb https://github.com/urbanadventurer/WhatWeb.git
wappalyzer https://github.com/wappalyzer/wappalyzer.git
ctfr https://github.com/UnaPibaGeek/ctfr.git
arjun https://github.com/s0md3v/Arjun.git
Photon https://github.com/s0md3v/Photon.git
spiderfoot https://github.com/smicallef/spiderfoot.git
aquatone https://github.com/michenriksen/aquatone.git
nrich https://github.com/sa7mon/nrich.git
tlsx https://github.com/projectdiscovery/tlsx.git
mapcidr https://github.com/projectdiscovery/mapcidr.git
ipv4bypass https://github.com/rotemreiss/ipv4bypass.git
# --- Vulnerability Scanners / Web App ---
nuclei https://github.com/projectdiscovery/nuclei.git
nuclei-templates https://github.com/projectdiscovery/nuclei-templates.git
dalfox https://github.com/hahwul/dalfox.git
xsstrike https://github.com/s0md3v/XSStrike.git
crlfuzz https://github.com/dwisiswant0/crlfuzz.git
corsy https://github.com/s0md3v/Corsy.git
tplmap https://github.com/epinna/tplmap.git
kiterunner https://github.com/assetnote/kiterunner.git
ffuf https://github.com/ffuf/ffuf.git
gobuster https://github.com/OJ/gobuster.git
feroxbuster https://github.com/epi052/feroxbuster.git
dirsearch https://github.com/maurosoria/dirsearch.git
wfuzz https://github.com/xmendez/wfuzz.git
nikto https://github.com/sullo/nikto.git
wpscan https://github.com/wpscanteam/wpscan.git
cmsmap https://github.com/Dionach/CMSmap.git
whatbuster https://github.com/3nock/wordpress-user-enum.git
ssti-map https://github.com/vladko312/SSTImap.git
ssrfmap https://github.com/swisskyrepo/SSRFmap.git
smuggler https://github.com/defparam/smuggler.git
httpreq-smuggler https://github.com/anshumanpattnaik/http-request-smuggler.git
concurlscan https://github.com/s0md3v/Concurlscan.git
cariddi https://github.com/edoardottt/cariddi.git
jaeles https://github.com/jaeles-project/jaeles.git
# --- Exploitation / Offensive ---
metasploit-framework https://github.com/rapid7/metasploit-framework.git
exploitdb https://github.com/offensive-security/exploitdb.git
commix https://github.com/commixproject/commix.git
routersploit https://github.com/threat9/routersploit.git
weevely3 https://github.com/epinna/weevely3.git
revshellgen https://github.com/0dayCTF/reverse-shell-generator.git
pwncat https://github.com/calebstewart/pwncat.git
linset https://github.com/chunkingz/linset.git
swisskyrepo-payloads https://github.com/swisskyrepo/PayloadsAllTheThings.git
# --- Password Attacks / Wordlists ---
hashcat https://github.com/hashcat/hashcat.git
john https://github.com/openwall/john.git
hydra https://github.com/vanhauser-thc/thc-hydra.git
ncrack https://github.com/nmap/ncrack.git
medusa https://github.com/jmk-foofus/medusa.git
cewl https://github.com/digininja/CeWL.git
crunch https://github.com/crunchsec/crunch.git
rsmangler https://github.com/digininja/RSMangler.git
PrinceProcessor https://github.com/hashcat/princeprocessor.git
hashcat-utils https://github.com/hashcat/hashcat-utils.git
seclists https://github.com/danielmiessler/SecLists.git
commonspeak2 https://github.com/assetnote/commonspeak2-wordlists.git
raft-wordlists https://github.com/daviddias/node-dirbuster.git
OneListForAll https://github.com/six2dez/OneListForAll.git
# --- Wireless / Radio ---
aircrack-ng https://github.com/aircrack-ng/aircrack-ng.git
wifite2 https://github.com/derv82/wifite2.git
reaver https://github.com/t6x/reaver-wps-fork-t6x.git
bully https://github.com/aanarchyy/bully.git
mdk4 https://github.com/aircrack-ng/mdk4.git
hcxdumptool https://github.com/ZerBea/hcxdumptool.git
hcxtools https://github.com/ZerBea/hcxtools.git
cowpatty https://github.com/joswr1ght/cowpatty.git
kismet https://github.com/kismetwireless/kismet.git
bettercap https://github.com/bettercap/bettercap.git
# --- Sniffing / Spoofing / MITM ---
ettercap https://github.com/Ettercap/ettercap.git
mitmproxy https://github.com/mitmproxy/mitmproxy.git
responder https://github.com/lgandx/Responder.git
bettercap-caplets https://github.com/bettercap/caplets.git
tshark-notes https://gitlab.com/wireshark/wireshark.git
# --- Post-Exploitation / Priv-Esc ---
linpeas https://github.com/carlospolop/PEASS-ng.git
winpeas https://github.com/carlospolop/PEASS-ng.git
pspy https://github.com/DominicBreuker/pspy.git
les https://github.com/mzet-/linux-exploit-suggester.git
les2 https://github.com/jondonas/linux-exploit-suggester-2.git
linenum https://github.com/rebootuser/LinEnum.git
gtfobins https://github.com/GTFOBins/GTFOBins.github.io.git
traitor https://github.com/liamg/traitor.git
suid3num https://github.com/Anon-Exploiter/SUID3NUM.git
mimikatz https://github.com/gentilkiwi/mimikatz.git
impacket https://github.com/fortra/impacket.git
psexec-python https://github.com/ramo-j/python-psexec.git
evil-winrm https://github.com/Hackplayers/evil-winrm.git
crackmapexec https://github.com/Porchetta-Industries/CrackMapExec.git
bloodhound https://github.com/BloodHoundAD/BloodHound.git
bloodhound-python https://github.com/fox-it/BloodHound.py.git
kerbrute https://github.com/ropnop/kerbrute.git
rubeus https://github.com/GhostPack/Rubeus.git
sharphound https://github.com/BloodHoundAD/SharpHound.git
powerview https://github.com/PowerShellMafia/PowerSploit.git
powersploit https://github.com/PowerShellMafia/PowerSploit.git
empire https://github.com/BC-SECURITY/Empire.git
# --- Forensics / IR ---
volatility3 https://github.com/volatilityfoundation/volatility3.git
volatility https://github.com/volatilityfoundation/volatility.git
sleuthkit https://github.com/sleuthkit/sleuthkit.git
autopsy https://github.com/sleuthkit/autopsy.git
binwalk https://github.com/ReFirmLabs/binwalk.git
foremost https://github.com/korczis/foremost.git
bulk-extractor https://github.com/simsong/bulk_extractor.git
pdfid https://github.com/DidierStevens/DidierStevensSuite.git
peepdf https://github.com/jesparza/peepdf.git
oledump https://github.com/DidierStevens/DidierStevensSuite.git
exiftool https://github.com/exiftool/exiftool.git
steghide https://github.com/StefanoDeVuono/steghide.git
stegseek https://github.com/RickdeJager/stegseek.git
zsteg https://github.com/zed-0xff/zsteg.git
yara https://github.com/VirusTotal/yara.git
yara-rules https://github.com/Yara-Rules/rules.git
xz-backdoor-scanner https://github.com/amlweems/xzbot.git
# --- Reverse Engineering ---
ghidra https://github.com/NationalSecurityAgency/ghidra.git
radare2 https://github.com/radareorg/radare2.git
cutter https://github.com/rizinorg/cutter.git
rizin https://github.com/rizinorg/rizin.git
angr https://github.com/angr/angr.git
apktool https://github.com/iBotPeaches/Apktool.git
jadx https://github.com/skylot/jadx.git
frida https://github.com/frida/frida.git
objection https://github.com/sensepost/objection.git
ghidra-ninja https://github.com/mandiant/Ghidrathon.git
# --- Mobile / Android Testing ---
mobSF https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
andbug https://github.com/swdunlop/AndBug.git
qark https://github.com/linkedin/qark.git
apkX https://github.com/ashishb/android-apktool-installer-for-linux.git
# --- Cloud / Container / IaC ---
prowler https://github.com/prowler-cloud/prowler.git
ScoutSuite https://github.com/nccgroup/ScoutSuite.git
cloudbrute https://github.com/0xsha/cloudbrute.git
trivy https://github.com/aquasecurity/trivy.git
grype https://github.com/anchore/grype.git
syft https://github.com/anchore/syft.git
tfsec https://github.com/aquasecurity/tfsec.git
kics https://github.com/Checkmarx/kics.git
kube-hunter https://github.com/aquasecurity/kube-hunter.git
kubeaudit https://github.com/Shopify/kubeaudit.git
kubescape https://github.com/kubescape/kubescape.git
dockle https://github.com/goodwithtech/dockle.git
# --- Bug Bounty Utils ---
notify https://github.com/projectdiscovery/notify.git
interactsh https://github.com/projectdiscovery/interactsh.git
proxify https://github.com/projectdiscovery/proxify.git
uncover https://github.com/projectdiscovery/uncover.git
dalfox https://github.com/hahwul/dalfox.git
dnsvalidator https://github.com/vortexau/dnsvalidator.git
github-search https://github.com/gwen001/github-search.git
lazyrecon https://github.com/nahamsec/lazyrecon.git
bbht https://github.com/nahamsec/bbht.git
jsleak https://github.com/0x240x23elu/JSScanner.git
uro https://github.com/s0md3v/uro.git
kxss2 https://github.com/tomnomnom/hacks
# --- OSINT ---
sherlock https://github.com/sherlock-project/sherlock.git
maigret https://github.com/soxoj/maigret.git
holehe https://github.com/megadose/holehe.git
ghunt https://github.com/mxrch/GHunt.git
twint https://github.com/twintproject/twint.git
snscrape https://github.com/JustAnotherArchivist/snscrape.git
dumper-diver https://github.com/securing/DumpsterDiver.git
phoneinfoga https://github.com/sundowndev/PhoneInfoga.git
infoga https://github.com/m4ll0k/Infoga.git
metabigor https://github.com/j3ssie/metabigor.git
cloudflare-trace https://github.com/Daemon-Codes/CF-Scanner.git
# --- Reporting / Notes ---
dradis https://github.com/dradis/dradis-ce.git
faraday https://github.com/infobyte/faraday.git
serpico https://github.com/SerpicoProject/Serpico.git
pwnDoc https://github.com/pwndoc/pwndoc.git
# --- Misc / Helpers ---
jq https://github.com/jqlang/jq.git
yq https://github.com/mikefarah/yq.git
fdupes https://github.com/adrianlopezroche/fdupes.git
fzf https://github.com/junegunn/fzf.git
bat https://github.com/sharkdp/bat.git
exa https://github.com/ogham/exa.git
ripgrep https://github.com/BurntSushi/ripgrep.git
fd https://github.com/sharkdp/fd.git
tmux https://github.com/tmux/tmux.git
zsh-autosuggestions https://github.com/zsh-users/zsh-autosuggestions.git
zsh-syntax-highlighting https://github.com/zsh-users/zsh-syntax-highlighting.git
# --- Your (sunnamsriram1) Repos / Requests ---
Whois_4v https://github.com/sunnamsriram1/Whois_4v.git
AdvancedOSINT https://github.com/sunnamsriram1/AdvancedOSINT.git
UserRecon https://github.com/sunnamsriram1/UserRecon.git
RANSOM_E_V6_TOOL https://github.com/sunnamsriram1/RANSOM_E_V6_TOOL.git
Ransome_eE_4v https://github.com/sunnamsriram1/Ransome_eE_4v.git
Wget https://github.com/sunnamsriram1/Wget.git
Sqlsimpl https://github.com/sunnamsriram1/Sqlsimpl.git
Sql-_scanner- https://github.com/sunnamsriram1/Sql-_scanner-.git
S https://github.com/sunnamsriram1/S.git
Sqltor5.3v https://github.com/sunnamsriram1/Sqltor5.3v.git
PB_Self-Destruct5.py https://github.com/sunnamsriram1/PB_Self-Destruct5.py.git
GeoInfo https://github.com/sunnamsriram1/GeoInfo.git
IPFind https://github.com/sunnamsriram1/IPFind.git
ip_locator_3v https://github.com/sunnamsriram1/ip_locator_3v.git
AllHashCracker_Pro_6v https://github.com/sunnamsriram1/AllHashCracker_Pro_6v.git
AutoHashCracker_Pro_3v_7 https://github.com/sunnamsriram1/AutoHashCracker_Pro_3v_7.git
PhoneInfoga7 https://github.com/sunnamsriram1/PhoneInfoga7.git
PhoneInfoga8 https://github.com/sunnamsriram1/PhoneInfoga8.git
Indialive_flight_panel_8v_7v https://github.com/sunnamsriram1/Indialive_flight_panel_8v_7v.git
webtester_clickjacking_waf_5v_Pro https://github.com/sunnamsriram1/webtester_clickjacking_waf_5v_Pro.git
# --- Extra Additions to exceed 250 ---
zaproxy https://github.com/zaproxy/zaproxy.git
burpsuite-extensions https://github.com/snoopysecurity/awesome-burp-extensions.git
wafw00f https://github.com/EnableSecurity/wafw00f.git
sqlninja https://github.com/xxgrunge/sqlninja.git
waf-tester https://github.com/EnableSecurity/wafw00f.git
arjun2 https://github.com/s0md3v/Arjun.git
jwt-tool https://github.com/ticarpi/jwt_tool.git
jwt-hack https://github.com/hahwul/jwt-hack.git
csp-analyzer https://github.com/google/csp-evaluator.git
subjs https://github.com/lc/subjs.git
dalfox-plugins https://github.com/hahwul/dalfox-plugins.git
airgeddon https://github.com/v1s1t0r1sh3r3/airgeddon.git
hashid https://github.com/psypanda/hashID.git
hash-identifier https://github.com/blackploit/hash-identifier.git
threagile https://github.com/Threagile/threagile.git
osmedeus https://github.com/j3ssie/osmedeus.git
sn1per https://github.com/1N3/Sn1per.git
xsrfprobe https://github.com/0xInfection/XSRFProbe.git
x8 https://github.com/Sh1Yo/x8.git
uro2 https://github.com/s0md3v/uro.git
param-miner https://github.com/PortSwigger/param-miner.git
CORS-Scanner https://github.com/chenjj/CORScanner.git
sqlmap-tamper https://github.com/sqlmapproject/sqlmap/tree/master/tamper
jwtcat https://github.com/aress31/jwtcat.git
ferret https://github.com/Michaelbaltazar/ferret.git
hakrevdns https://github.com/hakluke/hakrevdns.git
puredns-resolvers https://github.com/TruffleSecurity/TruffleHog.git
trufflehog https://github.com/trufflesecurity/trufflehog.git
gitleaks https://github.com/gitleaks/gitleaks.git
git-secrets https://github.com/awslabs/git-secrets.git
aws-nuke https://github.com/rebuy-de/aws-nuke.git
shhgit https://github.com/eth0izzle/shhgit.git
gospider https://github.com/jaeles-project/gospider.git
hakcheckurl https://github.com/hakluke/hakcheckurl.git
bbrf https://github.com/honoki/bbrf-client.git
rengine https://github.com/yogeshojha/rengine.git
xray https://github.com/chaitin/xray.git
jaeles-signatures https://github.com/jaeles-project/jaeles-signatures.git
nmap-vulners https://github.com/vulnersCom/nmap-vulners.git
nmap-vscan https://github.com/vulnersCom/nmap-vscan.git
masscan https://github.com/robertdavidgraham/masscan.git
zmap https://github.com/zmap/zmap.git
zgrab2 https://github.com/zmap/zgrab2.git
rustscan https://github.com/RustScan/RustScan.git
naabu-templates https://github.com/projectdiscovery/fuzzing-templates.git
EOF

# --------- Parse & de-dup ---------
# clean comments and blank lines
mapfile -t LINES < <(printf "%s\n" "$TOOLS" | sed 's/\r$//' | grep -v '^[[:space:]]*#' | sed '/^[[:space:]]*$/d')

# Use associative array to keep first occurrence of a tool name
declare -A MAP
for line in "${LINES[@]}"; do
  name="${line%% *}"
  url="${line#* }"
  # sanitize name to avoid path issues
  name="${name//[^A-Za-z0-9_.\-]/_}"
  MAP["$name"]="$url"
done

TOTAL=${#MAP[@]}
echo "[*] Total tools to process: $TOTAL"

# --------- Clone in parallel batches ---------
# build a list and process in small parallel groups to avoid heavy load
i=0
batch=()
for name in "${!MAP[@]}"; do
  url="${MAP[$name]}"
  batch+=("$name" "$url")
  i=$((i+1))
  if (( i % PARALLEL_JOBS == 0 )); then
    # run batch
    for ((k=0; k<${#batch[@]}; k+=2)); do
      clone_one "${batch[k]}" "${batch[k+1]}" &
    done
    wait
    batch=()
  fi
done

# run leftover
if (( ${#batch[@]} > 0 )); then
  for ((k=0; k<${#batch[@]}; k+=2)); do
    clone_one "${batch[k]}" "${batch[k+1]}" &
  done
  wait
fi

echo
echo "✅ Done. All (${TOTAL}) tools processed. Saved at: $TOOLS_DIR"
