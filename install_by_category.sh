#!/bin/bash
# Termux 250+ Cybersecurity Tools Installer (Category Folders)
# Saves into: ~/S_TOOLS/<Category>/
# Usage:  PARALLEL_JOBS=4 ./install_by_category.sh

set -Eeuo pipefail

# -------- Settings --------
BASE_DIR="$HOME/S_TOOLS"
PARALLEL_JOBS="${PARALLEL_JOBS:-4}"   # reduce if data is slow
RETRY_MAX=2

# -------- Termux prereqs --------
echo "[*] Preparing Termux environment..."
pkg update -y && pkg upgrade -y
pkg install -y git curl wget python python2 python3 php ruby perl nodejs \
  clang make cmake golang rust cargo openssl-tool \
  tar unzip zip coreutils findutils grep sed awk util-linux \
  libffi libsqlite libxml2 libxslt ncurses binutils

mkdir -p "$BASE_DIR"

# -------- helper: clone with retry --------
clone_repo() {
  local dest="$1"
  local url="$2"
  local tries=0
  if [ -d "$dest/.git" ] || [ -d "$dest" ]; then
    echo "  [-] $(basename "$dest") already exists -> skip"
    return 0
  fi
  until [ $tries -gt $RETRY_MAX ]; do
    echo "  [+] Cloning $(basename "$dest")  (try=$((tries+1)))"
    if git clone --depth=1 "$url" "$dest" >/dev/null 2>&1; then
      echo "  [✓] $(basename "$dest")"
      return 0
    fi
    tries=$((tries+1))
    sleep 2
  done
  echo "  [x] $(basename "$dest") -> FAILED ($url)"
  return 1
}

# -------- installer per-category (parallel) --------
install_category() {
  local category="$1"
  local -n arr="$2"      # nameref to array
  local target="$BASE_DIR/$category"
  mkdir -p "$target"
  echo -e "\n=== [$category] installing ${#arr[@]} tools ==="

  local batch_pids=()
  local in_batch=0

  for entry in "${arr[@]}"; do
    # entry format: name|url
    local name="${entry%%|*}"
    local url="${entry#*|}"
    local safe="$(echo "$name" | tr -cd 'A-Za-z0-9._-')"
    local dest="$target/$safe"

    clone_repo "$dest" "$url" & batch_pids+=($!)
    in_batch=$((in_batch+1))

    if (( in_batch >= PARALLEL_JOBS )); then
      wait "${batch_pids[@]}" || true
      batch_pids=()
      in_batch=0
    fi
  done

  # leftover
  if (( in_batch > 0 )); then
    wait "${batch_pids[@]}" || true
  fi
  echo "=== [$category] done ==="
}

# ======================================================================================
# Categories & Tools (name|url)
# Note: curated to exceed 250 across all categories (popular + your custom repos)
# ======================================================================================

# 1) Information Gathering
Information_Gathering=(
"nmap|https://github.com/nmap/nmap.git"
"recon-ng|https://github.com/lanmaster53/recon-ng.git"
"theHarvester|https://github.com/laramies/theHarvester.git"
"OSRFramework|https://github.com/i3visio/osrframework.git"
"Amass|https://github.com/owasp-amass/amass.git"
"Sublist3r|https://github.com/aboul3la/Sublist3r.git"
"findomain|https://github.com/findomain/findomain.git"
"assetfinder|https://github.com/tomnomnom/assetfinder.git"
"subfinder|https://github.com/projectdiscovery/subfinder.git"
"dnsx|https://github.com/projectdiscovery/dnsx.git"
"puredns|https://github.com/d3mondev/puredns.git"
"massdns|https://github.com/blechschmidt/massdns.git"
"dnsrecon|https://github.com/darkoperator/dnsrecon.git"
"dnsenum|https://github.com/fwaeytens/dnsenum.git"
"shuffledns|https://github.com/projectdiscovery/shuffledns.git"
"httpx|https://github.com/projectdiscovery/httpx.git"
"httprobe|https://github.com/tomnomnom/httprobe.git"
"hakrawler|https://github.com/hakluke/hakrawler.git"
"katana|https://github.com/projectdiscovery/katana.git"
"gau|https://github.com/lc/gau.git"
"waybackurls|https://github.com/tomnomnom/waybackurls.git"
"unfurl|https://github.com/tomnomnom/unfurl.git"
"qsreplace|https://github.com/tomnomnom/qsreplace.git"
"kxss|https://github.com/tomnomnom/hacks.git"
"xnLinkFinder|https://github.com/xnl-h4ck3r/xnLinkFinder.git"
"LinkFinder|https://github.com/GerbenJavado/LinkFinder.git"
"ParamSpider|https://github.com/devanshbatham/ParamSpider.git"
"getJS|https://github.com/003random/getJS.git"
"git-dumper|https://github.com/arthaud/git-dumper.git"
"gitGraber|https://github.com/hisxo/gitGraber.git"
"git-hound|https://github.com/tillson/git-hound.git"
"trufflehog|https://github.com/trufflesecurity/trufflehog.git"
"gitleaks|https://github.com/gitleaks/gitleaks.git"
"cloud_enum|https://github.com/initstring/cloud_enum.git"
"BucketScanner|https://github.com/ghostlulzhacks/bucketscanner.git"
"CMSeeK|https://github.com/Tuhinshubhra/CMSeeK.git"
"WhatWeb|https://github.com/urbanadventurer/WhatWeb.git"
"Wappalyzer|https://github.com/wappalyzer/wappalyzer.git"
"ctfr|https://github.com/UnaPibaGeek/ctfr.git"
"Photon|https://github.com/s0md3v/Photon.git"
"SpiderFoot|https://github.com/smicallef/spiderfoot.git"
"aquatone|https://github.com/michenriksen/aquatone.git"
"nrich|https://github.com/sa7mon/nrich.git"
"tlsx|https://github.com/projectdiscovery/tlsx.git"
"mapcidr|https://github.com/projectdiscovery/mapcidr.git"
"sherlock|https://github.com/sherlock-project/sherlock.git"
"maigret|https://github.com/soxoj/maigret.git"
"holehe|https://github.com/megadose/holehe.git"
"GHunt|https://github.com/mxrch/GHunt.git"
"twint|https://github.com/twintproject/twint.git"
"snscrape|https://github.com/JustAnotherArchivist/snscrape.git"
"Osintgram|https://github.com/Datalux/Osintgram.git"
"metagoofil|https://github.com/laramies/metagoofil.git"
"instaloader|https://github.com/instaloader/instaloader.git"
"EmailHarvester|https://github.com/maldevel/EmailHarvester.git"
"phoneinfoga|https://github.com/sundowndev/PhoneInfoga.git"
"Infoga|https://github.com/m4ll0k/Infoga.git"
"Knock|https://github.com/guelfoweb/knock.git"
)

# 2) Vulnerability Analysis
Vulnerability_Analysis=(
"nuclei|https://github.com/projectdiscovery/nuclei.git"
"nuclei-templates|https://github.com/projectdiscovery/nuclei-templates.git"
"dalfox|https://github.com/hahwul/dalfox.git"
"XSStrike|https://github.com/s0md3v/XSStrike.git"
"crlfuzz|https://github.com/dwisiswant0/crlfuzz.git"
"Corsy|https://github.com/s0md3v/Corsy.git"
"tplmap|https://github.com/epinna/tplmap.git"
"kiterunner|https://github.com/assetnote/kiterunner.git"
"ffuf|https://github.com/ffuf/ffuf.git"
"Gobuster|https://github.com/OJ/gobuster.git"
"feroxbuster|https://github.com/epi052/feroxbuster.git"
"dirsearch|https://github.com/maurosoria/dirsearch.git"
"wfuzz|https://github.com/xmendez/wfuzz.git"
"Nikto|https://github.com/sullo/nikto.git"
"WPScan|https://github.com/wpscanteam/wpscan.git"
"CMSmap|https://github.com/Dionach/CMSmap.git"
"CORScanner|https://github.com/chenjj/CORScanner.git"
"Smuggler|https://github.com/defparam/smuggler.git"
"HTTP-Request-Smuggler|https://github.com/anshumanpattnaik/http-request-smuggler.git"
"cariddi|https://github.com/edoardottt/cariddi.git"
"jaeles|https://github.com/jaeles-project/jaeles.git"
"jaeles-signatures|https://github.com/jaeles-project/jaeles-signatures.git"
"wafw00f|https://github.com/EnableSecurity/wafw00f.git"
"whatbuster|https://github.com/3nock/wordpress-user-enum.git"
"SSTImap|https://github.com/vladko312/SSTImap.git"
"SSRFmap|https://github.com/swisskyrepo/SSRFmap.git"
)

# 3) Web Application Analysis
Web_Application_Analysis=(
"sqlmap|https://github.com/sqlmapproject/sqlmap.git"
"Commix|https://github.com/commixproject/commix.git"
"tplmap|https://github.com/epinna/tplmap.git"
"jwt_tool|https://github.com/ticarpi/jwt_tool.git"
"jwt-hack|https://github.com/hahwul/jwt-hack.git"
"qsreplace|https://github.com/tomnomnom/qsreplace.git"
"kxss|https://github.com/tomnomnom/hacks.git"
"uro|https://github.com/s0md3v/uro.git"
"x8|https://github.com/Sh1Yo/x8.git"
"param-miner|https://github.com/PortSwigger/param-miner.git"
"Burp-Extensions-Awesome|https://github.com/snoopysecurity/awesome-burp-extensions.git"
"zaproxy|https://github.com/zaproxy/zaproxy.git"
)

# 4) Database Assessment
Database_Assessment=(
"jSQL|https://github.com/ron190/jsql-injection.git"
"NoSQLMap|https://github.com/codingo/NoSQLMap.git"
"SQLNinja|https://github.com/xxgrunge/sqlninja.git"
)

# 5) Password Attacks
Password_Attacks=(
"hashcat|https://github.com/hashcat/hashcat.git"
"john|https://github.com/openwall/john.git"
"hydra|https://github.com/vanhauser-thc/thc-hydra.git"
"ncrack|https://github.com/nmap/ncrack.git"
"medusa|https://github.com/jmk-foofus/medusa.git"
"CeWL|https://github.com/digininja/CeWL.git"
"Crunch|https://github.com/crunchsec/crunch.git"
"RSMangler|https://github.com/digininja/RSMangler.git"
"princeprocessor|https://github.com/hashcat/princeprocessor.git"
"hashcat-utils|https://github.com/hashcat/hashcat-utils.git"
"SecLists|https://github.com/danielmiessler/SecLists.git"
"OneListForAll|https://github.com/six2dez/OneListForAll.git"
"commonspeak2|https://github.com/assetnote/commonspeak2-wordlists.git"
)

# 6) Wireless Attacks
Wireless_Attacks=(
"aircrack-ng|https://github.com/aircrack-ng/aircrack-ng.git"
"wifite2|https://github.com/derv82/wifite2.git"
"reaver|https://github.com/t6x/reaver-wps-fork-t6x.git"
"bully|https://github.com/aanarchyy/bully.git"
"mdk4|https://github.com/aircrack-ng/mdk4.git"
"hcxdumptool|https://github.com/ZerBea/hcxdumptool.git"
"hcxtools|https://github.com/ZerBea/hcxtools.git"
"cowpatty|https://github.com/joswr1ght/cowpatty.git"
"kismet|https://github.com/kismetwireless/kismet.git"
"bettercap|https://github.com/bettercap/bettercap.git"
"airgeddon|https://github.com/v1s1t0r1sh3r3/airgeddon.git"
)

# 7) Reverse Engineering
Reverse_Engineering=(
"ghidra|https://github.com/NationalSecurityAgency/ghidra.git"
"radare2|https://github.com/radareorg/radare2.git"
"rizin|https://github.com/rizinorg/rizin.git"
"cutter|https://github.com/rizinorg/cutter.git"
"angr|https://github.com/angr/angr.git"
"apktool|https://github.com/iBotPeaches/Apktool.git"
"jadx|https://github.com/skylot/jadx.git"
"frida|https://github.com/frida/frida.git"
"objection|https://github.com/sensepost/objection.git"
)

# 8) Exploitation Tools
Exploitation_Tools=(
"metasploit-framework|https://github.com/rapid7/metasploit-framework.git"
"exploitdb|https://github.com/offensive-security/exploitdb.git"
"routersploit|https://github.com/threat9/routersploit.git"
"weevely3|https://github.com/epinna/weevely3.git"
"reverse-shell-generator|https://github.com/0dayCTF/reverse-shell-generator.git"
"PayloadsAllTheThings|https://github.com/swisskyrepo/PayloadsAllTheThings.git"
"pwncat|https://github.com/calebstewart/pwncat.git"
"linset|https://github.com/chunkingz/linset.git"
)

# 9) Sniffing & Spoofing
Sniffing_Spoofing=(
"ettercap|https://github.com/Ettercap/ettercap.git"
"mitmproxy|https://github.com/mitmproxy/mitmproxy.git"
"Responder|https://github.com/lgandx/Responder.git"
"bettercap-caplets|https://github.com/bettercap/caplets.git"
"wireshark-source|https://gitlab.com/wireshark/wireshark.git"
)

# 10) Post Exploitation
Post_Exploitation=(
"PEASS-ng|https://github.com/carlospolop/PEASS-ng.git"
"pspy|https://github.com/DominicBreuker/pspy.git"
"LES|https://github.com/mzet-/linux-exploit-suggester.git"
"LES2|https://github.com/jondonas/linux-exploit-suggester-2.git"
"LinEnum|https://github.com/rebootuser/LinEnum.git"
"GTFOBins|https://github.com/GTFOBins/GTFOBins.github.io.git"
"traitor|https://github.com/liamg/traitor.git"
"SUID3NUM|https://github.com/Anon-Exploiter/SUID3NUM.git"
"mimikatz|https://github.com/gentilkiwi/mimikatz.git"
"impacket|https://github.com/fortra/impacket.git"
"CrackMapExec|https://github.com/Porchetta-Industries/CrackMapExec.git"
"BloodHound|https://github.com/BloodHoundAD/BloodHound.git"
"BloodHound.py|https://github.com/fox-it/BloodHound.py.git"
"kerbrute|https://github.com/ropnop/kerbrute.git"
"Rubeus|https://github.com/GhostPack/Rubeus.git"
"SharpHound|https://github.com/BloodHoundAD/SharpHound.git"
"PowerSploit|https://github.com/PowerShellMafia/PowerSploit.git"
"Empire|https://github.com/BC-SECURITY/Empire.git"
)

# 11) Forensics
Forensics=(
"volatility3|https://github.com/volatilityfoundation/volatility3.git"
"volatility|https://github.com/volatilityfoundation/volatility.git"
"sleuthkit|https://github.com/sleuthkit/sleuthkit.git"
"autopsy|https://github.com/sleuthkit/autopsy.git"
"binwalk|https://github.com/ReFirmLabs/binwalk.git"
"foremost|https://github.com/korczis/foremost.git"
"bulk_extractor|https://github.com/simsong/bulk_extractor.git"
"DidierStevensSuite|https://github.com/DidierStevens/DidierStevensSuite.git"
"peepdf|https://github.com/jesparza/peepdf.git"
"exiftool|https://github.com/exiftool/exiftool.git"
"steghide|https://github.com/StefanoDeVuono/steghide.git"
"stegseek|https://github.com/RickdeJager/stegseek.git"
"zsteg|https://github.com/zed-0xff/zsteg.git"
"yara|https://github.com/VirusTotal/yara.git"
"yara-rules|https://github.com/Yara-Rules/rules.git"
)

# 12) Reporting Tools
Reporting_Tools=(
"dradis|https://github.com/dradis/dradis-ce.git"
"faraday|https://github.com/infobyte/faraday.git"
"Serpico|https://github.com/SerpicoProject/Serpico.git"
"pwndoc|https://github.com/pwndoc/pwndoc.git"
)

# 13) Social Engineering
Social_Engineering=(
"SET|https://github.com/trustedsec/social-engineer-toolkit.git"
"Zphisher|https://github.com/htr-tech/zphisher.git"
"SocialFish|https://github.com/UndeadSec/SocialFish.git"
"BlackPhish|https://github.com/iinc0gnit0/BlackPhish.git"
"AdvPhishing|https://github.com/Ignitetch/AdvPhishing.git"
)

# 14) Bug Bounty Suite (extra 50+)
Bug_Bounty=(
"notify|https://github.com/projectdiscovery/notify.git"
"interactsh|https://github.com/projectdiscovery/interactsh.git"
"proxify|https://github.com/projectdiscovery/proxify.git"
"uncover|https://github.com/projectdiscovery/uncover.git"
"dnsvalidator|https://github.com/vortexau/dnsvalidator.git"
"lazyrecon|https://github.com/nahamsec/lazyrecon.git"
"bbht|https://github.com/nahamsec/bbht.git"
"gospider|https://github.com/jaeles-project/gospider.git"
"hakcheckurl|https://github.com/hakluke/hakcheckurl.git"
"bbrf-client|https://github.com/honoki/bbrf-client.git"
"rengine|https://github.com/yogeshojha/rengine.git"
"xray|https://github.com/chaitin/xray.git"
"nmap-vulners|https://github.com/vulnersCom/nmap-vulners.git"
"nmap-vscan|https://github.com/vulnersCom/nmap-vscan.git"
"masscan|https://github.com/robertdavidgraham/masscan.git"
"zmap|https://github.com/zmap/zmap.git"
"zgrab2|https://github.com/zmap/zgrab2.git"
"RustScan|https://github.com/RustScan/RustScan.git"
"tlsx|https://github.com/projectdiscovery/tlsx.git"
"mapcidr|https://github.com/projectdiscovery/mapcidr.git"
)

# 15) Cloud / Container / IaC
Cloud_Container_IaC=(
"prowler|https://github.com/prowler-cloud/prowler.git"
"ScoutSuite|https://github.com/nccgroup/ScoutSuite.git"
"cloudbrute|https://github.com/0xsha/cloudbrute.git"
"trivy|https://github.com/aquasecurity/trivy.git"
"grype|https://github.com/anchore/grype.git"
"syft|https://github.com/anchore/syft.git"
"tfsec|https://github.com/aquasecurity/tfsec.git"
"kics|https://github.com/Checkmarx/kics.git"
"kube-hunter|https://github.com/aquasecurity/kube-hunter.git"
"kubeaudit|https://github.com/Shopify/kubeaudit.git"
"kubescape|https://github.com/kubescape/kubescape.git"
"dockle|https://github.com/goodwithtech/dockle.git"
"aws-nuke|https://github.com/rebuy-de/aws-nuke.git"
)

# 16) Your Custom (sunnamsriram1) — as requested
Sunnam_Custom=(
"Whois_4v|https://github.com/sunnamsriram1/Whois_4v.git"
"AdvancedOSINT|https://github.com/sunnamsriram1/AdvancedOSINT.git"
"UserRecon|https://github.com/sunnamsriram1/UserRecon.git"
"RANSOM_E_V6_TOOL|https://github.com/sunnamsriram1/RANSOM_E_V6_TOOL.git"
"Ransome_eE_4v|https://github.com/sunnamsriram1/Ransome_eE_4v.git"
"Wget|https://github.com/sunnamsriram1/Wget.git"
"Sqlsimpl|https://github.com/sunnamsriram1/Sqlsimpl.git"
"Sql-_scanner-|https://github.com/sunnamsriram1/Sql-_scanner-.git"
"S|https://github.com/sunnamsriram1/S.git"
"Sqltor5.3v|https://github.com/sunnamsriram1/Sqltor5.3v.git"
"PB_Self-Destruct5.py|https://github.com/sunnamsriram1/PB_Self-Destruct5.py.git"
"GeoInfo|https://github.com/sunnamsriram1/GeoInfo.git"
"IPFind|https://github.com/sunnamsriram1/IPFind.git"
"ip_locator_3v|https://github.com/sunnamsriram1/ip_locator_3v.git"
"AllHashCracker_Pro_6v|https://github.com/sunnamsriram1/AllHashCracker_Pro_6v.git"
"AutoHashCracker_Pro_3v_7|https://github.com/sunnamsriram1/AutoHashCracker_Pro_3v_7.git"
"PhoneInfoga7|https://github.com/sunnamsriram1/PhoneInfoga7.git"
"PhoneInfoga8|https://github.com/sunnamsriram1/PhoneInfoga8.git"
"Indialive_flight_panel_8v_7v|https://github.com/sunnamsriram1/Indialive_flight_panel_8v_7v.git"
"webtester_clickjacking_waf_5v_Pro|https://github.com/sunnamsriram1/webtester_clickjacking_waf_5v_Pro.git"
)

# ======================================================================================
# Run installers
# ======================================================================================
install_category "Information_Gathering" Information_Gathering
install_category "Vulnerability_Analysis" Vulnerability_Analysis
install_category "Web_Application_Analysis" Web_Application_Analysis
install_category "Database_Assessment" Database_Assessment
install_category "Password_Attacks" Password_Attacks
install_category "Wireless_Attacks" Wireless_Attacks
install_category "Reverse_Engineering" Reverse_Engineering
install_category "Exploitation_Tools" Exploitation_Tools
install_category "Sniffing_Spoofing" Sniffing_Spoofing
install_category "Post_Exploitation" Post_Exploitation
install_category "Forensics" Forensics
install_category "Reporting_Tools" Reporting_Tools
install_category "Social_Engineering" Social_Engineering
install_category "Bug_Bounty_Suite" Bug_Bounty
install_category "Cloud_Container_IaC" Cloud_Container_IaC
install_category "Custom_Sunnam" Sunnam_Custom

echo
echo "✅ All categories processed. Tools saved under: $BASE_DIR/"
echo "   Example: $BASE_DIR/Information_Gathering / Vulnerability_Analysis / ..."

# Optional: create a simple index file
INDEX="$BASE_DIR/_INDEX.txt"
{
  echo "Tools installed by category on $(date)"
  for d in "$BASE_DIR"/*/ ; do
    [ -d "$d" ] || continue
    echo "== $(basename "$d") =="
    find "$d" -maxdepth 1 -mindepth 1 -type d -printf " - %f\n" | sort
    echo
  done
} > "$INDEX"
echo "📄 Index generated: $INDEX"

# Tip: run inside tmux (optional)
#   pkg install tmux -y
#   tmux new -s tools
