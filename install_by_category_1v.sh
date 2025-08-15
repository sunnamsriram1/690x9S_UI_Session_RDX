#!/data/data/com.termux/files/usr/bin/bash
# install_by_category.sh - Termux friendly

echo "[*] Preparing Termux environment..."
pkg update -y && pkg upgrade -y

# Correct package names for Termux
pkg install -y python rust gawk git curl wget unzip zip tar

# Example: GitHub tools installation
echo "[*] Installing tools from GitHub..."
tools_dir="$HOME/S_TOOLS"
mkdir -p "$tools_dir"
cd "$tools_dir" || exit

# Sample GitHub repo list
repos=(
    "https://github.com/sqlmapproject/sqlmap.git"
    "https://github.com/htr-tech/zphisher.git"
    "https://github.com/TheSpeedX/TBomb.git"


# 1) Information Gathering
#Information_Gathering=
    "https://github.com/nmap/nmap.git"
    "https://github.com/lanmaster53/recon-ng.git"
    "https://github.com/laramies/theHarvester.git"
    "https://github.com/i3visio/osrframework.git"
    "https://github.com/owasp-amass/amass.git"
    "https://github.com/aboul3la/Sublist3r.git"
    "https://github.com/findomain/findomain.git"
    "https://github.com/tomnomnom/assetfinder.git"
    "https://github.com/projectdiscovery/subfinder.git"
    "https://github.com/projectdiscovery/dnsx.git"
    "https://github.com/d3mondev/puredns.git"
    "https://github.com/blechschmidt/massdns.git"
    "https://github.com/darkoperator/dnsrecon.git"
    "https://github.com/fwaeytens/dnsenum.git"
    "https://github.com/projectdiscovery/shuffledns.git"
    "https://github.com/projectdiscovery/httpx.git"
    "https://github.com/tomnomnom/httprobe.git"
    "https://github.com/hakluke/hakrawler.git"
    "https://github.com/projectdiscovery/katana.git"
    "https://github.com/lc/gau.git"
    "https://github.com/tomnomnom/waybackurls.git"
    "https://github.com/tomnomnom/unfurl.git"
    "https://github.com/tomnomnom/qsreplace.git"
    "https://github.com/tomnomnom/hacks.git"
    "https://github.com/xnl-h4ck3r/xnLinkFinder.git"
    "https://github.com/GerbenJavado/LinkFinder.git"
    "https://github.com/devanshbatham/ParamSpider.git"
    "https://github.com/003random/getJS.git"
    "https://github.com/arthaud/git-dumper.git"
    "https://github.com/hisxo/gitGraber.git"
    "https://github.com/tillson/git-hound.git"
    "https://github.com/trufflesecurity/trufflehog.git"
    "https://github.com/gitleaks/gitleaks.git"
    "https://github.com/initstring/cloud_enum.git"
    "https://github.com/ghostlulzhacks/bucketscanner.git"
    "https://github.com/Tuhinshubhra/CMSeeK.git"
    "https://github.com/urbanadventurer/WhatWeb.git"
    "https://github.com/wappalyzer/wappalyzer.git"
    "https://github.com/UnaPibaGeek/ctfr.git"
    "https://github.com/s0md3v/Photon.git"
    "https://github.com/smicallef/spiderfoot.git"
    "https://github.com/michenriksen/aquatone.git"
    "https://github.com/sa7mon/nrich.git"
    "https://github.com/projectdiscovery/tlsx.git"
    "https://github.com/projectdiscovery/mapcidr.git"
    "https://github.com/sherlock-project/sherlock.git"
    "https://github.com/soxoj/maigret.git"
    "https://github.com/megadose/holehe.git"
    "https://github.com/mxrch/GHunt.git"
    "https://github.com/twintproject/twint.git"
    "https://github.com/JustAnotherArchivist/snscrape.git"
    "https://github.com/Datalux/Osintgram.git"
    "https://github.com/laramies/metagoofil.git"
    "https://github.com/instaloader/instaloader.git"
    "https://github.com/maldevel/EmailHarvester.git"
    "https://github.com/sundowndev/PhoneInfoga.git"
    "https://github.com/m4ll0k/Infoga.git"
    "https://github.com/guelfoweb/knock.git"


# 2) Vulnerability Analysis
#Vulnerability_Analysis=(
    "https://github.com/projectdiscovery/nuclei.git":
    "https://github.com/projectdiscovery/nuclei-templates.git":
    "https://github.com/hahwul/dalfox.git":
    "https://github.com/s0md3v/XSStrike.git":
    "https://github.com/dwisiswant0/crlfuzz.git":
    "https://github.com/s0md3v/Corsy.git":
    "https://github.com/epinna/tplmap.git":
    "https://github.com/assetnote/kiterunner.git":
    "https://github.com/ffuf/ffuf.git":
    "https://github.com/OJ/gobuster.git":
    "https://github.com/epi052/feroxbuster.git":
    "https://github.com/maurosoria/dirsearch.git":
    "https://github.com/xmendez/wfuzz.git":
    "https://github.com/sullo/nikto.git":
    "https://github.com/wpscanteam/wpscan.git":
    "https://github.com/Dionach/CMSmap.git":
    "https://github.com/chenjj/CORScanner.git":
    "https://github.com/defparam/smuggler.git":
    "https://github.com/anshumanpattnaik/http-request-smuggler.git":
    "https://github.com/edoardottt/cariddi.git": 
    "https://github.com/jaeles-project/jaeles.git":
    "https://github.com/jaeles-project/jaeles-signatures.git":
    "https://github.com/EnableSecurity/wafw00f.git":
    "https://github.com/3nock/wordpress-user-enum.git":
    "https://github.com/vladko312/SSTImap.git":
    "https://github.com/swisskyrepo/SSRFmap.git":


# 3) Web Application Analysis
#Web_Application_Analysis=(
    "https://github.com/sqlmapproject/sqlmap.git":
    "https://github.com/commixproject/commix.git":
    "https://github.com/epinna/tplmap.git":
    "https://github.com/ticarpi/jwt_tool.git":
    "https://github.com/hahwul/jwt-hack.git":
    "https://github.com/tomnomnom/qsreplace.git":
    "https://github.com/tomnomnom/hacks.git":
    "https://github.com/s0md3v/uro.git":
    "https://github.com/Sh1Yo/x8.git":
    "https://github.com/PortSwigger/param-miner.git":
    "https://github.com/snoopysecurity/awesome-burp-extensions.git":
    "https://github.com/zaproxy/zaproxy.git":


# 4) Database Assessment
#Database_Assessment=(
    "https://github.com/ron190/jsql-injection.git"
    "https://github.com/codingo/NoSQLMap.git"
    "https://github.com/xxgrunge/sqlninja.git"


# 5) Password Attacks
#Password_Attacks=(
    "https://github.com/hashcat/hashcat.git":
    "https://github.com/openwall/john.git":
    "https://github.com/vanhauser-thc/thc-hydra.git":
    "https://github.com/nmap/ncrack.git":
    "https://github.com/jmk-foofus/medusa.git":
    "https://github.com/digininja/CeWL.git":
    "https://github.com/crunchsec/crunch.git":
    "https://github.com/digininja/RSMangler.git":
    "https://github.com/hashcat/princeprocessor.git":
    "https://github.com/hashcat/hashcat-utils.git":
    "https://github.com/danielmiessler/SecLists.git":
    "https://github.com/six2dez/OneListForAll.git":
    "https://github.com/assetnote/commonspeak2-wordlists.git":


# 6) Wireless Attacks
#Wireless_Attacks=(
    "https://github.com/aircrack-ng/aircrack-ng.git":
    "https://github.com/derv82/wifite2.git":
    "https://github.com/t6x/reaver-wps-fork-t6x.git":
    "https://github.com/aanarchyy/bully.git":
    "https://github.com/aircrack-ng/mdk4.git":
    "https://github.com/ZerBea/hcxdumptool.git":
    "https://github.com/ZerBea/hcxtools.git":
    "https://github.com/joswr1ght/cowpatty.git":
    "https://github.com/kismetwireless/kismet.git":
    "https://github.com/bettercap/bettercap.git":
    "https://github.com/v1s1t0r1sh3r3/airgeddon.git":


# 7) Reverse Engineering
#Reverse_Engineering=(
    "https://github.com/NationalSecurityAgency/ghidra.git":
    "https://github.com/radareorg/radare2.git":
    "https://github.com/rizinorg/rizin.git":
    "https://github.com/rizinorg/cutter.git":
    "https://github.com/angr/angr.git":
    "https://github.com/iBotPeaches/Apktool.git": 
    "https://github.com/skylot/jadx.git":
    "https://github.com/frida/frida.git":
    "https://github.com/sensepost/objection.git":


# 8) Exploitation Tools
#Exploitation_Tools=(
    "https://github.com/rapid7/metasploit-framework.git"
    "https://github.com/offensive-security/exploitdb.git"
    "https://github.com/threat9/routersploit.git"
    "https://github.com/epinna/weevely3.git"
    "https://github.com/0dayCTF/reverse-shell-generator.git"
    "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    "https://github.com/calebstewart/pwncat.git"
    "https://github.com/chunkingz/linset.git"


# 9) Sniffing & Spoofing
#Sniffing_Spoofing=(
    "https://github.com/Ettercap/ettercap.git"
    "https://github.com/mitmproxy/mitmproxy.git"
    "https://github.com/lgandx/Responder.git"
    "https://github.com/bettercap/caplets.git"
    "https://gitlab.com/wireshark/wireshark.git"


# 10) Post Exploitation
#Post_Exploitation=(
    "https://github.com/carlospolop/PEASS-ng.git"
    "https://github.com/DominicBreuker/pspy.git"
    "https://github.com/mzet-/linux-exploit-suggester.git"
    "https://github.com/jondonas/linux-exploit-suggester-2.git"
    "https://github.com/rebootuser/LinEnum.git"
    "https://github.com/GTFOBins/GTFOBins.github.io.git"
    "https://github.com/liamg/traitor.git"
    "https://github.com/Anon-Exploiter/SUID3NUM.git"
    "https://github.com/gentilkiwi/mimikatz.git"
    "https://github.com/fortra/impacket.git"
    "https://github.com/Porchetta-Industries/CrackMapExec.git"
    "https://github.com/BloodHoundAD/BloodHound.git"
    "https://github.com/fox-it/BloodHound.py.git"
    "https://github.com/ropnop/kerbrute.git"
    "https://github.com/GhostPack/Rubeus.git"
    "https://github.com/BloodHoundAD/SharpHound.git"
    "https://github.com/PowerShellMafia/PowerSploit.git"
    "https://github.com/BC-SECURITY/Empire.git"


# 11) Forensics
#Forensics=(
    "https://github.com/volatilityfoundation/volatility3.git"
    "https://github.com/volatilityfoundation/volatility.git"
    "https://github.com/sleuthkit/sleuthkit.git"
    "https://github.com/sleuthkit/autopsy.git"
    "https://github.com/ReFirmLabs/binwalk.git"
    "https://github.com/korczis/foremost.git"
    "https://github.com/simsong/bulk_extractor.git"
    "https://github.com/DidierStevens/DidierStevensSuite.git"
    "https://github.com/jesparza/peepdf.git"
    "https://github.com/exiftool/exiftool.git"
    "https://github.com/StefanoDeVuono/steghide.git"
    "https://github.com/RickdeJager/stegseek.git"
    "https://github.com/zed-0xff/zsteg.git"
    "https://github.com/VirusTotal/yara.git"
    "https://github.com/Yara-Rules/rules.git"


# 12) Reporting Tools
#Reporting_Tools=(
    "https://github.com/dradis/dradis-ce.git"
    "https://github.com/infobyte/faraday.git"
    "https://github.com/SerpicoProject/Serpico.git"
    "https://github.com/pwndoc/pwndoc.git"


# 13) Social Engineering
#Social_Engineering=(
    "https://github.com/trustedsec/social-engineer-toolkit.git"
    "https://github.com/htr-tech/zphisher.git"
    "https://github.com/UndeadSec/SocialFish.git"
    "https://github.com/iinc0gnit0/BlackPhish.git"
    "https://github.com/Ignitetch/AdvPhishing.git"


# 14) Bug Bounty Suite (extra 50+)
#Bug_Bounty=(
    "https://github.com/projectdiscovery/notify.git"
    "https://github.com/projectdiscovery/interactsh.git"
    "https://github.com/projectdiscovery/proxify.git"
    "https://github.com/projectdiscovery/uncover.git"
    "https://github.com/vortexau/dnsvalidator.git"
    "https://github.com/nahamsec/lazyrecon.git"
    "https://github.com/nahamsec/bbht.git"
    "https://github.com/jaeles-project/gospider.git"
    "https://github.com/hakluke/hakcheckurl.git"
    "https://github.com/honoki/bbrf-client.git"
    "https://github.com/yogeshojha/rengine.git"
    "https://github.com/chaitin/xray.git"
    "https://github.com/vulnersCom/nmap-vulners.git"
    "https://github.com/vulnersCom/nmap-vscan.git"
    "https://github.com/robertdavidgraham/masscan.git"
    "https://github.com/zmap/zmap.git"
    "https://github.com/zmap/zgrab2.git"
    "https://github.com/RustScan/RustScan.git"
    "https://github.com/projectdiscovery/tlsx.git"
    "https://github.com/projectdiscovery/mapcidr.git"


# 15) Cloud / Container / IaC
#Cloud_Container_IaC=(
    "https://github.com/prowler-cloud/prowler.git"
    "https://github.com/nccgroup/ScoutSuite.git"
    "https://github.com/0xsha/cloudbrute.git"
    "https://github.com/aquasecurity/trivy.git"
    "https://github.com/anchore/grype.git"
    "https://github.com/anchore/syft.git"
    "https://github.com/aquasecurity/tfsec.git"
    "https://github.com/Checkmarx/kics.git"
    "https://github.com/aquasecurity/kube-hunter.git"
    "https://github.com/Shopify/kubeaudit.git"
    "https://github.com/kubescape/kubescape.git"
    "https://github.com/goodwithtech/dockle.git"
    "https://github.com/rebuy-de/aws-nuke.git"


# 16) Your Custom (sunnamsriram1) — as requested
#Sunnam_Custom=(
    "https://github.com/sunnamsriram1/Whois_4v.git"
    "https://github.com/sunnamsriram1/AdvancedOSINT.git"
    "https://github.com/sunnamsriram1/UserRecon.git"
    "https://github.com/sunnamsriram1/RANSOM_E_V6_TOOL.git"
    "https://github.com/sunnamsriram1/Ransome_eE_4v.git"
    "https://github.com/sunnamsriram1/Wget.git"
    "https://github.com/sunnamsriram1/Sqlsimpl.git"
    "https://github.com/sunnamsriram1/Sql-_scanner-.git"
    "https://github.com/sunnamsriram1/S.git"
    "https://github.com/sunnamsriram1/Sqltor5.3v.git"
    "https://github.com/sunnamsriram1/PB_Self-Destruct5.py.git"
    "https://github.com/sunnamsriram1/GeoInfo.git" 
    "https://github.com/sunnamsriram1/IPFind.git"
    "https://github.com/sunnamsriram1/ip_locator_3v.git"
    "https://github.com/sunnamsriram1/AllHashCracker_Pro_6v.git"
    "https://github.com/sunnamsriram1/AutoHashCracker_Pro_3v_7.git"
    "https://github.com/sunnamsriram1/PhoneInfoga7.git"
    "https://github.com/sunnamsriram1/PhoneInfoga8.git"
    "https://github.com/sunnamsriram1/Indialive_flight_panel_8v_7v.git"
    "https://github.com/sunnamsriram1/webtester_clickjacking_waf_5v_Pro.git"




)

for repo in "${repos[@]}"; do
    name=$(basename "$repo" .git)
    if [ -d "$name" ]; then
        echo "[*] $name already exists, skipping..."
    else
        git clone "$repo"
    fi
done

echo "[*] All tools installed successfully!"
