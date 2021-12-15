# Videos
- [What do you need to know about the log4j (Log4Shell) vulnerability?](https://www.youtube.com/watch?v=oC2PZB5D3Ys) (First 15 min detail offensive side pretty well)
- [CVE-2021-44228 - Log4j - MINECRAFT VULNERABLE! (and SO MUCH MORE)](https://www.youtube.com/watch?v=7qoPDq41xhQ)
- [Quick demo by @MalwareTechBlog](https://www.youtube.com/watch?v=0-abhd-CLwQ)
- [Log4Shell, The Worst Java Vulnerability in Years](https://www.youtube.com/watch?v=m_AkCbFc8DM)

# Technical analysis
- [Log4j Analysis: More JNDI Injection](https://y4y.space/2021/12/10/log4j-analysis-more-jndi-injection/)
- [Rapid7 analysis](https://attackerkb.com/topics/in9sPR2Bzt/cve-2021-44228-log4shell/rapid7-analysis): Includes PoCs for Apache Struts2, VMWare VCenter, Apache James, Apache Solr, Apache Druid, Apache JSPWiki and Apache OFBiz

# Advisories
- [Apache Log4j Security Vulnerabilities](https://logging.apache.org/log4j/2.x/security.html)

# Intentionally vulnerable apps
- [PentesterLab challenge](https://pentesterlab.com/exercises/log4j_rce/course)
- [BugHuntr.io scenario](https://twitter.com/BugHuntrIo/status/1469298538593067012)
- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)

# Tools to detect and exploit
- [Thinkst Canary](https://twitter.com/thinkstcanary/status/1469439743905697797)
- [Huntress Log4Shell Tester](https://log4shell.huntress.com)
- [log4shell.nse](https://github.com/righel/log4shell_nse): Nmap NSE script that injects a Huntress/CanaryTokens/custom log4shell payload in HTTP requests described by JSON templates. Results expire after 30 minutes.
- [@SilentSignalHU’s Log4Shell Scanner as a Burp extension](https://twitter.com/Burp_Suite/status/1470418532475314177) & [silentsignal/burp-log4shell](https://github.com/silentsignal/burp-log4shell) (Burp extension)
- [Log4Shell detection to ActiveScan++](https://twitter.com/albinowax/status/1469258291616403457)
- [fullhunt/log4j-scan](https://github.com/fullhunt/log4j-scan)
- [Burp Bounty Pro Profile](https://twitter.com/BurpBounty/status/1469249786092085249)
- [whwlsfb/Log4j2Scan](https://github.com/whwlsfb/Log4j2Scan) (Passive Scanner plugin for Burp)
- [Semgrep rules](https://github.com/returntocorp/semgrep-rules/tree/develop/java/log4j/security)
- [CodeQL query](https://github.com/cldrn/codeql-queries/blob/master/log4j-injection.ql)
  - <https://twitter.com/pwntester/status/1469307027067396106>
