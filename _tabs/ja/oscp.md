---
# the default layout is 'page'
title: "OSCP+の旅 (OSCP+ Journey)"
layout: post
icon: fas fa-solid fa-dragon
date: 2025-01-01 00:45:00 +0900
toc: true
#description: "My journey of obtaining one of the most sort after certifications in the field of Cyber Security, the OSCP+."
order: 6
lang: ja
---

## どのようにしてOSCP+をMetasploitを使わずに合格されたのですか？

![OSCP+ Badge](/assets/img/oscp/oscp-2.png){: .center }
_OSCP+_

>過程を信じて頑張り続けること。
{: .prompt-info }

Thank you for stopping by to read about my experience with the OSCP+ exam. Whether you're here as an aspiring penetration tester, a seasoned professional, or someone simply curious about what this journey entails, I’m thrilled to share my insights with you.

The OSCP+ exam is more than just a test; it’s a challenge that pushes you to your limits, builds your resilience, and deepens your understanding of cybersecurity concepts. In this post, I’ll walk you through the highs and lows, the lessons learned, and the resources that helped me navigate this rigorous assessment.

>Trust the process and keep trying harder...
{: .prompt-info }

### OSCP+ Exam Structure

- 3 stand-alone machines (60 points in total)
  - 20 points per machine
    - 10 points for initial access
    - 10 points for privilege escalation

- 1 Active Directory (AD) set containing 3 machines (40 points in total)
  - Assumed Breach Scenario
    - 10 points for machine #1
    - 10 points for machine #2
    - 20 points for machine #3

### Before purchasing the OSCP+ module

Before purchasing the OSCP+ course, I haven’t done any other Cyber Security related certifications. I had little to no knowledge about penetration testing or ethical hacking. I only had little experience on solving online CTF problems and have studied some Networking concepts. I was a Data Analyst before, so you can all judge how much technical experience I would have had.  

I have been reading about other people’s OSCP exam experience and watched videos after videos of how people failed on their first, second and even their third attempt, before finally passing it. People who have passed the exam kept giving different advice which further increased my fear. Being a newcomer to the field of Cyber Security, these videos and blogs kept me from taking this challenge. 

But on June 2024, I thought that I can’t be able to concretely know about something that I personally haven’t tried. So, I decided in order to overcome the fears all I had to do was to accept the challenge.

So, I purchased the course on July 2024.

#### Initial Phase - The first month

Everything was going good. I was going through page after page of the exceptionally written ~800-page OSCP module. Lot of new things.

But, it all became overwhelming near the end of the first month. Learning new tools and commands just by seeing the examples given in the module weren’t enough for me to get a full understanding. I thought this might be because I have no prior knowledge or experience in the field of Cyber Security. The modules progressed and at the end of the first month, I decided to try a few ‘EASY’ difficulty boxes at Hack The Box. To no surprise, I wasn’t even able to decide on what to do first. I saw the writeups and was still unable to make head or tails out of it.

I was close to giving up.

Now, that I have purchased the course and already a month into it, I didn’t want my investment and time to go in vain. So, I googled further and found that many others were facing similar difficulties as mine. And one of the suggestions led me to the Practical Ethical Hacking Course by TCM Security.

My god was I saved! Heath Adams has made an exceptional job in creating that course.

#### PEH by TCM Security - The second month

To no offense of any sort intended, I found the videos given in the OSCP module are nowhere (to use the GEN-Z term) “vibe” with it. The videos had a very strong disconnect between the video demonstration and the voice over. The voice over was scripted and unnatural. Maybe the videos were not for me.

That is where PEH by TCM Security excels in. While watching these videos, it felt like someone was sitting next to me and explaining things as they do. Heath would just talk through the concept explanation and also solve a box on Tryhackme relating to that topic. He would make mistakes along the way; we can hear him giving out small tips & tricks about the tools; his practical experience etc., It felt very NATURAL! 

So, during my second month I completely stopped progressing on the OSCP modules and completed the PEH videos. I skipped a few labs here and there. Following along with Heath gave me an idea of what a Penetration Methodology should look like.

At the end of the second month, I went back to the OSCP modules and was better able to relate the tools and concepts mentioned with what I have practiced during the PEH videos. I felt myself progressing.

#### OSCP Challenge labs - The third month

I was in my final month of my access to the OSCP modules. I decided to concentrate mainly on Active Directory. PEH videos and the OSCP modules helped me get a good grasp of the Active Directory Penetration testing concepts.

Now, I was at a point where I was confidently able to enumerate the easy boxes on Hack The Box. But still needed to read the writeups to understand the vulnerability. I was learning and progressing with every box I solve.

I had to start the challenge labs as well because my access was ending soon. So, I completed the OSCP modules and started solving the Challenge labs one by one.With the occasional hints and help from the Discord chat of OffSec, I was able to solve all the challenge labs except SKYLARK.

By now, I had created some sort of methodology to go about solving these practice labs. I further used Tib3rius’s Linux Priv Esc and Windows Priv Esc courses. And along with the third month, my access to the OSCP module labs came to an end.


#### HTB and PG Practice labs - The fourth month

This was the most exciting month.

Thanks to TJ Null, I practiced the OSCP-like boxes that he was listed in this google sheets. I kind of had a hunch that doing Proving Grounds Practice boxes would be more similar to the OSCP exam. But I equally gave importance to the HTB boxes as well.

>Stay tuned for Capture the Flag writeups!
{: .prompt-tip }

I had finally found my rhythm. Solving CTF challenges in both HTB and PG Practice gave me a better understanding of the concepts and it also allowed me to create my own penetration testing methodology.

With all my notes gathered, I was ready to face the ultimate challenge – The OSCP+ exam.


## Importance of Note-taking

What is this methodology that I keep talking about? How can I create one?

Well the answer is CREATING YOUR OWN NOTES.

### Obsidian

In order to create your own notes, you need a note taking app that suits you. Mine was Obsidian. I am sure there are other note-taking tools out there which might suit you. All you have got to do is try whichever works for you.

Obsidian is a simply fantastic note taking tool which allows markdown format. It took sometime to getting used to the syntax. But once you got used to it, there is no going back.

### Notes Structure (sample)

I can share how I structured my notes so that it might help some of you.

#### Active Directory
- Enumeration
  - Automated (bloodhound etc.,)
  - Manual (PowerView etc.,)
- Attacks
  - Kerberos attack (AS-REP roasting, Kerberoasting etc.,)
  - Password Spray (crackmapexec, netexec etc.,)
- Lateral Movement
  - Pass the Hash
  - Over Pass the Hash
  - etc.,
- Persistence
  - Silve Ticket
  - Golden Ticket

#### Linux & Windows
- Enumeration
  - Common Ports
    - 21 - FTP
    - 22 - SSH
    - 25 - SMTP
    - etc., (30 more common ports)
  - Busting
    - Directory Busting
    - Sub-domain hunting
  - Website Penetration Testing
    - Directory Traversal
    - LFI
    - RFI
    - SQL injection (SQL syntax etc.,)
    - API
    - etc.,
- Initial Foothold
  - Brute Forcing (ssh, smb etc.,)
  - Phishing Attacks (MS Office macros)
  - Public Exploits
    - Compiling an exploit
    - List of other CVEs that I had encountered in practice
- Port Forwarding
  - SSH Tunnelling (Local, remote etc.,)
  - HTTP Tunnelling (chisel)
  - LIGOLO-NG
- Password Cracking
  - hashcat
  - johntheripper
- Privilege Escalation
  - Linux
    - Users & Groups
    - Network
    - File Search
    - Cron jobs
    - Services
    - Kernel exploits
    - etc.,
  - Windows
    - Users & Groups
    - File Search
    - Network
    - Password & NTLM
    - Privilege Attacks (SeBackupPrivilege, SeImpersonatePrivilege etc.,)
    - Token Impersonation (Potato Attacks)
    - Services
    - etc.,
- Reverse Shells
  - Linux
    - php reverse shell
    - python
    - nc, bash etc.,
  - Windows
    - powershell
    - msfvenom etc.,
- File Transfers (nc, evil-winrm, curl, wget, ssh etc.,)

There are many topics that I might have missed here, but this might give you a general idea for you to create your own notes and organize them in a way that you would prefer.

The best advice anybody would ever give is, keep reviewing your notes again and again that you feel at one with your notes. Life saver!

>Always remember there is no one right way to do things.
{: .prompt-info }

## OSCP+ Exam Experience

I had received many requests on my linkedin to share my exam experience. So, here it goes. Make sure to read it till the end to know what I did wrong that you can do right.

### Exam start : 11:30 AM

There was six IP addresses that were given to me in the exam portal. You can easily guess the AD set just by seeing the IP addresses given. But I confirmed it by performing a nmap scan as well.

I solved machine #1 of the AD set. Took me around one and a half hours to do it. Then, I setup my `ligolo-ng` to perform port forward to jump to machine #2 and #3. But I received a message from my proctor that they are patching my AD set. Thus, I got a time extension of 3 hours. So, 24 hours became 27 hours for me. I was ecstatic.

Therefore, I moved to solve the standalone machines. The first standalone was a linux machine and was able to solve it in around 2 hours. Luckily, I had already dealt with the service running on the box during my practice sessions. My notes came in handy. Without them I would have wasted more time on that machine. My points total was 30. I need 40 more points to pass the exam.

But then, I wasn't able to solve the standalone machine #2 and #3. I did find some leaked passwords and the services where it should be used. For some reason I wasn't able to get a shell. Totally 13 hours gone and I was still stuck with 30 points. I did the port scanning again. There were other rabbit holes as well. I dived into the rabbit hole desparately looking for ways to get the initial foothold. I hit deadend after deadend.

That's when I suddenly remembered seeing this in 0xdf's or ippsec's solves and started hunting for that. Finally found the culprit that was keeping me from getting the shell. It was a syntax mistake. I felt like a total idiot. I had every information needed to get the shell, but I didn't follow the right syntax. So, I got the initial foothold on standalone machine #2. Privilege Escalation took surprisingly less time. Points total was now 50.

I had the leaked password for the standalone machine #3 but didn't know a way to get the username. I tried bruteforcing it desaparately, but it didn't work. The mistake I did here was completely ignoring a tab on my kali terminal. I had run a command and while waiting for it to run, I had moved to do some other enumeration and had forgotten about the command running in the ignored tab. Maybe its the exam pressure that got to me? Thus, with the output of the command I got shell. After the initial foothold, the privilege escalation took just five minutes. So, my total points is 70 (machine #1 in AD set = 10 points + all 3 standalone machines = 60 points). I had already gotten enough points to pass the exam!

But, I still had 12 hours left in the total exam time. I also wanted to PWN the AD set as well. So, I set off to solve the AD set and did so in another 2 hours. I had done it! I had solved all the exam machines in 17 hours.

I took frequent short breaks during the 17 hours. As I solved the boxes, I took notes of the commands I used and the output screenshots as much as possible. There was some left. But since I had been at it for 17 hours, I was feeling very tired and went to take a long break.

### PWNED all the machines, but...

Disaster struck! I had 5 hours left for the exam time to come to an end. I needed to have the screenshots and the commands saved in my notes to prepare my report. I spent nearly 3 hours in the standalone machine by taking notes and rechecking if everything works as per my notes.

The disaster was when I reached the AD set. I had saved the NTLM hash of administrator of machine #1 in AD set. After that the proctor told there was a system that is going to be done on the AD set. So, after the patch, I directly used the administrator hash to moved on the solve machine #2 and #3 of the AD set.

But when I was trying to retrieve the NTLM hash of the administrator again from the machine #1, I wasn't able to do it. Nothing worked from my notes. The machine got patched and got changed. So, I had the hash but had no evidence of reproducing it. Points will be allocated only if the steps we present in the report can be reproduced. I had only 1 hour left in the exam time. The stress got to me! I feared what if because of this one issue my whole AD set will not be allocated any points. With just the standalones I only had 60 points. 10 points less for the pass.

It was very tense. But I somehow calmed myself down and found the command that worked. Saved the screenshots. I had only the final two minutes left for crosschecking everything. I prayed that I should have enough evidence to be put into the report. And the time ended...

### Finally...

After going from ecstatic to stressed, the first 24 hours (27 hours for me) got over. It is report writing time.

I used the standard report template given by OffSec in their website. I had changed the template in a format that I will be using in the exam. I completed writing my report. Cross checked everything thrice. I was ready to submit it.

Disaster struck again! Remember I told I had gotten a 3-hour extension? It was totally 27 hours for me (from 11:30AM to next day 14:30). But the portal where we need to submit the report showed that I had exceeded the time limit given to me and won't be able to submit the report. Thus, my exam will not be graded. WHAT???

But in reality, I accessed the portal at 13:00 to submit my report. There should be one and a half hours of time left as per the time extension they gave me right? So, I contacted the issue through a mail at once to OffSec. But there didn't seem to be any immediate response. PANIC again!

Then, I went to the live chat support which can be used by candidates during the exam. There a kind-hearted person solved this issue for me. As I was withing the time limit, he enabled the portal again for me to submit the report. WHEW!!!

Finally, done...

Hope nobody else faces this in their exam. But if someone does, please be patient and contact the OffSec exam support. They were truly the life-savers.

## Resources

1. <a href="https://www.offsec.com/courses/pen-200/" target="_blank">PEN-200 modules & Challenge labs</a>
2. <a href="https://academy.tcm-sec.com/p/practical-ethical-hacking-the-complete-course" target="_blank">Practical Ethical Hacking by TCM Security</a>
3. <a href="https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview" target="_blank">TJ Null's list</a>
4. <a href="https://0xdf.gitlab.io/" target="_blank">0xdf's blog</a>
5. <a href="https://www.youtube.com/@ippsec" target="_blank">ippsec's youtube channel</a>
6. <a href="https://ippsec.rocks/?#" target="_blank">ippsec's reference search</a>
7. <a href="https://youtube.com/playlist?list=PLJrSyRNlZ2EeqkJa12Tu-Ezun9kXvHufN&si=ljKYjOgPyMduWmcE" target="_blank">S!REN's youtube channel</a>
8.  <a href="https://www.udemy.com/course/windows-privilege-escalation/?srsltid=AfmBOoovTXqjQ-L7LhFSSZtS4s5aLt9TncdwSE9gNJjGpKLnTaQDu0kx" target="_blank">Tib3rius - Windows Privilege Escalation for OSCP & Beyond!</a>
9.  <a href="https://www.udemy.com/course/linux-privilege-escalation/" target="_blank">Tib3rius - Linux Privilege Escalation for OSCP & Beyond!</a>
10. Last but not the least - my own notes
