### CVE Analysis 11/18/2026 ###     

At 6:30pm on Nov 16 Microsoft Defender found over 100 threats and vulerabilities after a routine scan. Of which included Malware, Exploits, Spyware and viruses. Action was taken on Nov 17th.  
After sifting through the hefty list, action was taken to remove and quarantine the known threats and vulerabilities. 
However, one exploit was very persistant, Exploit: JS/ShellCode.gen. After removing it kept triggering the alert so escalated action was necessary.

***Exploit: JS/ShellCode.gen is a java-script enabled object that does something malicious. Malicious websites and malformed PDF documents may contain JavaScript, which may try to run code without the user's consent. It's common for this detection to trigger on/in the internet cache, this might indicate that you've visited a website or webpage that tries to run code without consent.

1. The internet browser cache was cleared, all time
2. The host machine was disconnected from wi-fi to isolate it.
3. Windows Malicious Software Removal Tool was run with a full scan starting at 7:36pm Nov 17 lasting until Nov 18th 11:30am
4. The program was stagnant and identified containerfile: C:\Users\Kai\Desktop\kali-linux-2026.2-installer-amd64.iso. An iso image of kali-linux for a virtual machine, downloaded over 3 month ago.
4. Task Manager was run to determine if MSR was running, but the file was too large. The system was rebooted and the iso was manually removed.
5. A final quick scan was run in Windows Security to determine if all threats and vulerabities were removed, with results positive.

In conclusion, the result was false positive because windows scan considered the iso image of kali-linux and its capabilities as "threats", however the user was unsure if the downloaded iso was from a legitamate source or not which raised concern. 