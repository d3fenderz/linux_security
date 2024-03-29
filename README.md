# Linux Security

![GitHub last commit](https://img.shields.io/github/last-commit/d3fenderz/linux_security?label=last%20update%3A)

## Transparency

I'm a senior DEV, a cybersec enthusiast and writer, and a very bad sysadmin on my free time. Everything you will read here is documented.

I'm not trying to speak with authority, but I will show you how to hack **and** defend your machine or a server. Linux is fantastic but not inherently secure. It does not mean package managers and update cycles are not great.

Security requires knowledge and time. Regardless of your level of experience, it's easy to fail. Nobody's perfect.

Let's review the basics and mitigate classic attacks.

## Some Linux myths

### Linux is more secure than ***

This sentence is problematic, as it does not tackle the problem correctly. While there are way more CVEs and exploits associated with Windows, for example, it's usually related to specific programs and apps that do not run on Linux natively.

Then, it would be interesting to count all the vulnerabilities that have been fixed vs. those that remain unpatched.

However, the comparison between the two OSes does not make sense, to me. If you're a threat actor you probably want to spread your malware everywhere and target the most popular OS. If you need to target your victims more specifically or to attack Cloud infrastructures, you can build Linux malware, as well.

Thanks to modern programming languages, it's easier to generate cross-platform scripts.

It depends on the goals.

Last but not least, unpatched or misconfigured Linux machines are vulnerable.

### Default configurations are enough

Just no.

### The market share is ridiculous, so it's not a target

It might look very small if you only consider the end-users, a.k.a. the casual users, but it's used everywhere in reality:

* IoT devices
* Cloud-based architectures
* Cars
* Military infrastructures
* Servers
* Systems that drive critical tasks such as Air Traffic Control
* public clouds

Many other devices rely on Linux distributions and do not always bother with encryption, software patches, and other security measures, making them attractive targets to reach other instances.

### Linux is open-source, so all bugs are addressed quickly

Open-source brings trustworthiness and auditability, which is undeniably beneficial for users, especially if you care about privacy, but it does not mean all security holes are fixed _automagically_.

[Pwnkit](https://github.com/berdav/CVE-2021-4034) has finally been patched after more than 12 years of active exploitation and affect all modern Linux distributions. This memory corruption is particularly easy to exploit on vulnerable machines.

### I'm invicible with my distro for hackers

Some people seem to believe installing Kali Linux or one the numerous alternative Linux distributions for hackers and security researchers is enough to be incognito or keep attackers away.

It's definitely not the case. For instance, it does not mask your real IP and need to be configured correctly. Don't get that false impression of security that can lead you to very bad outcomes.

## Linux distributions vs. Desktops vs. package managers

A Linux distribution, or "distro," is an OS that contains the Linux kernel and a package manager. For example, Ubuntu, one of the most popular distros, is a Debian-based OS that relies on `dpkg` to manage the packages in the system. `APT` is the interface that provides command lines to search, install, update, remove, or list packages in Debian-based distros.

However, Linux has literally hundreds of distros, and many other associated package managers. For example, Arch Linux uses [pacman](https://wiki.archlinux.org/title/Pacman), which has a very different approach of release cycles and dependency management.

While the most popular distros are pretty-well maintained and many people give their time to patch others, some remain unpatched and others get simply abandoned.

The Desktop environment is the graphical user interface (GUI). There are popular desktops, such as KDE, Gnome, or Mate, but many flavors and derivative solutions exist as well. The Desktop is not only for the look and feel, and usually provides specific functionalities. You don't get the same catalog with KDE and Gnome, for example, and some programs may not be compatible with all Desks.

Once you have installed your favorite distro, it's possible to change the default Desktop.

## Linux essentials for hackers

You can [start with the Fundamental Manual](https://man7.org/tlpi/index.html) if you're motivated.

Otherwise, and even if there are tons of other great resources, I appreciate the series by [HackerSploit](https://www.youtube.com/watch?v=T0Db6dVYyoA): very concise.

It's not exhaustive, but it's a great synthesis.

I've also read [this book](https://a.co/d/3Hfp7S9) and [this other one](https://a.co/d/dqmntNz)

## Installing Linux for cybersecurity

Of course, [Kali Linux](https://www.kali.org/) is a fantastic distro to create your own lab. If you don't need all tools and you are a beginner, you might want to install a Debian-based distro or Debian itself instead. You can use my repos [godebian](https://github.com/d3fenderz/godebian) to install a few packages.

I would also recommend a virtual machine to isolate your environment.

Only attack machines that you own or with explicit authorization. Otherwise, you'll take the path of cybercriminals, and good luck.

## Attacking Linux

### Disclaimer

There are so many attacks that it's impossible to list them all. Here is a quick overview.

### Linux malware

[2020 set a record for new Linux malware families](https://www.intezer.com/blog/cloud-security/2020-set-record-for-new-linux-malware-families/) and it keeps increasing.

These are mostly targeted campaigns, but it shows that threat actors will target any system if that's necessary. Besides, Linux servers are everywhere and power most websites and applications, not to mention cloud infrastructures.

The other major trend is the rise of cryptominers. Because mining cryptocurrencies requires heavy CPU utilization, threat actors like to distribute the load to unsuspecting victims.

Cybercriminals use specific rootkits to hide these processes on the targeted machines/servers. Otherwise, it would be detected quickly. It does not prevent the performance issues, so the victims know something is wrong, but it's pretty hard to identify the exact processes involved.

If you don't find it, you can't remove it easily.

### Why Linux internals are so important

I strongly encourage you to study Linux internals in details, like what is a process, the difference between processes, threads, and jobs, or what is the Linux Kernel and how user mode programs call it. It's not in the guide, as it cannot be done quickly, IMHO. 

Without this knowledge, you cannot understand memory corruption, kernel exploits, buffer overflows, and other low-level interactions correctly, IMHO.

The ultimate goal of these attacks is usually to gain unauthorized access to privileged processes, perhaps root privileges.

### Kernel exploits

You may have read names like "DirtyCow" or "DirtyPipes." These are kernel exploits that are actively exploited by cybercriminals on unpatched machines.

A very quick and efficient way to exploit the kernel is to use [automatic scanners](#enumerate-like-an-attacker). If you want to do it manually, you can start by checking the current version of the kernel with one of these commands:

```
uname -r
hostnamectl | grep Kernel
```

Then, it's not very complicated to relate it with a known exploit, as many CVEs have public POCs (proof of concept). A list of vulnerable kernel versions and exploits can be found [here](https://github.com/lucyoa/kernel-exploits).

You can also check dedicated platforms, if the most recent ones are not listed.

It should be noted that kernel protection has been improved over the past years, which mitigates what an attacker can do and might even eliminate old exploits. Still, there are CVEs associated with the Linux kernel in 2023.

### Memory corruption

Hacking memory is often rewarding. Some credentials may appear in clear text, and you can even gain root privileges in the best-case scenario. Linux has special directories such as `/proc/` and `/dev/mem` that exposes memory processes, for example.

To understand how it works, read about virtual memory (~ extended memory with hard disk) vs. physical memory (~ RAM).

Pwnkit, a popular Linux kit for memory corruption, allows root access with an unprivileged account. The bug has been known for years (12), but the patch is relatively recent (at the time of writing).

Don't panic, though. Memory protection has also improved, sometimes making classic attacks impossible in real-world conditions.

The bad news is that most documented POCs are outdated (~ patched).

However, you may google terms like [buffer overflow](https://www.cloudflare.com/learning/security/threats/buffer-overflow/) or [Heartbleed](https://xkcd.com/1354/) for practical examples.

### Privilege escalation

[Read HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

Bookmark [GTFOBins](https://gtfobins.github.io/).

### Evasion

Read [HackerSploit Red Team Series - Evasion](https://www.linode.com/docs/guides/linux-defense-evasion-hiding-linux-processes/).

### Persistence

One of the multiple benefits of evasion can be persistence, which means you can stabilize a RCE (Remote Code Execution) or exfiltrate information despite counter-measures.

Attackers can achieve that in various ways, such as modifiying the targeted OS configuration, injecting payloads in memory, or even using the filesystem. Each approach has its cons:

* config updates can be detected
* memory injections are harder to detect but die with the session
* the filesystem leaves tracks
* many persistence mechanisms require admin privileges 

Check [HackerSploit Red Team Series - Persistence](https://www.linode.com/docs/guides/linux-red-team-persistence-techniques/) for practical examples and further explanations.

### Physical attack: the recovery abuse

Misknown hacking method on Linux that relies on the single user mode:

#### Context and disclaimer

This part has some limitations, especially with recent hardware that offers interesting security features, like additional authentication.

I'm totally aware that when an attacker has access to the machine it's hard to completely secure it, but this easy method should be more documented, IMHO.

#### Quick steps to bypass Linux login

1. reboot and press `shift` just after to start the GRUB menu
2. select "Advanced options for Ubuntu"
3. select a version that contains "(recovery mode)"
4. select the root console or shell prompt in the recovery menu
5. type `id` in the console to see check if you're root, but if you see something similar to `root@pc`, it's done
6. navigate to the folder of your choice, as you have now the highest privileges

#### High probablity

While this scenario won't work all the time, it's highly probable, to me, especially if you consider an average user and a classic installation. Not everybody will change root password, encrypt the disk, or monitor such modifications, as the `sudo` command allows to perform most administrative tasks.

Besides, Ubuntu provides a graphical interface to handle all operations, for example, update and maintenance.

#### Mitigation

Even if the first one should be enough for this particular case, you may combine all tips for better security:

* Do not only consider the `/home`, use full disk encryption
* Set admin password in the BIOS
* Set user password in the BIOS and require it during the boot

#### Don't touch the GRUB

After some tests, I don't recommend setting a GRUB password or removing the GRUB rescue anymore.

While it's possible and might work in your case, it's the most hacky approach and not the most efficient one. There's a significant risk to mess up the booting sequence, which can be hard to recover.

In another perspective, dual boot configurations are bad from a security perspective.

## Inspecting Linux

### Manual inspection

#### Useful commands

```
# basic OS information
uname -a # all info
uname -r # only the kernel version

# get info about the filesystem and mounted devices 
df -h

# scroll in the file that contain all users
less -r /etc/passwd

# scroll in the file that contain all encrypted passwords
sudo less -r /etc/shadow

# who is currently logged in?
w -huis

# something suspicious in recent connections?
last -Fw

# network info and ports
lsof -i TCP # show TCP activity
lsof -i4 # ipv4 activity
lsof -i6 # ipv6 activity
lsof -i -n # open connections
netstat -ano

# inspect processes
ps aux
ps aux | grep root # pipe to search a specific term

# Inspect history
ls -alh $HOME/.*history
less -r $HOME/.bash_history

# /var/log
# auth.log*
# syslog*
# kern.log

# files opened using SSH
sudo lsof -r -i :22

# journal
journalctl -S -4h
```

#### Cheat sheet

Learn additional commands in [the Blue Sheet](https://github.com/d3fenderz/blue_sheet)

#### Quick Todo list inspection

* check file and folder permissions: this is critical, especially for dotfiles and system binaries
* check the sudo config (e.g., available commands for sudoers), `/etc/passwd`, and `/etc/shadow`
* check mounted drives
* check the `$PATH`
* check the CRON jobs (e.g., commands containing wildcards)
* use `tcpdump` to sniff the traffic or more advanced networking tools
* check the `~/.ssh/` directory

### Memory Inspection

The big caveat with tools is that it does not teach you how to analyze memory correctly and where to look. Besides, OSS (Open-Source Security) can be tricky, especially with abandoned or deprecated projects. Still, tools are important, and you have to know some, at least.

Memory inspection can be hard. One of the most popular tool to analyze memory dumps is [Volatility](https://github.com/volatilityfoundation/volatility/wiki/Linux).

You might also appreciate [Volshell](https://volatility3.readthedocs.io/en/latest/volshell.html).

I also like the `smem` utility. It's a very light command-line memory tool that can generate various reports on memory usage on a Linux system.

### Automate Inspection

#### Enumerate like an attacker

Why not using CTF tools to spot vulnerabilities?

* [Lynis](https://github.com/CISOfy/lynis)
* [Linux Exploit Suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)
* [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

#### Network utilities

These free programs can ease network inspection significantly:

* [htop](https://htop.dev/)
* [nethogs](https://github.com/raboof/nethogs)
* [nagios](https://www.nagios.org/)
* [tcpflow](https://github.com/simsong/tcpflow)
* [tcpreplay](https://github.com/appneta/tcpreplay)
* iftop
* [netfilter & iptables](https://www.netfilter.org/)

### 7 Forensic resources to go further

* [LinuxForensics](https://linuxdfir.ashemery.com/): Everything related to Linux Forensics
* [Practical Linux Forensics](https://a.co/d/gs1bxga)
* [The art of Memory Forensics (cross-platform)](https://a.co/d/8GN7pTI)
* [A Linux Forensics Starter Case Study](https://www.forensicfocus.com/articles/a-linux-forensics-starter-case-study/)
* [Linux and disk forensics](https://resources.infosecinstitute.com/topic/linux-and-disk-forensics/)
* [Count Upon Security: Intro To Linux Forensics](https://countuponsecurity.com/2017/04/12/intro-to-linux-forensics/)
* [TryHackMe: Linux Server Forensics](https://tryhackme.com/room/linuxserverforensics)

## Hardening Linux

### Manual hardening

#### Quick Todo list to secure your machine

In my experience, Linux requires manual hardening. You may apply the following for basic security hygiene:

* use full disk encryption, not just for your ~/home folder
* disable any telemetry (e.g., disable system reports, don’t send crash reports) and file history if you don’t need them, which is likely
* disable wireless connections if you don’t need them (e.g., Bluetooth, WiFi)
* get rid of useless services (e.g., in privacy settings) and packages, and close unused ports
* cover your camera
* lock down the desktop, but also the BIOS (e.g., set administrator password)
* consider moving to SELinux

#### FDE (Full Disk Encryption)

Depending on your hardware, disk encryption will not be the same. For example, it may allow you to encrypt the `/home` folder only, which is a good start, but full disk encryption is better.

While it's a bit more constraining, as you need to provide a key to unlock your machine every time you start/restart (before the login/password), it's compatible with UEFI Secure Boot and TPM 2.0, at least in Ubuntu 20.04.

If it's available, enable it during install. It's possible to do it afterwards, but it's a bit more technical. LUKS & LVM can do that. More advanced users may appreciate this [reencrypt](https://manpages.ubuntu.com/manpages/trusty/man8/cryptsetup-reencrypt.8.html) package, but backup your data before anything.

#### About Secure Boot

The `Secure boot` option in the BIOS can be beneficial, but it's important to understand what it does. The goal is to prove authenticity and integrity (it verifies signatures). To protect your data from potential thefts, you need **encryption**.

However, disabling it, for example, dual boot configurations, is not recommended, as you extend the surface.

### Automate hardening & monitoring

Depending on the context, you will need additional resources. Manual inspection and quick todo lists won't be enough to catch highly-evasive and targeted attacks in a corporate environment.

Note that using tools does not guarantee anything, as these solutions will likely focus on compliance. Still, connecting a SIEM to your logs and programming custom alerts can help spot anomalous activities and mitigate further operations.

This guide is not meant to fight against advanced adversaries. Sometimes, there's no mitigation. However, it's not a valid reason to be nihilist. Lock everything you can while keeping the system usable.

### Protect your Network

#### Filter and monitor outgoing traffic

It's easy to understand why incoming traffic must be filtered, perhaps entirely blocked depending on your usage. One of the easiest ways to do that is to enable the Uncomplicated Firewall (ufw) and deny incoming traffic.

However, you should not neglect outgoing traffic. While it's a bit more constraining to configure, there's no reason to allow all ports on out.

#### Use a VPN

It's indeed not specific to Linux, but many solutions on the market are compatible with _the Penguin_. Because I'd like keep this guide agnostic, I'm not recommending a particular one, but you may use OpenVPN, as a large range of providers will provide ready-to-use configuration files and an interface for it.

On Debian-based distros, you can start with the following command:

```
sudo apt install -y openvpn bridge-utils
```

However, it's usually more efficient to follow the instructions provided by your client/provider. In any case, manual installations from scratch are documented.

Using a VPN is recommended to mitigate packet sniffing, improve privacy, or simply circumvent geo-blocking.

#### Why people keep disabling IPv6

In very short, IPv6 solves the following problem: the number of IPv4 addresses available is limited. The number of IPv6 addresses is exponentially larger (~ 10<sup>28</sup> for IPv6 against "a few" billions for IPv4)

There are many other features and improvements, and the notation is not the same, but we won't see that here.

Most of the time, people disable it because it's still not supported everywhere. Some VPNs and ISPs just don't support it, for example. So [if it's unavailable](https://ipv6-test.com/) for you, disable it:

```
echo 'net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1' | sudo tee /etc/sysctl.d/10-disable-ipv6.conf
sudo sysctl -p
```

[Source: PrivSec](https://privsec.dev/posts/linux/protonvpn-ip-leakage-on-linux-and-workaround/#general-linux-distributions)

To learn more about IPv6 and its advantages, you can read [this guide by the NSA](https://media.defense.gov/2023/Jan/18/2003145994/-1/-1/0/CSI_IPV6_SECURITY_GUIDANCE.PDF).

## Introduction to Linux servers

### Why

Websites and applications are hosted on servers that run Linux distributions (not always), which means these machines must be secured.

Pretty much the same commands and recommendations will apply, but you will likely have to take additional measures.

### Basic security

* update and upgrade packages
* remove unused packages (`dpkg --list`)
* disable root login (`PermitRootLogin no` in `/etc/ssh/sshd_conf`)
* applu least privileges on users and groups
* check and disable useless startup processes (see `systemd`)
* check and disable useless services (`systemctl list-unit-files --type=service`)
* have a tested backup/recovery strategy (manual or scheduled backups on the same server is not recommended)
* turn on and configure `iptables` (firewall)
* close useless ports (`sudo ss -tulnp | grep LISTEN`, then you can block them with firewall rules)
* disable unused services (`chkconfig {SERVICE} off`)

### SELinux

SE Linux can be an interesting additional layer. Be careful, though, as it's not an ordinary package and will deny access to anything that is not explicitly allowed. Ensure you don't exclude yourself from the server, which may happen to beginners in some cases.

Such approach is called a MAC system (Mandatory Access Control). The idea is to isolate privileged processes and ease security policy setup.

Here's how to install it on Debian-based machines in enforce mode:

```
sudo systemctl stop apparmor
sudo apt purge -y apparmor
sudo apt install -y selinux-basics selinux-policy-default auditd
sudo selinux-activate
sudo systemctl enable auditd
sudo setenforce 1 # 0 is for permissive mode
cat /etc/selinux/config 
sudo reboot
sudo sestatus
```

We remove AppArmor because the two packages have similar purposes: isolation.

Unlike the Enforcing mode, the Permissive mode does not block denied operations, but it logs them, for example, in `/var/log/audit/audit.log`.

## 7 links to go further

Here are useful links to go further:

* [Intezer - Not Another Linux Security Blog](https://www.intezer.com/blog/cloud-security/not-another-linux-security-blog/)
* [Linux security and system hardening checklist](https://linuxsecurity.expert/checklists/linux-security-and-system-hardening)
* [NSA - Linux hardening](https://github.com/shaurya-007/NSA-Linux-Hardening-docs)
* [Hacktricks - Linux privilege escalation](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)
* [Linux Kernel](https://www.kernel.org/doc/html/latest/)
* [PayloadsAllTheThings - Linux Privesc](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
* [Detecting Linux memfd_create()](https://sandflysecurity.com/blog/detecting-linux-memfd-create-fileless-malware-with-command-line-forensics/)
