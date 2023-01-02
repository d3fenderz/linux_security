# Linux recovery abuse

Misknown hacking method on Linux that relies on the single user mode and ways to protect 🧢

## Introduction

I've been testing many Linux configurations, mostly thanks to virtual machines, and I was shocked by various security traps along the way. It's super easy to mess up your configuration completely and get a false impression of security, which is probably the worst-case scenario.

As Intezer puts it, "Linux environments are just as vulnerable as any other environment." It might be even worse, as users may not resist the temptation to install sensitive software and run whatever script found on Internet without knowing what it does.

What I don't like in Linux is that it shifts the responsibility to the end-user. It does not mean this free open-source operating system is not great, but depending on the distro (Linux has hundreds of distributions and flavors) you have installed, you won't get the same security features, and you'd better know how to configure it correctly.

Linux has various vulnerabilities, like kernel exploits and multiple local privilege escalations that are documented on Internet. In all of these flaws, there is one that is not particularly technical. The recovery mode can allow an attacker with physical access to get root access, despite other security measures.

## Context and disclaimer

This guide has some limitations, especially with recent hardware that offers interesting security features, like additional authentication.

I've tested it on several machines, a couple of weeks ago. Most of these machines had default configurations and the Linux distro was Ubuntu. There are so many existing documentations about Ubuntu security. Hopefully, this short README has a different approach.

Please open an issue if you spot something weird.

I'm totally aware that when an attacker has access to the machine it's hard to completely secure it, but this easy method should be more documented, IMHO.

## Quick steps to bypass Linux login

1. reboot and press `shift` just after to start the GRUB menu
2. select "Advanced options for Ubuntu"
3. select a version that contains "(recovery mode)"
4. select the root console or shell prompt in the recovery menu
5. type `id` in the console to see check if you're root, but if you see something similar to `root@pc`, it's done
6. navigate to the folder of your choice, as you have now the highest privileges

## High probablity

While this scenario won't work all the time, it's highly probable, to me, especially if you consider an average user and a classic installation. Not everybody will change root password, encrypt the disk, or monitor such modifications, as the `sudo` command allows to perform most administrative tasks.

Besides, Ubuntu provides a nice interface to handle all operations, for example, update and maintenance, from the graphical interface.

## Mitigation

Even if the first one should be enough for this particular case, you may combine all tips for better security:

* Do not only consider the `/home`, use full disk encryption
* Set admin password in the BIOS
* Set user password in the BIOS and require it during the boot

## Don't touch the GRUB

After some tests, I don't recommend setting a GRUB password or removing the GRUB rescue anymore.

While it's possible and might work in your case, it's the most hacky approach and not the most efficient one. There's a significant risk to mess up the booting sequence, which can be hard to recover.

In another perspective, dual boot configurations are also bad from a security perspective.

## 7 links for Linux security

Here are useful links to go further:

* [Intezer - Not Another Linux Security Blog](https://www.intezer.com/blog/cloud-security/not-another-linux-security-blog/)
* [Linux security and system hardening checklist](https://linuxsecurity.expert/checklists/linux-security-and-system-hardening)
* [NSA - Linux hardening](https://github.com/shaurya-007/NSA-Linux-Hardening-docs)
* [Hacktricks - Linux privilege escalation](https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist)
* [linPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
* [Lynis - security auditing for Linux](https://github.com/CISOfy/lynis)
* [Some thoughts about Linux security](https://blog.julien-maury.dev/en/snippets/linux-security-levelup/)
