---
title: HTB - Boardlight
date: 2025-01-01 17:30:00 +0900
categories: [Hack The Box, Linux]
tags: [htb-boardlight, hackthebox, nmap, wfuzz, dolibarr, cve-2023-30253, ssh, mysql, linpeas, cve-2022-37706]     # TAG names should always be lowercase
published: true
lang: en
---

## Boardlight

BoardLight is an easy difficulty Linux machine that features a Dolibarr instance vulnerable to CVE-2023-30253.

![BoardLight](/assets/img/posts/htb-boardlight/BoardLight.png){: .center }
_BoardLight Machine info card_

### Machine info table

| Difficulty          | Easy     |
| OS               | Linux    |
| Released Date | 26 May 2024 |
| Machine State | Retired |

### Synopsis
Blah

## nmap Port scanning
As always, starting with `nmap` port scan.

### TCP scan

Finding the open TCP ports.

```bash
tcp_ports=$(nmap -p- --min-rate 10000 $IP | grep '^[0-9]' |  cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```
```bash
echo $tcp_ports
```
Performing a service scan on the open ports.

```bash
nmap -p$tcp_ports -Pn -sCV $IP
```

![nmap](/assets/img/posts/htb-boardlight/boardlight-1.png){: .center }

### UDP scan

I always make sure to scan the UDP ports as well. Usually I will let the scan run and continue with enumeration.

```bash
udp_ports=$(nmap -p- -sU --min-rate 10000 $IP | grep '^[0-9]' |  cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```

```bash
echo $udp_ports
```
There weren't any open UDP ports.

## 