---
layout: index
title: Andrea Cardaci
description: MSc student at the University of Pisa, Italy.
tags: [MSc, Pisa]
---

<section>

## Bio

{% include tagify.html text=page.description tags=page.tags %}

</section>

<section>

## Contacts

[e-mail](mailto:{{ site.email }})

</section>

<section>

## Profiles

[GitHub](https://github.com/cyrus-and){:rel='me'}
: **Code** goes here

[Twitter](https://twitter.com/cyrus_and){:rel='me'}
: **Social** stuff

[LinkedIn](https://www.linkedin.com/in/AndreaCardaci){:rel='me'}
: **Professional** profile

[Bēhance](https://www.behance.net/AndreaCardaci){:rel='me'}
: My attempt at **photography**

</section>

{% if site.categories.advisories != null %}

<section>

## Advisories

{% for post in site.categories.advisories %}
{% if post.url %}

{% assign title = post.title | split: ' — ' %}

{% assign brief = title | last %}
{% capture brief %}{% include tagify.html text=brief tags=post.tags %}{% endcapture %}

[{{ title | first }} — {{ post.date | date: '%Y-%m-%d' }}]({{ post.url }})
: {{ brief | strip_newlines }}

{% endif %}
{% endfor %}

</section>

{% endif %}

<section>

## Projects

[gdb-dashboard](https://github.com/cyrus-and/gdb-dashboard)
: Modular visual interface for **GDB** in **Python**

[chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface)
: **Chrome Debugging Protocol** interface for **Node.js**

[chrome-har-capturer](https://github.com/cyrus-and/chrome-har-capturer)
: Capture **HAR** files from a remote **Chrome** instance

[prof](https://github.com/cyrus-and/prof)
: Self-contained **C/C++ profiler** library for **Linux**

[mysql-unsha1](https://github.com/cyrus-and/mysql-unsha1)
: Authenticate against a **MySQL** server without knowing the cleartext **password**

[zoom](https://github.com/cyrus-and/zoom)
: Fixed and **automatic** balanced window layout for **Emacs**

[gproxy](https://github.com/cyrus-and/gproxy)
: **googleusercontent.com** as HTTP(S) **proxy**

[trace](https://github.com/cyrus-and/trace)
: Start or attach to a process and **monitor** a customizable set of **metrics**

[zizzania](https://github.com/cyrus-and/zizzania)
: Automated **DeAuth** attack

[gdb](https://github.com/cyrus-and/gdb)
: Go **GDB/MI** interface

[httpfs](https://github.com/cyrus-and/httpfs)
: Remote **FUSE** filesystem via **server-side** script

</section>
