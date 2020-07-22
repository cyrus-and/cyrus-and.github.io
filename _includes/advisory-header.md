{:#advisory-header}
|                |                                                          |
|---------------:|----------------------------------------------------------|
| **Discovered** | {{ page.advisory.discovered}}                            |
|     **Author** | [{{ site.author.name }}](mailto:{{ site.author.email }}) |
|    **Product** | {{ page.advisory.product }}                              |
{% for version in page.advisory.versions %}
{%- if forloop.first -%}
| **Tested versions** | {{ version }} |
{%- else %}
|| {{ version }} |
{%- endif -%}
{% endfor %}
{% for cve in page.advisory.cve %}
{%- if forloop.first -%}
| **CVE** | [{{ cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve }}) |
{%- else %}
|| [{{ cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ cve }}) |
{%- endif -%}
{% endfor %}
