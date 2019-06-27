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
{%- if page.advisory.cve %}
| **CVE entry** | [{{ page.advisory.cve }}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={{ page.advisory.cve }}) |
{%- endif %}
{:#advisory-header}
