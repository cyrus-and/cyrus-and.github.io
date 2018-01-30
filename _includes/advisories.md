{% if site.categories.advisories %}

<section>

## Advisories

{% for post in site.categories.advisories %}
{% if post.url %}

{% assign title = post.title | split: ' — ' %}

{% assign brief = title | last %}
{% capture brief %}{% include tagify.liquid text=brief tags=post.tags %}{% endcapture %}

[{{ title | first }} — {{ post.date | date: '%Y-%m-%d' }}]({{ post.url }})
: {{ brief | strip_newlines }}

{% endif %}
{% endfor %}

</section>

{% endif %}
