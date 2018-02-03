<div class="section">

## Projects

{% for project in site.data.projects %}
{% capture brief %}{% include tagify.liquid text=project.brief tags=project.tags %}{% endcapture %}
[{{ project.name }}](https://github.com/cyrus-and/{{ project.name }})
: {{ brief | strip_newlines }}
{% endfor %}

</div>
