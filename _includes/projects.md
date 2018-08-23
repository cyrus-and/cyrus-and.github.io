<div class="section">

## Projects

{% for project in site.data.projects %}
{% capture brief %}{% include tagify.liquid text=project.brief tags=project.tags %}{% endcapture %}
[{{ project.name }}](https://github.com/{{ project.link }})
: {{ brief | strip_newlines }}
{% endfor %}

</div>
