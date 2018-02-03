<div class="section">

## Profiles

{% for profile in site.data.profiles %}
{% capture brief %}{% include tagify.liquid text=profile.brief tags=profile.tags %}{% endcapture %}
[{{ profile.name }}]({{ profile.url }}){:rel='me'}
: {{ brief | strip_newlines }}
{% endfor %}

</div>
