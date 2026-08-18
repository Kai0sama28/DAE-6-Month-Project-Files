---
layout: default
title: Projects
---

<div class="dae-brand">
  <img src="{{ site.branding.logo | relative_url }}" alt="{{ site.branding.logo_alt }}">
</div>

<nav class="portfolio-nav" aria-label="Portfolio navigation">
  {% for link in site.navigation %}
  <a href="{{ link.url | relative_url }}">{{ link.title }}</a>
  {% unless forloop.last %}<span aria-hidden="true"> · </span>{% endunless %}
  {% endfor %}
</nav>


# Projects

Choose **2–3 of your strongest projects** for the finished portfolio.

{% for project in site.projects %}
## {{ project.name }}

![{{ project.name }} image]({{ project.image | relative_url }})

{{ project.description }}

- **Repository:** [{{ project.repo_url }}]({{ project.repo_url }})
{% if project.demo_url != "" %}
- **Live demo:** [{{ project.demo_url }}]({{ project.demo_url }})
{% endif %}
- **What I contributed:** {{ project.contribution }}
- **Tools/technologies:** {{ project.tools }}

{% endfor %}
