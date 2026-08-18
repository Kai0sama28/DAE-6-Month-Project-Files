---
layout: default
title: Contact
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


# Contact

- **Name:** {{ site.personal_details.full_name }}
- **Email:** [{{ site.contact_info.email }}](mailto:{{ site.contact_info.email }})
- **LinkedIn:** [LinkedIn Profile]({{ site.contact_info.linkedin }})
- **GitHub:** [GitHub Profile]({{ site.contact_info.github }})

[OPTIONAL SHORT CONTACT MESSAGE]
