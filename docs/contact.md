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

<a class="btn-resume" href="{{ site.contact_info.resume | relative_url }}" target="_blank" rel="noopener">Download Resume (PDF)</a>

<div class="qr-card">
  <img src="{{ site.qr_code.image | relative_url }}" alt="QR code with contact info">
  <p>{{ site.qr_code.caption }} — it saves my name, email, LinkedIn, and GitHub straight to your contacts.</p>
</div>

I'm actively looking for SOC analyst and IT helpdesk opportunities — feel free to reach out about roles, feedback on my labs, or just to connect.
