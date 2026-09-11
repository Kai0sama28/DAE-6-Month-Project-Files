---
layout: default
title: About
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


# About Me

![Professional headshot]({{ site.personal_details.profile_photo | relative_url }})

## {{ site.personal_details.full_name }}

**Graduation:** {{ site.personal_details.graduation_date }}

{{ site.about_me.interests_values }}

<a class="btn-resume" href="{{ site.contact_info.resume | relative_url }}" target="_blank" rel="noopener">Download Resume (PDF)</a>

## Cybersecurity Growth

<div class="growth-grid">
{% for item in site.growth_highlights %}
  <div class="growth-card">
    <h3>{{ item.title }}</h3>
    <p>{{ item.detail }}</p>
  </div>
{% endfor %}
</div>

## Career Direction

**Preferred role(s):** {{ site.career_aspirations.preferred_roles }}

**Work environment:** {{ site.career_aspirations.ideal_environment }}

**Ideal job description:** {{ site.career_aspirations.ideal_job }}

**Team:** {{ site.career_aspirations.ideal_team }}

**Future goals:** {{ site.career_aspirations.future_goals }}
