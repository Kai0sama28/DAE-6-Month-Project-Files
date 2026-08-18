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

## Career Direction

**Preferred role(s):** {{ site.career_aspirations.preferred_roles }}

**Work environment:** {{ site.career_aspirations.ideal_environment }}

**Ideal job description:** {{ site.career_aspirations.ideal_job }}

**Team:** {{ site.career_aspirations.ideal_team }}

**Future goals:** {{ site.career_aspirations.future_goals }}
