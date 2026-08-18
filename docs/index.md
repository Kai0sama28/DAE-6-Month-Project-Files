---
layout: default
title: Home
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

# {{ site.personal_details.full_name }}

**Graduation:** {{ site.personal_details.graduation_date }}

![Professional headshot]({{ site.personal_details.profile_photo | relative_url }})

## About Me

{{ site.about_me.bio_summary }}

## Career Aspirations

**Preferred role(s):** {{ site.career_aspirations.preferred_roles }}

**Ideal work environment:** {{ site.career_aspirations.ideal_environment }}

**Ideal job:** {{ site.career_aspirations.ideal_job }}

**Ideal team:** {{ site.career_aspirations.ideal_team }}

**Future goals:** {{ site.career_aspirations.future_goals }}

## Featured Projects

### [PROJECT 1 NAME]

![Project 1 image placeholder]({{ '/assets/images/project-placeholder.svg' | relative_url }})

[PROJECT 1 DESCRIPTION]

[Project repository or live demo](#)

### [PROJECT 2 NAME]

![Project 2 image placeholder]({{ '/assets/images/project-placeholder.svg' | relative_url }})

[PROJECT 2 DESCRIPTION]

[Project repository or live demo](#)

## Contact

- **Email:** {{ site.contact_info.email }}
- **LinkedIn:** [LinkedIn Profile]({{ site.contact_info.linkedin }})
- **GitHub:** [GitHub Profile]({{ site.contact_info.github }})
