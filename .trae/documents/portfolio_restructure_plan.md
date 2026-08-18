# Plan: GitHub Pages Portfolio Restructure (Centralized Config)

This plan outlines the steps to align the existing Jekyll portfolio site with the **GitHub Pages Portfolio Checklist** by centralizing the structure and content definitions in `_config.yml`.

## Summary
The objective is to reorganize the portfolio to follow the checklist's logical flow. By moving personal details, career aspirations, and project metadata into `_config.yml`, we create a clean, maintainable structure where the user can easily personalize their portfolio in one place. The Markdown files (`index.md`, `about.md`, etc.) will be refactored to use these variables.

## Current State Analysis
- The portfolio uses `jekyll-theme-hacker`.
- Existing files: `index.md`, `about.md`, `projects.md`, `contact.md`, and `_config.yml`.
- Images for branding (DAE logo) and placeholders are already in `docs/assets/images/`.
- Current pages have hardcoded placeholders, making them harder to maintain.

## Proposed Changes

### 1. Centralized Configuration (`docs/_config.yml`)
Add the following sections to `_config.yml`:
- **Personal Details**: `full_name`, `graduation_date`.
- **Career Aspirations**: `preferred_roles`, `ideal_environment`, `ideal_job`, `ideal_team`, `future_goals`.
- **About Me**: `bio_summary`, `interests_values`.
- **Contact Info**: `email`, `linkedin`, `github`.
- **Navigation**: Define the list of pages (Home, About, Projects, Contact).
- **Branding**: Path to the DAE logo.

### 2. Refactor Landing Page (`docs/index.md`)
Update to use Liquid variables from `site`:
- Display DAE logo using `site.branding.logo`.
- Use `site.personal_details.full_name` and `site.personal_details.graduation_date`.
- Include placeholders for the profile photo.
- Summarize About Me and Career Aspirations using `site.career_aspirations` and `site.about_me`.

### 3. Refactor About Page (`docs/about.md`)
- Focus on the detailed bio and career direction defined in `_config.yml`.

### 4. Refactor Projects Page (`docs/projects.md`)
- Organize the layout for projects, using placeholders that the user can later replace with their actual project data.

### 5. Refactor Contact Page (`docs/contact.md`)
- Use `site.contact_info` for all links.

### 6. Branding & Style
- Ensure the DAE logo is consistent across all pages via the centralized config.
- The `assets/css/style.scss` already handles basic responsiveness; ensure the new layout respects these styles.

## Assumptions & Decisions
- **Placeholders**: I will use clear placeholders like `[YOUR FULL NAME]` in `_config.yml`.
- **User Personalization**: The user will only need to edit `_config.yml` to update most of their portfolio details.

## Verification Steps
1. Review `_config.yml` to ensure all checklist items are accounted for.
2. Verify that `index.md`, `about.md`, `projects.md`, and `contact.md` correctly reference the new `site` variables.
3. Check navigation consistency across all pages.
