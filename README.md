# Mustapha El Bouazaoui — Academic Portfolio & Freelance Hub

Modern, interactive, and responsive portfolio website built with **Jekyll** and hosted on **GitHub Pages**.

🌐 **Live Website:** [https://Ahpatsum15.github.io](https://Ahpatsum15.github.io)

---

## 🌟 Key Features

- **Modern Glassmorphic UI:** Clean typography with Inter & JetBrains Mono, polished cards, subtle glow effects, and responsive mobile navigation.
- **Interactive Dark / Light Mode:** Instant toggle with smooth transitions and persistent theme state via `localStorage`.
- **Interactive Project Filtering:** Dynamic JavaScript filter tabs on the projects page and homepage.
- **Cybersecurity Freelancing Section:** Dedicated freelance service cards, case studies, deliverables, and high-conversion inquiry CTAs.
- **PhD Research & Information Theory Companion:** Prominent spotlight for doctoral research at UM6P College of Computing, LaTeX mathematical rendering (MathJax 3), and structured research series.
- **Updated CV Integration:** Direct download link for `CV_PhD_mustapha_el bouazaoui_updated.pdf`.
- **Fast Build & Clean Structure:** Pre-configured with zero build warnings and no deprecated supply-chain CDNs.

---

## 🛠️ How to Add Content

### 1. Adding a New Cybersecurity Freelance Project
Edit `_data/projects.yml` and add a new entry:
```yaml
- name: "Your Client / Freelance Project Name"
  category: "cybersecurity-freelance"
  category_display: "Freelance Service"
  badge_class: "badge-cyber"
  status: "Completed / Available"
  featured: true
  description: "Short summary of what you delivered for this client."
  highlights:
    - "Deliverable 1 (e.g., Penetration test report)"
    - "Deliverable 2 (e.g., Remediation roadmap)"
  tags:
    - "Penetration Testing"
    - "OWASP Top 10"
  url: "/contact/"
  link_text: "Inquire for Similar Project →"
```

### 2. Writing a New PhD Information Theory Article
Add a new markdown file in `_posts/` with the filename format `YYYY-MM-DD-short-title.md`:
```markdown
---
layout: post
title: "Your Article Title"
date: YYYY-MM-DD
categories:
  - information-theory
tags:
  - information-theory
  - phd
  - quantum-information
author: Mustapha El Bouazaoui
---

## Introduction

Your text here with inline math $C_s = \max [I(X;Y) - I(X;Z)]^+$ or display equations:

$$C_s = \frac{1}{2}\log_2\left(1 + \frac{P}{\sigma_B^2}\right)$$
```

---

## 💻 Local Development

Run from `portfolio/`:

```bash
bundle install
bundle exec jekyll serve
```

Then visit `http://127.0.0.1:4000`.
