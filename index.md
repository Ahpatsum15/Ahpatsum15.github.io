---
# index.md
layout: default
title: Home
---

<!-- ======================================================================== -->
<!-- MODERN HERO SECTION                                                      -->
<!-- ======================================================================== -->
<div class="hero-section">
  <div class="hero-avatar-wrapper">
    <img src="{{ '/assets/images/profile.jpg' | relative_url }}" alt="Mustapha El Bouazaoui" class="hero-avatar">
    <div class="avatar-badge-icon" title="Doctoral Researcher & Cybersecurity Engineer">🔐</div>
  </div>

  <div class="hero-body">
    <div class="hero-status-pill">
      <span class="badge-pill badge-primary">🎯 PhD Researcher @ UM6P · 🛡️ Cybersecurity Freelance Consultant</span>
    </div>

    <h1 class="hero-title">
      Hi, I'm <span class="gradient-text">Mustapha El Bouazaoui</span>
    </h1>

    <p class="hero-subtitle">
      Information Theory Doctoral Researcher &amp; Cybersecurity Engineer
    </p>

    <p class="hero-bio">
      Doctoral researcher at <strong>UM6P College of Computing</strong> investigating <em>Secrecy Capacity and Coding for Noisy Quantum Wiretap Channels</em>. Graduate of <strong>IMT Atlantique</strong> in Cybersecurity &amp; Telecommunications. I combine deep mathematical theory with offensive and defensive cybersecurity engineering, available for <strong>freelance security assessments, penetration testing, and DevSecOps consulting</strong>.
    </p>

    <div class="hero-highlights-bar">
      <span class="highlight-chip">🎓 PhD Candidate @ UM6P</span>
      <span class="highlight-chip">🛡️ IMT Atlantique Alum</span>
      <span class="highlight-chip">🎯 Certified Jr Pentester</span>
      <span class="highlight-chip">🔬 Quantum Information &amp; Crypto</span>
    </div>

    <div class="hero-cta-group">
      <a href="{{ '/projects/' | relative_url }}" class="btn btn-primary">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
          <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
        </svg>
        Projects &amp; Freelancing
      </a>

      <a href="{{ '/blog/' | relative_url }}" class="btn btn-secondary">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
          <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
        </svg>
        PhD Research Notes
      </a>

      <a href="{{ site.cv_url | relative_url }}" class="btn btn-outline" target="_blank">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
          <polyline points="7 10 12 15 17 10"></polyline>
          <line x1="12" y1="15" x2="12" y2="3"></line>
        </svg>
        Download CV
      </a>
    </div>
  </div>
</div>

<!-- ======================================================================== -->
<!-- FREELANCE SERVICES HIGHLIGHT BANNER                                      -->
<!-- ======================================================================== -->
<div class="freelance-banner-box">
  <div class="banner-content">
    <div class="banner-text">
      <div class="badge-pill badge-cyber" style="margin-bottom: 0.5rem;">💼 Freelance Services</div>
      <h3>Need Freelance Cybersecurity Consulting or Pentesting?</h3>
      <p>Available for web/API penetration testing, external attack surface monitoring, automated vulnerability management, and SIEM detection engineering (Microsoft Sentinel / KQL).</p>
      <div class="banner-skills-list">
        <span class="badge-pill">Web &amp; API Pentest</span>
        <span class="badge-pill">Attack Surface OSINT</span>
        <span class="badge-pill">Sentinel SIEM Rules</span>
        <span class="badge-pill">PKI / Cryptography</span>
      </div>
    </div>
    <div class="banner-cta">
      <a href="{{ '/projects/' | relative_url }}" class="btn btn-cyber">View Services &amp; Rates &rarr;</a>
    </div>
  </div>
</div>

<!-- ======================================================================== -->
<!-- FEATURED PROJECTS SECTION                                                -->
<!-- ======================================================================== -->
<div class="section-header">
  <div class="section-tag badge-pill badge-primary">Featured Work</div>
  <h2 class="section-title">Highlighted Projects &amp; Research</h2>
  <p class="section-subtitle">A curated selection of freelance deliverables, security platforms, and academic research.</p>
</div>

<div class="project-grid">
  {% for project in site.data.projects %}
    {% if project.featured %}
      <div class="project-card" data-category="{{ project.category }}">
        <div class="card-top">
          <div class="card-badges">
            <span class="card-category">{{ project.category_display }}</span>
            <span class="badge-pill {{ project.badge_class }}">{{ project.status }}</span>
          </div>
          <h3 class="card-title">
            {% if project.url %}
              <a href="{{ project.url | relative_url }}" {% if project.url contains 'http' %}target="_blank" rel="noopener"{% endif %}>
                {{ project.name }}
              </a>
            {% else %}
              {{ project.name }}
            {% endif %}
          </h3>
          <p class="card-desc">{{ project.description }}</p>

          {% if project.highlights %}
            <ul class="card-highlights">
              {% for item in project.highlights limit:2 %}
                <li>{{ item }}</li>
              {% endfor %}
            </ul>
          {% endif %}
        </div>

        <div class="card-bottom">
          {% if project.tags %}
            <div class="card-tags">
              {% for tag in project.tags limit:3 %}
                <span class="tag-pill-mini">{{ tag }}</span>
              {% endfor %}
            </div>
          {% endif %}

          {% if project.url %}
            <div class="card-footer">
              <a href="{{ project.url | relative_url }}" class="card-link" {% if project.url contains 'http' %}target="_blank" rel="noopener"{% endif %}>
                {{ project.link_text | default: "Learn More →" }}
              </a>
            </div>
          {% endif %}
        </div>
      </div>
    {% endif %}
  {% endfor %}
</div>

<div style="text-align: center; margin-bottom: 3.5rem;">
  <a href="{{ '/projects/' | relative_url }}" class="btn btn-outline">
    View All Projects &amp; Freelance Case Studies &rarr;
  </a>
</div>

<!-- ======================================================================== -->
<!-- LATEST ARTICLES & PHD NOTES                                              -->
<!-- ======================================================================== -->
<div class="section-header">
  <div class="section-tag badge-pill badge-quantum">Writings &amp; Notes</div>
  <h2 class="section-title">Latest Articles &amp; PhD Notes</h2>
  <p class="section-subtitle">Deep dives on Information Theory, DevSecOps, and Machine Learning.</p>
</div>

<div class="article-cards-list">
  {% for post in site.posts limit:3 %}
    <article class="article-card">
      <div class="card-top">
        <div class="article-meta">
          <span>{{ post.date | date: "%B %-d, %Y" }}</span>
          <span>•</span>
          {% if post.categories contains "information-theory" %}
            <span class="badge-pill badge-quantum">PhD Research</span>
          {% elsif post.categories contains "devops" %}
            <span class="badge-pill badge-cyber">DevSecOps</span>
          {% else %}
            <span class="badge-pill badge-ml">Machine Learning</span>
          {% endif %}
        </div>
        <h3 class="article-title">
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        </h3>
        <p class="article-excerpt">
          {{ post.excerpt | strip_html | truncatewords: 30 }}
        </p>
      </div>

      <div class="card-bottom">
        <div class="article-footer">
          <a href="{{ post.url | relative_url }}" class="card-link">Read Article &rarr;</a>
        </div>
      </div>
    </article>
  {% endfor %}
</div>

<div style="text-align: center; margin-top: 1rem;">
  <a href="{{ '/blog/' | relative_url }}" class="btn btn-outline">
    Browse All Articles &amp; Research Series &rarr;
  </a>
</div>
