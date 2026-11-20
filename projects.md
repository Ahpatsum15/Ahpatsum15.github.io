---
# projects.md
layout: default
title: Projects & Freelance Services
permalink: /projects/
---

<div class="page-header">
  <div class="badge-pill badge-primary">Portfolio & Freelance Hub</div>
  <h1 class="page-title">Projects & Freelance Services</h1>
  <p class="page-subtitle">Showcasing offensive/defensive cybersecurity projects, enterprise freelance consulting, doctoral research in Information Theory, and engineering tools.</p>
</div>

<!-- ======================================================================== -->
<!-- FREELANCE SERVICES SHOWCASE & CALL TO ACTION                             -->
<!-- ======================================================================== -->
<div class="freelance-banner-box">
  <div class="banner-content">
    <div class="banner-text">
      <div class="badge-pill badge-cyber" style="margin-bottom: 0.6rem;">Available for Freelance & Consulting</div>
      <h3>Looking for Cybersecurity Consulting or Penetration Testing?</h3>
      <p>I help companies, startups, and development teams identify vulnerabilities before attackers do, automate attack surface discovery, design resilient cryptographic systems, and build detection rules for SIEM.</p>
      <div class="banner-skills-list">
        <span class="badge-pill">🛡️ Web & API Penetration Testing</span>
        <span class="badge-pill">🔍 Attack Surface Monitoring (OSINT)</span>
        <span class="badge-pill">⚡ Microsoft Sentinel & KQL Rules</span>
        <span class="badge-pill">🔐 Cryptography & PKI Consulting</span>
      </div>
    </div>
    <div class="banner-cta">
      <a href="{{ '/contact/' | relative_url }}" class="btn btn-cyber">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
        </svg>
        Hire for a Project
      </a>
    </div>
  </div>
</div>

<!-- ======================================================================== -->
<!-- FREELANCE OFFERINGS BREAKDOWN                                            -->
<!-- ======================================================================== -->
<div class="section-header">
  <div class="section-tag badge-pill">What I Deliver</div>
  <h2 class="section-title">Cybersecurity Freelancing Capabilities</h2>
  <p class="section-subtitle">Tailored security services designed for modern engineering organizations.</p>
</div>

<div class="services-grid">
  <div class="service-card">
    <div class="service-icon">🎯</div>
    <h4>Web & API Penetration Testing</h4>
    <p>Black-box and grey-box security testing to uncover injection flaws, broken auth, privilege escalations, and business logic bugs.</p>
    <ul>
      <li>Comprehensive OWASP Top 10 assessment</li>
      <li>RESTful API & GraphQL security audits</li>
      <li>Remediation roadmap & verification re-tests</li>
    </ul>
  </div>

  <div class="service-card">
    <div class="service-icon">🔭</div>
    <h4>Vulnerability Management & ASM</h4>
    <p>Continuous mapping of public-facing assets, automated vulnerability scanning, and risk-based prioritization.</p>
    <ul>
      <li>External asset & OSINT reconnaissance</li>
      <li>CVE / CVSS / EPSS risk scoring</li>
      <li>FastAPI-based continuous ingestion workflows</li>
    </ul>
  </div>

  <div class="service-card">
    <div class="service-icon">📊</div>
    <h4>SIEM & Detection Engineering</h4>
    <p>Custom detection engineering mapped to MITRE ATT&CK for cloud workloads and enterprise networks.</p>
    <ul>
      <li>High-fidelity KQL rules for Microsoft Sentinel</li>
      <li>Splunk queries & SOC alert tuning</li>
      <li>SOAR playbooks for automated incident response</li>
    </ul>
  </div>

  <div class="service-card">
    <div class="service-icon">🔑</div>
    <h4>Cryptography & Key Architecture</h4>
    <p>Designing secure cryptographic protocols, key lifecycle management, and public key infrastructures (PKI).</p>
    <ul>
      <li>PGP/GPG key management architecture</li>
      <li>Zero-knowledge and confidentiality reviews</li>
      <li>Post-quantum & modern cipher evaluation</li>
    </ul>
  </div>
</div>

<!-- ======================================================================== -->
<!-- INTERACTIVE PROJECTS FILTER & GRID                                       -->
<!-- ======================================================================== -->
<div class="section-header" style="margin-top: 3.5rem;">
  <div class="section-tag badge-pill">All Projects & Case Studies</div>
  <h2 class="section-title">Case Studies & Research Work</h2>
  <p class="section-subtitle">Filter by domain to explore technical implementations and academic output.</p>
</div>

<div class="filter-tabs-container">
  <button class="filter-btn active" data-filter="all">All Projects</button>
  <button class="filter-btn" data-filter="cybersecurity-freelance">🛡️ Cybersecurity & Freelancing</button>
  <button class="filter-btn" data-filter="information-theory-phd">🔬 PhD & Information Theory</button>
  <button class="filter-btn" data-filter="machine-learning">🤖 Machine Learning & Dev</button>
</div>

<div class="project-grid" id="projects-container">
  {% for project in site.data.projects %}
    <div class="project-card" data-category="{{ project.category }}">
      <div class="card-top">
        <div class="card-badges">
          <span class="card-category">{{ project.category_display }}</span>
          {% if project.badge_class %}
            <span class="badge-pill {{ project.badge_class }}">{{ project.status }}</span>
          {% else %}
            <span class="badge-pill">{{ project.status }}</span>
          {% endif %}
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
            {% for item in project.highlights %}
              <li>{{ item }}</li>
            {% endfor %}
          </ul>
        {% endif %}
      </div>

      <div class="card-bottom">
        {% if project.tags %}
          <div class="card-tags">
            {% for tag in project.tags %}
              <span class="tag-pill">{{ tag }}</span>
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
  {% endfor %}
</div>

<!-- Easy note for adding projects -->
<div style="background: var(--bg-subtle); border: 1px dashed var(--border-color); border-radius: 12px; padding: 1.5rem; text-align: center; margin-top: 2rem;">
  <p style="margin-bottom: 0.5rem; font-weight: 600; color: var(--text-primary);">💼 Ready to collaborate on your next cybersecurity project or hire me for consulting?</p>
  <p style="margin-bottom: 1rem; font-size: 0.95rem;">I am available for freelance penetration tests, security audits, and DevSecOps advisory contracts.</p>
  <a href="{{ '/contact/' | relative_url }}" class="btn btn-sm btn-primary">Initiate Contact</a>
</div>
