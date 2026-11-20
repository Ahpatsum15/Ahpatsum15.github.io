---
# blog.md
layout: default
title: PhD Research & Technical Articles
permalink: /blog/
---

<div class="page-header">
  <div class="badge-pill badge-quantum">Doctoral Notes & Technical Writings</div>
  <h1 class="page-title">PhD Articles & Research Blog</h1>
  <p class="page-subtitle">Academic research in Information Theory and Quantum Communication, practical DevSecOps engineering guides, machine learning tutorials, and cybersecurity insights.</p>
</div>

<!-- ======================================================================== -->
<!-- FEATURED PHD RESEARCH COMPANION SPOTLIGHT                                 -->
<!-- ======================================================================== -->
<div class="phd-spotlight-card">
  <div class="phd-badge">
    <span class="badge-pill badge-quantum">🔬 PhD Companion Series · UM6P College of Computing</span>
  </div>
  <h3>Information Theory & Quantum Wiretap Research</h3>
  <p>
    As part of my doctoral research at <strong>UM6P College of Computing</strong> on <span class="thesis-topic">"Secrecy Capacity and Coding for Noisy Quantum Wiretap Channels"</span>, I publish regular theoretical deep dives, mathematical derivations, and code implementations exploring physical-layer security, wiretap channels, and quantum information bounds.
  </p>
  <div class="phd-actions">
    <a href="#information-theory" class="btn btn-sm btn-outline">Explore PhD Research Notes ↓</a>
    <a href="{{ '/assets/files/CV_PhD_mustapha_el bouazaoui_updated.pdf' | relative_url }}" target="_blank" class="btn btn-sm btn-secondary">Download Academic CV (PDF)</a>
  </div>
</div>

<!-- ======================================================================== -->
<!-- INTERACTIVE CATEGORY FILTER                                              -->
<!-- ======================================================================== -->
<div class="filter-tabs-container">
  <button class="filter-btn active" data-filter="all">All Articles ({{ site.posts.size }})</button>
  <button class="filter-btn" data-filter="cat-information-theory">🔬 Information Theory (PhD)</button>
  <button class="filter-btn" data-filter="cat-devops">🛡️ Cybersecurity & DevSecOps</button>
  <button class="filter-btn" data-filter="cat-machine-learning">🤖 Machine Learning</button>
  <button class="filter-btn" data-filter="cat-productivity">⚡ Productivity</button>
</div>

<!-- ======================================================================== -->
<!-- ALL ARTICLES STREAM                                                      -->
<!-- ======================================================================== -->
<div class="article-cards-list">
  {% for post in site.posts %}
    {% assign post_categories_slug = "" %}
    {% for cat in post.categories %}
      {% assign c_slug = cat | downcase | replace: " ", "-" %}
      {% assign post_categories_slug = post_categories_slug | append: " cat-" | append: c_slug %}
    {% endfor %}

    <article class="article-card project-card" data-category="{{ post_categories_slug | strip }}">
      <div class="card-top">
        <div class="article-meta">
          <span class="post-date">{{ post.date | date: "%B %-d, %Y" }}</span>
          <span>•</span>
          {% if post.categories contains "information-theory" %}
            <span class="badge-pill badge-quantum">PhD Research</span>
          {% elsif post.categories contains "devops" %}
            <span class="badge-pill badge-cyber">DevSecOps</span>
          {% elsif post.categories contains "Machine-learning" or post.categories contains "machine-learning" %}
            <span class="badge-pill badge-ml">Machine Learning</span>
          {% else %}
            <span class="badge-pill">{{ post.categories | first }}</span>
          {% endif %}
        </div>

        <h2 class="article-title">
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        </h2>

        <p class="article-excerpt">
          {{ post.excerpt | strip_html | truncatewords: 35 }}
        </p>
      </div>

      <div class="card-bottom">
        {% if post.tags %}
          <div class="card-tags">
            {% for tag in post.tags limit:4 %}
              <span class="tag-pill-mini">#{{ tag }}</span>
            {% endfor %}
          </div>
        {% endif %}

        <div class="article-footer">
          <a href="{{ post.url | relative_url }}" class="card-link">Read Full Article &rarr;</a>
        </div>
      </div>
    </article>
  {% endfor %}
</div>

<!-- ======================================================================== -->
<!-- DEDICATED SECTIONS BY CATEGORY                                           -->
<!-- ======================================================================== -->
<div class="section-header" id="information-theory" style="margin-top: 3.5rem;">
  <div class="section-tag badge-pill badge-quantum">Doctoral Research Archive</div>
  <h2 class="section-title">🔬 Information Theory & Quantum Secrecy Notes</h2>
  <p class="section-subtitle">Articles, theorem proofs, and simulation notebooks written as a complement to my PhD research.</p>
</div>

<div class="categorized-section">
  <ul class="post-list">
    {% for post in site.categories.information-theory %}
      <li style="margin-bottom: 1.25rem;">
        <span class="post-meta" style="color: var(--text-muted); font-size: 0.85rem;">{{ post.date | date: "%b %-d, %Y" }}</span>
        <h3 style="margin-top: 0.2rem; margin-bottom: 0.3rem; font-size: 1.15rem;">
          <a href="{{ post.url | relative_url }}" style="color: var(--text-primary);">{{ post.title }}</a>
        </h3>
        <p style="margin: 0; font-size: 0.9rem; color: var(--text-secondary);">{{ post.excerpt | strip_html | truncatewords: 25 }}</p>
      </li>
    {% else %}
      <p style="font-style: italic; color: var(--text-muted);">More articles in this PhD research series are in progress.</p>
    {% endfor %}
  </ul>
</div>

<!-- Category Index Links -->
<div style="background: var(--bg-subtle); border: 1px solid var(--border-color); border-radius: 12px; padding: 1.5rem; margin-top: 2.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
  <div>
    <strong style="color: var(--text-primary);">Looking for the complete archive by category?</strong>
    <p style="margin: 0; font-size: 0.9rem; color: var(--text-secondary);">Browse all historical posts grouped by domain.</p>
  </div>
  <a href="{{ '/categories/' | relative_url }}" class="btn btn-outline btn-sm">View Archive by Category &rarr;</a>
</div>
