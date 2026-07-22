---
# index.md
layout: default
title: Home
---

<div class="profile-container">
  <img src="{{ '/assets/images/profile.jpg' | relative_url }}" alt="Simon Baker" class="profile-image">
  <p class="image-caption">Simon Baker(Patrick Jane) from The Mentalist</p>
  </div>
  <div class="hero-content">
    <h1>Hi, I'm Mustapha El Bouazaoui</h1>
    <p class="subtitle">Cybersecurity and Telecom Engineer & Math Enthusiast</p>
    <p>I specialize in vulnerability management and cryptography.But I'm passionate about machine learning/deep learning and competitive programming</p>
    <div class="cta-buttons">
      <a href="{{ '/about/' | relative_url }}" class="btn btn-primary">About Me</a>
      <a href="{{ '/projects/' | relative_url }}" class="btn btn-secondary">View Projects</a>
      <a href="{{ '/assets/files/CV_mustapha_el bouazaoui_main.pdf' | relative_url }}" class="btn btn-outline" target="_blank">Download CV</a>
    </div>
  </div>

<div class="section">
  <h2>Featured Projects and blog</h2>
  <div class="project-grid">
    <!-- You can list a couple of key projects here, or pull from _data/projects.yml -->
    <div class="project-card">
      <h3><a href="https://github.com/Ahpatsum15/Understanding-cryptography-solution-handbook-even-numbered" target="_blank">Understanding Cryptography Solutions</a></h3>
      <p>Solutions and explanations for exercises from the "Understanding Cryptography" textbook.</p>
    </div>
    <!-- <div class="project-card">
      <h3><a href="https://github.com/Ahpatsum15/unhashit" target="_blank">UnhashIt</a></h3>
      <p>A smart hash analyzer tool.</p>
    </div>
  </div>-->
  <p><a href="{{ '/projects/' | relative_url }}">See all projects &rarr;</a></p>
</div>

<!-- Optional: Latest Blog Post Section (if you add a blog later) -->

<div class="section">
  <h2>Latest Blog Posts</h2>
  <ul class="post-list">
    {% for post in site.posts limit:2 %}
      <li>
        <span class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</span>
        <h3>
          <a class="post-link" href="{{ post.url | relative_url }}">
            {{ post.title | escape }}
          </a>
        </h3>
      </li>
    {% endfor %}
  </ul>
  <p><a href="/blog/">Read more posts &rarr;</a></p>
</div>

