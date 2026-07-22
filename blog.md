---
# blog.md
layout: default
title: Blog
permalink: /blog/
---

<h1>Blog</h1>

<p>Welcome to my blog! Here, I share thoughts and insights on topics I'm passionate about.</p>

<div class="categories-section">
  <h2>Categories</h2>

  <div class="category">
    <h3> Productivity</h3>
    <ul>
      {% for post in site.categories.Productivity %}
        <li>
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
          <span class="post-date">{{ post.date | date: "%B %d, %Y" }}</span>
        </li>
      {% endfor %}
    </ul>
  </div>

  <div class="category">
    <h3> Competitive Programming (Coming Soon)</h3>
    <p>Exploring algorithms, data structures, and problem-solving techniques.</p>
    <ul>
      <li><em>Posts coming soon...</em></li>
    </ul>
  </div>

  <div class="category">
    <h3> Machine Learning </h3>
    <p>Insights into ML concepts, projects, and learning resources.</p>
    <ul>
      {% for post in site.categories.Machine-learning %}
        <li>
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
          <span class="post-date">{{ post.date | date: "%B %d, %Y" }}</span>
        </li>
      {% endfor %}
    </ul>
  </div>

  <div class="category">
    <h3>DevSecOps</h3>
    <ul>
      {% for post in site.categories.devops %}
        <li>
          <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
          <span class="post-date">{{ post.date | date: "%B %d, %Y" }}</span>
        </li>
      {% endfor %}
    </ul>
  </div>
  
  <div class="category">
    <h3> Cryptography (Coming Soon)</h3>
    <p>Notes on cryptographic concepts, tools, and research.</p>
    <ul>
      <li><em>Posts coming soon...</em></li>
    </ul>
  </div>

</div>
