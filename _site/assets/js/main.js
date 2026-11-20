// assets/js/main.js
document.addEventListener('DOMContentLoaded', () => {
  // 1. Theme Switcher (Light / Dark)
  const themeToggleBtn = document.getElementById('theme-toggle');
  
  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      try {
        localStorage.setItem('theme', newTheme);
      } catch (e) {}
    });
  }

  // 2. Mobile Menu Toggle
  const mobileToggleBtn = document.getElementById('mobile-menu-toggle');
  const siteNav = document.getElementById('site-nav');
  const headerActions = document.querySelector('.header-actions');

  if (mobileToggleBtn && siteNav) {
    mobileToggleBtn.addEventListener('click', () => {
      siteNav.classList.toggle('open');
      if (headerActions) {
        headerActions.classList.toggle('menu-active');
      }
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
      if (!siteNav.contains(e.target) && !mobileToggleBtn.contains(e.target) && siteNav.classList.contains('open')) {
        siteNav.classList.remove('open');
        if (headerActions) {
          headerActions.classList.remove('menu-active');
        }
      }
    });
  }

  // 3. Back to Top Button
  const backToTopBtn = document.getElementById('back-to-top');
  if (backToTopBtn) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 350) {
        backToTopBtn.classList.add('visible');
      } else {
        backToTopBtn.classList.remove('visible');
      }
    }, { passive: true });

    backToTopBtn.addEventListener('click', () => {
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    });
  }

  // 4. Interactive Project Filter (Projects Page & Home)
  const filterBtns = document.querySelectorAll('.filter-btn');
  const projectCards = document.querySelectorAll('.project-card[data-category]');

  if (filterBtns.length > 0 && projectCards.length > 0) {
    filterBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const filterValue = btn.getAttribute('data-filter');

        projectCards.forEach(card => {
          const cardCategories = card.getAttribute('data-category').split(' ');
          if (filterValue === 'all' || cardCategories.includes(filterValue)) {
            card.style.display = 'flex';
            setTimeout(() => {
              card.style.opacity = '1';
              card.style.transform = 'translateY(0)';
            }, 10);
          } else {
            card.style.opacity = '0';
            card.style.transform = 'translateY(10px)';
            setTimeout(() => {
              card.style.display = 'none';
            }, 200);
          }
        });
      });
    });
  }

  // 5. Reading Time Calculation for Blog Posts
  const postContent = document.getElementById('post-content');
  const readingTimeEl = document.getElementById('reading-time-estimate');
  if (postContent && readingTimeEl) {
    const text = postContent.innerText || '';
    const words = text.trim().split(/\s+/).length;
    const minutes = Math.max(1, Math.ceil(words / 200));
    readingTimeEl.textContent = `${minutes} min read`;
  }

  // 6. Copy Code Button on Code Blocks
  const preElements = document.querySelectorAll('pre');
  preElements.forEach((pre) => {
    // Only add if not already present
    if (pre.querySelector('.copy-code-btn')) return;

    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-code-btn';
    copyBtn.type = 'button';
    copyBtn.textContent = 'Copy';
    copyBtn.setAttribute('aria-label', 'Copy code snippet');

    copyBtn.addEventListener('click', async () => {
      const code = pre.querySelector('code');
      const textToCopy = code ? code.innerText : pre.innerText;

      try {
        await navigator.clipboard.writeText(textToCopy);
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
          copyBtn.classList.remove('copied');
        }, 2000);
      } catch (err) {
        copyBtn.textContent = 'Failed';
        setTimeout(() => {
          copyBtn.textContent = 'Copy';
        }, 2000);
      }
    });

    pre.appendChild(copyBtn);
  });
});
