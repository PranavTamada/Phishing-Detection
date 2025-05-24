document.addEventListener('DOMContentLoaded', function () {
  // Utility: Map feature keys to user-friendly titles, explanations, and icons (SVG paths)
  const featureDetails = {
    ipInUrl: {
      title: 'Use of IP Address in URL',
      description: 'URLs containing IP addresses instead of domain names are suspicious because attackers often use them to hide their identity.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="10" rx="2" ry="2"></rect><line x1="2" y1="12" x2="22" y2="12"></line><line x1="6" y1="7" x2="6" y2="17"></line><line x1="10" y1="7" x2="10" y2="17"></line><line x1="14" y1="7" x2="14" y2="17"></line><line x1="18" y1="7" x2="18" y2="17"></line></svg>'
    },
    suspiciousSubdomain: {
      title: 'Suspicious Subdomains',
      description: 'Phishing URLs often use multiple or misleading subdomains to confuse users and mimic legitimate sites.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path><path d="M12 2a15.3 15.3 0 0 1 0 20"></path></svg>'
    },
    misspellings: {
      title: 'Misspellings in Domain',
      description: 'Misspelled domain names are a common trick used by phishers to impersonate legitimate websites.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 20h9"></path><path d="M12 4h9"></path><path d="M4 9h16"></path><path d="M4 15h16"></path></svg>'
    },
    specialChars: {
      title: 'Special Characters in URL',
      description: 'Excessive or unusual special characters in URLs can indicate attempts to obfuscate malicious links.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M12 2l4 20"></path><path d="M12 2l-4 20"></path></svg>'
    },
    recentlyRegistered: {
      title: 'Recently Registered Domain',
      description: 'Domains registered very recently are often used for phishing before they get blacklisted.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
    },
    impersonation: {
      title: 'Impersonation Detected',
      description: 'This site appears to be impersonating a legitimate website to steal your information.',
      icon: '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24"><path d="M18 8h1a4 4 0 0 1 0 8h-1"></path><path d="M2 8h16v9a4 4 0 0 1-4 4H6a4 4 0 0 1-4-4V8z"></path><line x1="6" y1="1" x2="6" y2="4"></line><line x1="10" y1="1" x2="10" y2="4"></line><line x1="14" y1="1" x2="14" y2="4"></line></svg>'
    }
  };

  // Parse query parameters
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get('url');
  const score = parseFloat(params.get('score')) || 0;
  let features = params.get('features') || '';

  // Display blocked URL
  const blockedUrlElement = document.getElementById('blocked-url');
  if (blockedUrl && blockedUrl.trim().length > 0) {
    blockedUrlElement.textContent = decodeURIComponent(blockedUrl);
  } else {
    blockedUrlElement.textContent = 'No URL provided';
  }

  // Display phishing score visually and textually
  const scoreBar = document.getElementById('phishing-score-bar');
  const scoreText = document.getElementById('phishing-score-text');
  const normalizedScore = score <= 1 ? score * 100 : score;
  const clampedScore = Math.min(Math.max(normalizedScore, 0), 100);
  
  // Update the progress bar
  scoreBar.style.width = `${clampedScore}%`;
  scoreBar.style.backgroundColor = clampedScore > 70 ? 'var(--danger)' : 
                                 clampedScore > 40 ? 'var(--warning)' : 
                                 'var(--success)';
  
  // Update the score text
  scoreText.textContent = `Phishing Score: ${clampedScore.toFixed(1)}%`;
  scoreText.style.color = clampedScore > 70 ? 'var(--danger)' : 
                         clampedScore > 40 ? 'var(--warning)' : 
                         'var(--success)';

  // Parse features string into array
  const featuresArray = features.split(',').map(f => f.trim()).filter(f => f.length > 0);

  // Container for reasons
  const reasonsContainer = document.getElementById('reasons-container');
  reasonsContainer.innerHTML = '';

  if (featuresArray.length === 0) {
    reasonsContainer.innerHTML = '<p>No specific phishing features detected.</p>';
  } else {
    featuresArray.forEach(featureKey => {
      const detail = featureDetails[featureKey];
      if (detail) {
        // Create reason item
        const reasonItem = document.createElement('div');
        reasonItem.className = 'reason-item';
        reasonItem.setAttribute('tabindex', '0');
        reasonItem.setAttribute('role', 'button');
        reasonItem.setAttribute('aria-expanded', 'false');

        // Icon container
        const iconWrapper = document.createElement('div');
        iconWrapper.className = 'reason-icon';
        iconWrapper.innerHTML = detail.icon;

        // Content container
        const contentWrapper = document.createElement('div');
        contentWrapper.className = 'reason-content';

        // Title with toggle icon
        const title = document.createElement('div');
        title.className = 'reason-title';
        title.textContent = detail.title;

        const toggleIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        toggleIcon.setAttribute('class', 'toggle-icon');
        toggleIcon.setAttribute('viewBox', '0 0 24 24');
        toggleIcon.setAttribute('fill', 'none');
        toggleIcon.setAttribute('stroke', 'currentColor');
        toggleIcon.setAttribute('stroke-width', '3');
        toggleIcon.setAttribute('stroke-linecap', 'round');
        toggleIcon.setAttribute('stroke-linejoin', 'round');
        toggleIcon.innerHTML = '<polyline points="6 9 12 15 18 9"></polyline>';
        title.appendChild(toggleIcon);

        // Description
        const description = document.createElement('div');
        description.className = 'reason-description';
        description.textContent = detail.description;

        contentWrapper.appendChild(title);
        contentWrapper.appendChild(description);

        reasonItem.appendChild(iconWrapper);
        reasonItem.appendChild(contentWrapper);

        // Toggle expand/collapse on click or keyboard enter/space
        reasonItem.addEventListener('click', () => {
          const expanded = reasonItem.classList.toggle('expanded');
          reasonItem.setAttribute('aria-expanded', expanded);
        });
        reasonItem.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            reasonItem.click();
          }
        });

        reasonsContainer.appendChild(reasonItem);
      }
    });
  }

  // About phishing collapsible toggle
  const aboutPhishing = document.getElementById('about-phishing');
  const aboutHeader = aboutPhishing.querySelector('.about-header');
  const aboutContent = aboutPhishing.querySelector('.about-content');

  function toggleAbout() {
    const expanded = aboutPhishing.classList.toggle('expanded');
    aboutHeader.setAttribute('aria-expanded', expanded);
    aboutContent.setAttribute('aria-hidden', !expanded);
  }

  aboutHeader.addEventListener('click', toggleAbout);
  aboutHeader.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      toggleAbout();
    }
  });

  // Quiz toggle button
  const quizToggleBtn = document.getElementById('quiz-toggle-btn');
  const quizSection = document.getElementById('quiz-section');
  quizToggleBtn.addEventListener('click', () => {
    const isHidden = quizSection.style.display === 'none' || quizSection.style.display === '';
    quizSection.style.display = isHidden ? 'block' : 'none';
    quizToggleBtn.setAttribute('aria-expanded', isHidden);
  });

  // Quiz logic
  const quizForm = document.getElementById('quiz-form');
  const quizResult = document.getElementById('quiz-result');
  const quizFeedback = document.getElementById('quiz-feedback');
  const quizEncouragement = document.getElementById('quiz-encouragement');

  const quizAnswers = {
    q1: 'b',
    q2: 'b',
    q3: 'c'
  };

  const quizExplanations = {
    q1: 'Misspelled domain names are a common sign of phishing links.',
    q2: 'If you click a phishing link, change your passwords and monitor your accounts immediately.',
    q3: 'Official company domain names are NOT a common trait of phishing URLs.'
  };

  quizForm.addEventListener('submit', (e) => {
    e.preventDefault();
    let score = 0;
    let feedbackHtml = '';
    let allAnswered = true;
    for (const [q, correctAns] of Object.entries(quizAnswers)) {
      const userAnswer = quizForm.elements[q].value;
      if (!userAnswer) allAnswered = false;
      const isCorrect = userAnswer === correctAns;
      if (isCorrect) score++;
      feedbackHtml += `<p><strong>Question ${q.slice(1)}:</strong> ${isCorrect ? 'Correct' : 'Incorrect'} - ${quizExplanations[q]}</p>`;
    }
    if (!allAnswered) {
      quizResult.textContent = 'Please answer all questions before submitting.';
      quizFeedback.innerHTML = '';
      quizEncouragement.textContent = '';
      return;
    }
    quizResult.textContent = `You scored ${score} out of 3.`;
    quizFeedback.innerHTML = feedbackHtml;
    quizEncouragement.textContent = score >= 2 ? 'Great job!' : 'Review the tips above again.';
  });

  // Button actions
  document.getElementById('go-back').addEventListener('click', () => {
    window.history.back();
  });

  document.getElementById('report-false').addEventListener('click', () => {
    alert('Thank you for your feedback. Our team will review this website. If you believe this is a false positive, please try accessing the site in another browser.');
  });

  document.getElementById('learn-more').addEventListener('click', () => {
    window.open('https://www.phishguard-example.com/learn', '_blank');
  });
}); 