(function() {
  'use strict';

  function initTabs(container) {
    const buttons = Array.from(container.querySelectorAll('[data-tabs-target]'));
    const titleEl = container.querySelector('[data-tabs-title]');

    if (buttons.length === 0) return;

    function activate(btn) {
      const targetId = btn.dataset.tabsTarget;
      buttons.forEach(function(b) {
        b.classList.toggle('tab-btn--active', b === btn);
      });
      container.querySelectorAll('[data-tabs-panel]').forEach(function(panel) {
        panel.hidden = panel.id !== targetId;
      });
      if (titleEl) titleEl.textContent = btn.dataset.tabsLabel || btn.textContent;
    }

    buttons.forEach(function(btn) {
      btn.addEventListener('click', function() { activate(btn); });
    });

    activate(buttons[0]);
  }

  function initCollapsible(details) {
    var body = details.querySelector('.collapsible-section__body');
    var summary = details.querySelector('summary');
    if (!body || !summary) return;

    summary.addEventListener('click', function(e) {
      e.preventDefault();
      if (details.open) {
        body.style.height = body.scrollHeight + 'px';
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            body.style.height = '0';
          });
        });
        body.addEventListener('transitionend', function handler() {
          body.removeEventListener('transitionend', handler);
          details.removeAttribute('open');
          body.style.height = '';
        });
      } else {
        details.setAttribute('open', '');
        body.style.height = '0';
        requestAnimationFrame(function() {
          requestAnimationFrame(function() {
            body.style.height = body.scrollHeight + 'px';
          });
        });
        body.addEventListener('transitionend', function handler() {
          body.removeEventListener('transitionend', handler);
          body.style.height = '';
        });
      }
    });
  }

  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-tabs]').forEach(initTabs);
    document.querySelectorAll('.collapsible-section').forEach(initCollapsible);
  });
})();
