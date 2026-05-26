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

  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-tabs]').forEach(initTabs);
  });
})();
