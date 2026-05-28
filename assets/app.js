(function() {
  'use strict';

  function initTabs(container) {
    const buttons = Array.from(container.querySelectorAll('[data-tabs-target]'));
    if (buttons.length === 0) return;

    const titleEl = container.querySelector('[data-tabs-title]');
    const panels = Array.from(container.querySelectorAll('[data-tabs-panel]'));

    function activate(btn) {
      const targetId = btn.dataset.tabsTarget;
      buttons.forEach((b) => b.classList.toggle('tab-btn--active', b === btn));
      panels.forEach((panel) => { panel.hidden = panel.id !== targetId; });
      if (titleEl) titleEl.textContent = btn.dataset.tabsLabel || btn.textContent;
    }

    buttons.forEach((btn) => btn.addEventListener('click', () => activate(btn)));

    const initial = buttons.find((b) => b.classList.contains('tab-btn--active')) || buttons[0];
    activate(initial);
  }

  function initCollapsible(details) {
    const body = details.querySelector('.collapsible-section__body');
    const summary = details.querySelector('summary');
    if (!body || !summary) return;

    let animating = false;

    summary.addEventListener('click', (e) => {
      e.preventDefault();
      if (animating) return;
      animating = true;

      const opening = !details.open;

      function onEnd(ev) {
        if (ev.propertyName !== 'height') return;
        body.removeEventListener('transitionend', onEnd);
        if (!opening) details.removeAttribute('open');
        body.style.height = '';
        animating = false;
      }

      if (opening) {
        details.setAttribute('open', '');
        body.style.height = '0';
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            body.addEventListener('transitionend', onEnd);
            body.style.height = body.scrollHeight + 'px';
          });
        });
      } else {
        body.style.height = body.scrollHeight + 'px';
        requestAnimationFrame(() => {
          requestAnimationFrame(() => {
            body.addEventListener('transitionend', onEnd);
            body.style.height = '0';
          });
        });
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-tabs]').forEach(initTabs);
    document.querySelectorAll('.collapsible-section').forEach(initCollapsible);
  });
})();
