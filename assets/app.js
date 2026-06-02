(function() {
  'use strict';

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
    document.querySelectorAll('.collapsible-section').forEach(initCollapsible);
  });
})();

// Attach a column-header sort + top-N visibility cap to a data table.
// defaultSortCol: 0-based <td> index of the initial sort column (desc).
// topN: max rows to display at once; remaining rows are hidden in the DOM.
window.makeSortable = function(tableId, defaultSortCol, topN) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var tbody = table.querySelector('tbody');
  var ths = table.querySelectorAll('thead th[data-col]');
  var sortCol = defaultSortCol;
  var sortAsc = false;

  function applySort() {
    var rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort(function(a, b) {
      var av = parseFloat(a.querySelectorAll('td')[sortCol].dataset.value) || 0;
      var bv = parseFloat(b.querySelectorAll('td')[sortCol].dataset.value) || 0;
      return sortAsc ? av - bv : bv - av;
    });
    rows.forEach(function(r, i) {
      r.querySelector('td').textContent = i + 1;
      r.style.display = i < topN ? '' : 'none';
      tbody.appendChild(r);
    });
  }

  // Initial state: hide rows beyond topN (server pre-sorted by default col).
  Array.from(tbody.querySelectorAll('tr')).forEach(function(r, i) {
    if (i >= topN) r.style.display = 'none';
  });

  // Mark initial sort column.
  ths.forEach(function(th) {
    th.style.cursor = 'pointer';
    if (parseInt(th.dataset.col, 10) === defaultSortCol) {
      th.textContent += ' ▼'; // ▼
    }
    th.addEventListener('click', function() {
      var col = parseInt(th.dataset.col, 10);
      if (sortCol === col) {
        sortAsc = !sortAsc;
      } else {
        sortCol = col;
        sortAsc = false;
      }
      ths.forEach(function(h) { h.textContent = h.textContent.replace(/ [▲▼]$/, ''); });
      th.textContent += sortAsc ? ' ▲' : ' ▼';
      applySort();
    });
  });
};
