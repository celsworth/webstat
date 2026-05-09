/* ============================================================
   Webstat — app.js
   Vanilla JS: table sorting + live search/filter
   ============================================================ */

(function () {
  "use strict";

  /* ---- Table sorting ---- */
  document.querySelectorAll("table.sortable thead th[data-sort]").forEach(function (th) {
    th.style.cursor = "pointer";

    th.addEventListener("click", function () {
      var table = th.closest("table");
      var allThs = Array.from(th.closest("tr").querySelectorAll("th"));
      var colIndex = allThs.indexOf(th); // real td position
      var sortable = Array.from(table.querySelectorAll("thead th[data-sort]"));
      var ascending = !th.classList.contains("sort-asc");

      sortable.forEach(function (h) {
        h.classList.remove("sort-asc", "sort-desc");
      });
      th.classList.add(ascending ? "sort-asc" : "sort-desc");

      var tbody = table.querySelector("tbody");
      var rows = Array.from(tbody.querySelectorAll("tr"));
      var sortType = th.dataset.sort;

      rows.sort(function (a, b) {
        var aVal = cellValue(a, colIndex, sortType);
        var bVal = cellValue(b, colIndex, sortType);
        if (aVal < bVal) return ascending ? -1 : 1;
        if (aVal > bVal) return ascending ? 1 : -1;
        return 0;
      });

      rows.forEach(function (r) {
        tbody.appendChild(r);
      });
    });
  });

  function cellValue(row, index, sortType) {
    var cell = row.querySelectorAll("td")[index];
    if (!cell) return sortType === "num" ? 0 : "";
    // Prefer explicit data-value (raw integer) over display text
    if (cell.dataset.value !== undefined && cell.dataset.value !== "") {
      return sortType === "num" ? parseFloat(cell.dataset.value) || 0 : cell.dataset.value.toLowerCase();
    }
    var text = cell.textContent.trim();
    if (sortType === "num") {
      return parseFloat(text.replace(/[^0-9.\-]/g, "")) || 0;
    }
    return text.toLowerCase();
  }

  function cellText(row, index) {
    var cell = row.querySelectorAll("td")[index];
    return cell ? cell.textContent.trim() : "";
  }

  /* ---- Live table search ---- */
  document.querySelectorAll("input.table-search").forEach(function (input) {
    var tableId = input.dataset.table;
    var table = tableId ? document.getElementById(tableId) : null;
    if (!table) return;

    var tbody = table.querySelector("tbody");

    input.addEventListener("input", function () {
      var query = input.value.trim().toLowerCase();
      var rows = tbody.querySelectorAll("tr");

      rows.forEach(function (row) {
        var text = row.textContent.toLowerCase();
        row.style.display = !query || text.includes(query) ? "" : "none";
      });
    });
  });
})();
