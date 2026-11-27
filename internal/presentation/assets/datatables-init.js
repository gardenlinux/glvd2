// Keep the static tables usable when enhancement is unavailable.
(function () {
  "use strict";

  var root = document.documentElement;

  var jq = window.jQuery;
  if (!jq || !jq.fn || !jq.fn.DataTable) {
    // Reveal the static tables when the enhancement libraries are unavailable.
    root.classList.remove("dt-pending");
    return;
  }

  var tables = [];
  var initialized = false;

  function watchWidth(api) {
    var container = api.table().container();
    var width = container.getBoundingClientRect().width;
    var scheduled = false;

    function adjust() {
      var next = container.getBoundingClientRect().width;
      if (next === width || next === 0) {
        return;
      }
      width = next;
      if (scheduled) {
        return;
      }
      scheduled = true;
      // Defer layout changes out of the observer callback and coalesce resize bursts.
      window.requestAnimationFrame(function () {
        scheduled = false;
        api.columns.adjust();
      });
    }

    if (window.ResizeObserver) {
      new window.ResizeObserver(adjust).observe(container);
    } else {
      window.addEventListener("resize", adjust);
    }
  }

  function setupScopeFilter(table, api) {
    var id = table.dataset.scopeFilter;
    if (!id) {
      return;
    }
    var panel = document.getElementById(id);
    if (!panel) {
      return;
    }

    panel.querySelectorAll(".scope-filter-group").forEach(function (group) {
      var column = parseInt(group.dataset.filterColumn, 10);
      var buttons = group.querySelectorAll("button[data-filter-value]");

      buttons.forEach(function (button) {
        button.addEventListener("click", function () {
          var value = button.dataset.filterValue;

          buttons.forEach(function (other) {
            var active = other === button;
            other.classList.toggle("is-active", active);
            other.setAttribute("aria-pressed", active ? "true" : "false");
          });

          var currentColumn = api.colReorder.transpose(column, "toCurrent");

          // Exact, non-smart search so "affected" never also matches "not-affected".
          api.column(currentColumn).search(value ? "^" + value + "$" : "", true, false).draw();
        });
      });
    });

    // Reveal the controls only once wired, so they never appear without enhancement.
    panel.hidden = false;
  }

  function initialize() {
    if (initialized) {
      return;
    }
    initialized = true;

    try {
      jq("table.datatable").each(function () {
        // Capture semantic headers before DataTables adds sorting controls and sizing markup.
        var template = document.createElement("table");
        template.className = "print-table";
        template.appendChild(this.tHead.cloneNode(true));

        var options = {
          // Preserve the ordering until the user chooses a sort.
          order: [],
          pageLength: 10,
          lengthMenu: [10, 25, 50, 100],
          autoWidth: false,
          scrollX: true,
          colReorder: true,
          language: { thousands: "," },
        };
        if (this.dataset.columnVisibility === "true" &&
            jq.fn.dataTable && jq.fn.dataTable.Buttons && jq.fn.dataTable.ext.buttons.colvis) {
          options.columnDefs = [];
          this.querySelectorAll("thead th").forEach(function (header, index) {
            if (index > 0 && header.dataset.defaultHidden === "true") {
              options.columnDefs.push({ targets: index, visible: false });
            }
          });
          options.layout = {
            topStart: ["pageLength", { buttons: [{
              extend: "colvis",
              text: "Columns",
              // Keep the row identity visible even when all optional columns are hidden.
              columns: ":not(:first-child)",
              postfixButtons: [
                { text: "Show all columns", action: function (event, api) { api.columns().visible(true); } },
                { extend: "colvisRestore", text: "Reset to defaults" },
              ],
            }] }],
          };
        }
        var api = jq(this).DataTable(options);
        setupScopeFilter(this, api);
        tables.push({ api: api, template: template, printTable: null });
        watchWidth(api);
      });
    } finally {
      root.classList.remove("dt-pending");
    }
  }

  function clearPrintTables() {
    tables.forEach(function (table) {
      if (table.printTable) {
        table.printTable.remove();
        table.printTable = null;
        table.api.table().container().classList.remove("print-source");
      }
    });
  }

  function preparePrintTables() {
    // Printing can start before the scheduled enhancement has run.
    initialize();
    clearPrintTables();

    try {
      tables.forEach(function (table) {
        var printTable = table.template.cloneNode(true);
        var visible = table.api.columns().visible().toArray();
        var headers = printTable.querySelectorAll("thead th");
        var headerRow = printTable.tHead.rows[0];
        // Match the original header snapshot to the current row order and visibility.
        table.api.colReorder.order().forEach(function (originalIndex, currentIndex) {
          var cell = headers[originalIndex];
          if (visible[currentIndex]) {
            headerRow.appendChild(cell);
          } else {
            cell.remove();
          }
        });
        var body = document.createElement("tbody");
        var rows = table.api.rows({ search: "applied", order: "applied", page: "all" });
        rows.nodes().each(function (row) {
          body.appendChild(row.cloneNode(true));
        });
        if (!body.childElementCount) {
          var row = document.createElement("tr");
          var cell = document.createElement("td");
          cell.colSpan = visible.filter(Boolean).length;
          cell.textContent = "No matching records found";
          row.appendChild(cell);
          body.appendChild(row);
        }
        printTable.appendChild(body);

        var container = table.api.table().container();
        container.before(printTable);
        table.printTable = printTable;
        container.classList.add("print-source");
      });
    } catch (error) {
      clearPrintTables();
      throw error;
    }
  }

  window.addEventListener("beforeprint", preparePrintTables);
  window.addEventListener("afterprint", clearPrintTables);

  root.classList.add("dt-pending");
  // A second animation frame lets the loading overlay paint before synchronous initialization.
  window.requestAnimationFrame(function () {
    window.requestAnimationFrame(initialize);
  });
})();
