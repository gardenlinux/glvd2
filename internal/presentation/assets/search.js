// Navigates to a CVE detail page from an entered identifier.
// CVE pages are static files at cves/{id}/index.html, so no index or lookup table is required.
(function () {
  "use strict";

  var form = document.querySelector(".cve-search");
  if (!form) {
    return;
  }

  var input = document.getElementById("cve-id");
  var error = document.getElementById("cve-search-error");
  var pattern = /^CVE-\d{4}-\d+$/;

  form.addEventListener("submit", function (event) {
    event.preventDefault();

    var value = input.value.trim().toUpperCase();
    if (/^\d{4}-\d+$/.test(value)) {
      value = "CVE-" + value;
    }

    if (!pattern.test(value)) {
      error.textContent = "Enter a CVE ID like CVE-2026-129448.";
      error.hidden = false;
      input.focus();
      return;
    }

    error.hidden = true;
    var base = (form.getAttribute("data-cve-base") || "cves").replace(/\/$/, "");
    window.location.href = base + "/" + encodeURIComponent(value) + "/index.html";
  });
})();
