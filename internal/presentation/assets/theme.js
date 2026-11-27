// Apply the explicit theme choice before the page paints.
(function () {
  "use strict";

  var key = "glvd-theme";
  var root = document.documentElement;
  var mql = window.matchMedia("(prefers-color-scheme: dark)");
  var selectedTheme = null;

  function storedTheme() {
    try {
      return localStorage.getItem(key);
    } catch (error) {
      // Storage can be unavailable for local files or restricted browser sessions.
      return selectedTheme;
    }
  }

  function isDark() {
    if (selectedTheme === "dark") {
      return true;
    }
    if (selectedTheme === "light") {
      return false;
    }
    return mql.matches;
  }

  function applyTheme() {
    root.classList.toggle("dark", selectedTheme === "dark");
    root.classList.toggle("light", selectedTheme === "light");
  }

  function syncLabel() {
    var button = document.getElementById("theme-toggle");
    if (!button) {
      return;
    }

    var dark = isDark();
    button.textContent = dark ? "Light mode" : "Dark mode";
    button.setAttribute("aria-label", dark ? "Switch to light mode" : "Switch to dark mode");
  }

  function syncTheme() {
    selectedTheme = storedTheme();
    applyTheme();
    syncLabel();
  }

  syncTheme();

  document.addEventListener("click", function (event) {
    var button = event.target && event.target.closest && event.target.closest("#theme-toggle");
    if (!button) {
      return;
    }

    selectedTheme = isDark() ? "light" : "dark";
    applyTheme();
    try {
      localStorage.setItem(key, selectedTheme);
    } catch (error) {
      // Keep the in-memory choice when the browser disallows persistence.
    }
    syncLabel();
  });

  document.addEventListener("DOMContentLoaded", syncLabel);
  window.addEventListener("pageshow", syncTheme);
  window.addEventListener("storage", function (event) {
    if (event.storageArea === localStorage && (event.key === key || event.key === null)) {
      syncTheme();
    }
  });
  // Follow later system changes while no explicit choice is stored.
  if (mql.addEventListener) {
    mql.addEventListener("change", syncLabel);
  }
})();
