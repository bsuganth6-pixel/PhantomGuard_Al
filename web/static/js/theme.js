// Light/dark theme toggle. The initial theme is already set synchronously
// by the inline script in base.html's <head> (avoids a flash of the wrong
// theme) -- this file only wires up the button once the DOM is ready.
document.addEventListener("DOMContentLoaded", function () {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;

  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") || "light";
  }

  function applyLabel() {
    const isDark = currentTheme() === "dark";
    btn.setAttribute("aria-label", isDark ? "Switch to light theme" : "Switch to dark theme");
  }

  btn.addEventListener("click", function () {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("phantomguard-theme", next);
    applyLabel();
  });

  applyLabel();
});
