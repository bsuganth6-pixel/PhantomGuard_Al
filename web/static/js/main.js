// Tab switching + example-text chips for the scan panel.
document.addEventListener("DOMContentLoaded", function () {
  const tabButtons = document.querySelectorAll(".tab-btn");
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById("tab-" + btn.dataset.tab).classList.add("active");
    });
  });

  const exampleChips = document.querySelectorAll(".example-chip");
  const textarea = document.querySelector('textarea[name="text"]');
  exampleChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      if (textarea) {
        textarea.value = chip.dataset.example;
        textarea.focus();
      }
    });
  });
});
