document.addEventListener("DOMContentLoaded", () => {
  const root = document.documentElement;
  const button = document.getElementById("themeToggle");

  const saved = localStorage.getItem("theme");
  if (saved) {
    root.setAttribute("data-theme", saved);
  }

  if (button) {
    button.addEventListener("click", () => {
      const current = root.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      localStorage.setItem("theme", next);
    });
  }
});