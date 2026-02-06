// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Password visibility toggles.
document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-toggle-password]");
  if (!button) {
    return;
  }

  const target = button.getAttribute("data-target");
  if (!target) {
    return;
  }

  const input = document.querySelector(target);
  if (!input) {
    return;
  }

  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
  button.setAttribute("aria-pressed", show ? "true" : "false");
});

// Password checklist validation.
const updatePasswordChecklist = (input, checklist) => {
  const value = input.value || "";
  const rules = [
    { key: "length", test: (v) => v.length >= 12 },
    { key: "lowercase", test: (v) => /[a-z]/.test(v) },
    { key: "uppercase", test: (v) => /[A-Z]/.test(v) },
    { key: "number", test: (v) => /\d/.test(v) },
    { key: "symbol", test: (v) => /[^A-Za-z\d]/.test(v) },
  ];

  rules.forEach((rule) => {
    const item = checklist.querySelector(`[data-rule="${rule.key}"]`);
    if (!item) {
      return;
    }
    item.classList.toggle("met", rule.test(value));
  });
};

document.querySelectorAll("[data-password-checklist]").forEach((checklist) => {
  const target = checklist.getAttribute("data-target");
  if (!target) {
    return;
  }

  const input = document.querySelector(target);
  if (!input) {
    return;
  }

  updatePasswordChecklist(input, checklist);
  input.addEventListener("input", () => updatePasswordChecklist(input, checklist));
});
