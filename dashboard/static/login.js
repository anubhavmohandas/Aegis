/* Sign-in form handler. Moved out of login.html so the dashboard's
   Content-Security-Policy can forbid inline script outright -- see
   dashboard/server.py's _send and the note in theme-boot.js.

   Served pre-authentication, so it is listed in server.py's PUBLIC_FILES
   alongside login.html, style.css and the fonts. It contains nothing secret:
   it posts the form to /api/login and renders whatever comes back. */

"use strict";

const form = document.getElementById("form");
const errorBox = document.getElementById("error");
const submit = document.getElementById("submit");
const card = document.getElementById("card");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  errorBox.hidden = true;
  submit.disabled = true;
  submit.textContent = "Authenticating…";
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("username").value,
        password: document.getElementById("password").value,
      }),
    });
    if (res.ok) {
      submit.textContent = "Access granted";
      location.replace("/");
      return;
    }
    // 401 keeps the generic wording on purpose — the server never says which
    // half was wrong. Anything else (notably the 429 lockout) carries a
    // message worth reading: "locked for 60s" beats "Sign-in failed (429)."
    const data = await res.json().catch(() => ({}));
    errorBox.textContent = res.status === 401
      ? "Invalid credentials — access denied."
      : (data.error || `Sign-in failed (${res.status}).`);
  } catch {
    errorBox.textContent = "Aegis unreachable — is the server running?";
  }
  errorBox.hidden = false;
  card.classList.remove("shake");
  void card.offsetWidth;              // restart the animation
  card.classList.add("shake");
  document.getElementById("password").value = "";
  document.getElementById("password").focus();
  submit.disabled = false;
  submit.textContent = "Authenticate";
});
