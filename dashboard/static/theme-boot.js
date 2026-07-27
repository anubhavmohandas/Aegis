/* Apply the saved theme before first paint so there's no flash of the wrong
   one. Shared by index.html and login.html.

   This was an inline <script> in both pages until the dashboard grew a
   Content-Security-Policy (see dashboard/server.py's _send). A CSP that allows
   'unsafe-inline' for scripts forbids nothing, so the two inline blocks moved
   out here instead of the policy being weakened to keep them.

   Must stay a plain <script src> in <head> -- no defer, no async, no
   module. It has to run before the first paint, which is exactly what a
   render-blocking script in the head does; deferring it reintroduces the
   flash this file exists to prevent. */

document.documentElement.dataset.theme = localStorage.getItem("aegis-theme") || "obsidian";
