// Runs before the page paints, so a saved light theme does not flash dark first.
try { document.documentElement.dataset.theme = localStorage.getItem("suite_theme") || "dark"; } catch (e) { /* no storage */ }
