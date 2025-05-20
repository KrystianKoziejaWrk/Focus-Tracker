let isFocused = false;
let focusStart;
const statusEl = document.getElementById("focus-status");

document.addEventListener("keydown", async e => {
  if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "f") {
    e.preventDefault();
    isFocused = !isFocused;

    if (isFocused) {
      focusStart = new Date();
      statusEl.textContent = "Focused";
      statusEl.classList.replace("text-danger", "text-success");
    } else {
      const focusEnd = new Date();
      const duration = Math.round((focusEnd - focusStart) / 1000);

      statusEl.textContent = "Not Focused";
      statusEl.classList.replace("text-success", "text-danger");

      try {
        const res = await fetch(ADD_SESSION_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Source": "web"         // tell your endpoint this is a web event
          },
          credentials: "same-origin",  // send your JWT cookie
          body: JSON.stringify({ duration })
        });
        if (!res.ok) console.error("Add session failed:", await res.text());
      } catch (err) {
        console.error(err);
      }
    }
  }
});
