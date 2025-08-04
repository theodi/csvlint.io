document.addEventListener("DOMContentLoaded", function() {
  const section = document.querySelector("section.white.main");
  const id = section.getAttribute("data-id");
  if (id) {
    const newUrl = `/validation/${id}`;
    history.pushState({ path: newUrl }, '', newUrl);
  }
}); 