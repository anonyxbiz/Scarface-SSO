// Dashboard logic
let app_loader = document.querySelector("#app_loader");
let container = document.querySelector(".container");

document.addEventListener('DOMContentLoaded', async () => {
    try {
        app_loader.style.display = "none";
        container.style.display = "";
    } catch (error) {
        console.error('Error in 404 logic:', error);
    }
});
