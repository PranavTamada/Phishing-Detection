document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('goBack').addEventListener('click', (e) => {
        e.preventDefault();
        window.history.back();
    });
}); 