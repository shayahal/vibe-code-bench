// script.js
document.addEventListener('DOMContentLoaded', function() {
    // Add your JavaScript code here
    const orderButtons = document.querySelectorAll('.item button');
    orderButtons.forEach(button => {
        button.addEventListener('click', () => {
            alert('Your order has been placed!');
        });
    });
});