document.addEventListener('DOMContentLoaded', function() {
    // Add event listener to order buttons
    const orderButtons = document.querySelectorAll('.menu-items button');
    orderButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            alert('Thank you for your order!');
        });
    });
});