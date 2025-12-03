document.addEventListener('DOMContentLoaded', function() {
    // Add to cart functionality
    const addToCartButtons = document.querySelectorAll('.add-to-cart');
    addToCartButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            alert('Item added to cart!');
        });
    });

    // Order button functionality
    const orderBtn = document.querySelector('.order-btn');
    orderBtn.addEventListener('click', function() {
        window.location.href = '#'; // Replace with your order page URL
    });
});