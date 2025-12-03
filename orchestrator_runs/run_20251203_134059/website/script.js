document.addEventListener('DOMContentLoaded', function() {
    // Get all the order buttons
    const orderButtons = document.querySelectorAll('.order-btn');

    // Add click event listener to each order button
    orderButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            alert('Your order has been placed!');
        });
    });

    // Get the contact form
    const contactForm = document.querySelector('.contact form');

    // Add submit event listener to the contact form
    contactForm.addEventListener('submit', function(event) {
        event.preventDefault(); // Prevent the default form submission

        // Get the form data
        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const message = document.getElementById('message').value;

        // Log the form data to the console
        console.log('Name:', name);
        console.log('Email:', email);
        console.log('Message:', message);

        // Reset the form fields
        contactForm.reset();

        alert('Your message has been sent!');
    });
});