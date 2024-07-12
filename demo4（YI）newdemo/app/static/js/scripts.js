// main.js

// JavaScript for Update Account Form
document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('update-account-form');
    const loader = document.getElementById('loader');
    const notification = document.getElementById('notification');

    if (form) {
        form.addEventListener('submit', async (event) => {
            event.preventDefault();

            const formData = new FormData(form);

            // Reset validation states
            resetValidationStates();

            // Client-side validation
            const username = formData.get('username');
            const email = formData.get('email');
            let validationPassed = true;

            // Username validation
            if (username.length < 2 || username.length > 20) {
                showValidationError('username', 'Username must be between 2 and 20 characters.');
                validationPassed = false;
            }

            // Email validation
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailPattern.test(email)) {
                showValidationError('email', 'Invalid email format.');
                validationPassed = false;
            }

            if (!validationPassed) {
                return;
            }

            // Show loader during AJAX request
            loader.style.display = 'inline-block';
            showNotification('Updating your account...', 'info');

            try {
                const response = await fetch('/account', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (result.success) {
                    showNotification('Account updated successfully!', 'success');
                    // Optionally update the UI based on server response.
                } else {
                    showNotification('Error updating account.', 'danger');
                }
            } catch (error) {
                console.error('Error:', error);
                showNotification('An unexpected error occurred.', 'danger');
            } finally {
                loader.style.display = 'none';
            }
        });
    }

    function showNotification(message, type) {
        notification.textContent = message;
        notification.className = `alert alert-${type}`;
        notification.style.display = 'block';
        setTimeout(() => {
            notification.style.display = 'none';
        }, 3000);
    }

    function showValidationError(inputName, errorMessage) {
        const inputElement = form.querySelector(`[name="${inputName}"]`);
        inputElement.classList.add('is-invalid');
        showNotification(errorMessage, 'danger');
    }

    function resetValidationStates() {
        const inputs = form.querySelectorAll('input');
        inputs.forEach(input => {
            input.classList.remove('is-invalid');
            input.classList.remove('is-valid');
        });
    }
});