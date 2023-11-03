function togglePasswordVisibility(inputId, icon) {
    var input = document.getElementById(inputId);
    if (input.type === "password") {
        input.type = "text";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    } else {
        input.type = "password";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    }
}

document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        var modal = document.getElementById('errorModal');
        var errorMessage = modal.getAttribute('data-bs-error-message');
        var errorType = modal.getAttribute('data-bs-error-type');
        if (errorMessage && errorType === 'error') {
            var errorModal = new bootstrap.Modal(modal);
            errorModal.show();
        }
    }, 0);
});