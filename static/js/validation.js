document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("[data-registration-form]");
    if (!form) {
        return;
    }

    const password = form.elements.password;
    const confirmation = form.elements.confirm_password;
    const byteCount = document.querySelector("[data-password-byte-count]");

    function updatePasswordGuidance() {
        const bytes = new TextEncoder().encode(password.value).length;
        byteCount.textContent = `${bytes} / 72 UTF-8 bytes`;
        password.setCustomValidity(
            bytes > 72 ? "Password must not exceed 72 UTF-8 bytes." : ""
        );
    }

    function updateConfirmation() {
        confirmation.setCustomValidity(
            confirmation.value && confirmation.value !== password.value
                ? "Passwords do not match."
                : ""
        );
    }

    password.addEventListener("input", () => {
        updatePasswordGuidance();
        updateConfirmation();
    });
    confirmation.addEventListener("input", updateConfirmation);
});