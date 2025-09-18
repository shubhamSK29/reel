// Manual Decryption page JavaScript

// Switch between methods
function switchMethod(method) {
    const fileMethod = document.getElementById('fileMethod');
    const base64Method = document.getElementById('base64Method');
    const decryptType = document.getElementById('decrypt_type');
    const tabs = document.querySelectorAll('.method-tab');

    tabs.forEach(tab => tab.classList.remove('active'));
    const activeTab = document.querySelector(`.method-tab[data-method="${method}"]`);
    if (activeTab) activeTab.classList.add('active');

    if (method === 'file') {
        fileMethod.classList.add('active');
        base64Method.classList.remove('active');
        decryptType.value = 'file';
    } else {
        fileMethod.classList.remove('active');
        base64Method.classList.add('active');
        decryptType.value = 'base64';
    }
}

// Validate base64 string
function validateBase64() {
    const textarea = document.getElementById('base64_data');
    const value = textarea.value.trim();
    if (!value) {
        FracturedKeys.showNotification('Please paste base64 data', 'warning');
        return false;
    }
    try {
        atob(value);
        FracturedKeys.showNotification('Base64 looks valid', 'success');
        return true;
    } catch (e) {
        FracturedKeys.showNotification('Invalid base64 data', 'error');
        return false;
    }
}

function clearBase64() {
    const textarea = document.getElementById('base64_data');
    textarea.value = '';
}

// Copy recovered password to clipboard
function copyPassword() {
    const passwordInput = document.getElementById('recoveredPassword');
    const password = passwordInput.value;
    if (password) {
        FracturedKeys.copyToClipboard(password);
    } else {
        FracturedKeys.showNotification('No password to copy', 'warning');
    }
}

// Clear password from display
function clearPassword() {
    const passwordInput = document.getElementById('recoveredPassword');
    passwordInput.value = '';
    FracturedKeys.showNotification('Password cleared from display', 'info');
}

// Start new decryption
function startNewDecryption() {
    // Reset form
    document.getElementById('manualDecryptForm').reset();
    document.getElementById('fileInfo').style.display = 'none';
    
    // Hide result and error sections
    document.getElementById('resultSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'none';
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Handle file selection display
function handleBinaryFileSelection(fileInput) {
    const file = fileInput.files[0];
    const fileInfo = document.getElementById('fileInfo');
    
    if (file) {
        fileInfo.style.display = 'block';
        fileInfo.querySelector('.file-name').textContent = file.name;
        fileInfo.querySelector('.file-size').textContent = FracturedKeys.formatFileSize(file.size);
    } else {
        fileInfo.style.display = 'none';
    }
}

// Handle form submission
async function handleManualDecryption(event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData();
    const decryptType = document.getElementById('decrypt_type').value;

    // Validate form
    if (!FracturedKeys.validateForm(form)) {
        FracturedKeys.showNotification('Please fill in all required fields', 'error');
        return;
    }

    // Add form data
    formData.append('master_password', document.getElementById('master_password').value);
    formData.append('decrypt_type', decryptType);

    if (decryptType === 'file') {
        const fileInput = document.getElementById('binary_file');
        if (!fileInput.files[0]) {
            FracturedKeys.showNotification('Please select a binary file', 'error');
            return;
        }
        formData.append('binary_file', fileInput.files[0]);
    } else {
        const base64Data = document.getElementById('base64_data').value.trim();
        if (!base64Data) {
            FracturedKeys.showNotification('Please paste base64 data', 'error');
            return;
        }
        formData.append('base64_data', base64Data);
    }

    try {
        FracturedKeys.showLoading();

        const response = await fetch('/manual_decrypt', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (result.success) {
            displayManualDecryptionResults(result);
            FracturedKeys.showNotification('Decryption completed successfully!', 'success');
        } else {
            displayManualDecryptionError(result.error);
        }
    } catch (error) {
        console.error('Manual decryption error:', error);
        displayManualDecryptionError(`Network error: ${error.message}`);
    } finally {
        FracturedKeys.hideLoading();
    }
}

function displayManualDecryptionResults(result) {
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const passwordInput = document.getElementById('recoveredPassword');

    // Hide error section
    errorSection.style.display = 'none';

    // Set recovered password
    passwordInput.value = result.password;

    // Show result section
    resultSection.style.display = 'block';
    resultSection.scrollIntoView({ behavior: 'smooth' });
}

function displayManualDecryptionError(errorMessage) {
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const errorMessageElement = document.getElementById('errorMessage');

    // Hide result section
    resultSection.style.display = 'none';

    // Set error message
    errorMessageElement.textContent = errorMessage;

    // Show error section
    errorSection.style.display = 'block';
    FracturedKeys.showNotification(`Decryption failed: ${errorMessage}`, 'error');
    errorSection.scrollIntoView({ behavior: 'smooth' });
}

// Initialize page

document.addEventListener('DOMContentLoaded', function() {
    // Method switching
    const tabs = document.querySelectorAll('.method-tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const method = this.getAttribute('data-method');
            switchMethod(method);
        });
    });

    // File input handling
    const fileInput = document.getElementById('binary_file');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            handleBinaryFileSelection(e.target);
        });
    }

    // Form submission
    const form = document.getElementById('manualDecryptForm');
    if (form) {
        form.addEventListener('submit', handleManualDecryption);
    }
});

// Expose functions
window.switchMethod = switchMethod;
window.validateBase64 = validateBase64;
window.clearBase64 = clearBase64;
window.copyPassword = copyPassword;
window.clearPassword = clearPassword;
window.startNewDecryption = startNewDecryption;
