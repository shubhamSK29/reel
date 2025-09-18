// Decryption page JavaScript

let selectedStegoFiles = [];

// Handle file selection for steganographic images
function handleStegoFileSelection(files) {
    const imagePreview = document.getElementById('imagePreview');
    
    // Clear previous previews
    imagePreview.innerHTML = '';
    selectedStegoFiles = [];
    
    // Filter and validate image files
    const imageFiles = Array.from(files).filter(file => {
        return file.type.startsWith('image/');
    });
    
    if (imageFiles.length === 0) {
        FracturedKeys.showNotification('Please select valid image files', 'error');
        return;
    }
    
    // Store selected files
    selectedStegoFiles = imageFiles;
    
    // Create previews
    selectedStegoFiles.forEach((file, index) => {
        FracturedKeys.createImagePreview(file, imagePreview);
    });
    
    // Update upload area
    const uploadArea = document.getElementById('imageUploadArea');
    const placeholder = uploadArea.querySelector('.upload-placeholder');
    if (selectedStegoFiles.length > 0) {
        placeholder.innerHTML = `
            <i class="fas fa-check-circle" style="color: #059669;"></i>
            <p>${selectedStegoFiles.length} steganographic images selected</p>
            <small>Click to select different images</small>
        `;
    }
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
    document.getElementById('decryptForm').reset();
    document.getElementById('imagePreview').innerHTML = '';
    selectedStegoFiles = [];
    
    // Hide result and error sections
    document.getElementById('resultSection').style.display = 'none';
    document.getElementById('errorSection').style.display = 'none';
    
    // Reset upload area
    const uploadArea = document.getElementById('imageUploadArea');
    const placeholder = uploadArea.querySelector('.upload-placeholder');
    placeholder.innerHTML = `
        <i class="fas fa-cloud-upload-alt"></i>
        <p>Click to select images or drag and drop</p>
        <small>Upload your steganographic images (PNG, JPG, GIF, BMP, TIFF)</small>
    `;
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Handle form submission
async function handleDecryption(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData();
    
    // Validate form
    if (!FracturedKeys.validateForm(form)) {
        FracturedKeys.showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    // Check if images are selected
    if (selectedStegoFiles.length === 0) {
        FracturedKeys.showNotification('Please select at least one steganographic image', 'error');
        return;
    }
    
    // Add form data
    formData.append('master_password', document.getElementById('master_password').value);
    
    // Add image files
    selectedStegoFiles.forEach((file, index) => {
        formData.append('stego_images', file);
    });
    
    try {
        FracturedKeys.showLoading();
        
        const response = await fetch('/decrypt', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayDecryptionResults(result);
            FracturedKeys.showNotification('Decryption completed successfully!', 'success');
        } else {
            displayDecryptionError(result.error);
        }
    } catch (error) {
        console.error('Decryption error:', error);
        displayDecryptionError(`Network error: ${error.message}`);
    } finally {
        FracturedKeys.hideLoading();
    }
}

// Display decryption results
function displayDecryptionResults(result) {
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const passwordInput = document.getElementById('recoveredPassword');
    
    // Hide error section
    errorSection.style.display = 'none';
    
    // Set recovered password
    passwordInput.value = result.password;
    
    // Show result section
    resultSection.style.display = 'block';
    
    // Scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth' });
}

// Display decryption error
function displayDecryptionError(errorMessage) {
    const resultSection = document.getElementById('resultSection');
    const errorSection = document.getElementById('errorSection');
    const errorMessageElement = document.getElementById('errorMessage');
    
    // Hide result section
    resultSection.style.display = 'none';
    
    // Set error message
    errorMessageElement.textContent = errorMessage;
    
    // Show error section
    errorSection.style.display = 'block';
    
    // Show notification
    FracturedKeys.showNotification(`Decryption failed: ${errorMessage}`, 'error');
    
    // Scroll to error
    errorSection.scrollIntoView({ behavior: 'smooth' });
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Set up form submission
    const decryptForm = document.getElementById('decryptForm');
    if (decryptForm) {
        decryptForm.addEventListener('submit', handleDecryption);
    }
    
    // Set up file input
    const imageInput = document.getElementById('stego_images');
    const uploadArea = document.getElementById('imageUploadArea');
    
    if (imageInput && uploadArea) {
        // Handle file input change
        imageInput.addEventListener('change', function(e) {
            handleStegoFileSelection(e.target.files);
        });
        
        // Set up drag and drop
        FracturedKeys.setupDragAndDrop(uploadArea, imageInput);
    }
    
    // Set up password input security
    const passwordInput = document.getElementById('recoveredPassword');
    if (passwordInput) {
        // Auto-select text when focused for easy copying
        passwordInput.addEventListener('focus', function() {
            this.select();
        });
        
        // Warn about password visibility
        passwordInput.addEventListener('input', function() {
            if (this.type === 'text' && this.value) {
                // Could add a warning about password being visible
            }
        });
    }
    
    // Add keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl+C or Cmd+C to copy password when in result section
        if ((e.ctrlKey || e.metaKey) && e.key === 'c') {
            const resultSection = document.getElementById('resultSection');
            if (resultSection && resultSection.style.display === 'block') {
                const passwordInput = document.getElementById('recoveredPassword');
                if (document.activeElement === passwordInput) {
                    // Let default copy behavior work
                    return;
                }
                // If not focused on password input, copy it anyway
                e.preventDefault();
                copyPassword();
            }
        }
        
        // Escape to clear password
        if (e.key === 'Escape') {
            const resultSection = document.getElementById('resultSection');
            if (resultSection && resultSection.style.display === 'block') {
                clearPassword();
            }
        }
    });
    
    // Add security warning for password display
    const style = document.createElement('style');
    style.textContent = `
        .password-display input[type="text"] {
            background-color: #fef3c7;
            border-color: #d97706;
        }
        
        .security-warning {
            display: none;
            background: #fef3c7;
            border: 1px solid #d97706;
            border-radius: 0.5rem;
            padding: 0.75rem;
            margin-top: 0.5rem;
            font-size: 0.875rem;
            color: #92400e;
        }
        
        .password-display input[type="text"] + .toggle-password + .copy-password + .security-warning {
            display: block;
        }
    `;
    document.head.appendChild(style);
});

// Make functions available globally
window.copyPassword = copyPassword;
window.clearPassword = clearPassword;
window.startNewDecryption = startNewDecryption;
