// Encryption page JavaScript

let selectedFiles = [];

// Update threshold options based on total shares
function updateThresholdOptions() {
    const totalShares = parseInt(document.getElementById('total_shares').value);
    const thresholdSelect = document.getElementById('threshold');
    const sharesCount = document.getElementById('shares-count');
    const thresholdCount = document.getElementById('threshold-count');
    const requiredImages = document.getElementById('required-images');
    
    // Clear existing options
    thresholdSelect.innerHTML = '';
    
    // Add threshold options (from 2 to total_shares)
    for (let i = 2; i <= totalShares; i++) {
        const option = document.createElement('option');
        option.value = i;
        option.textContent = `${i} shares`;
        if (i === 2) option.selected = true;
        thresholdSelect.appendChild(option);
    }
    
    // Update display text
    const currentThreshold = thresholdSelect.value;
    sharesCount.textContent = totalShares;
    thresholdCount.textContent = currentThreshold;
    requiredImages.textContent = totalShares;
    
    // Update threshold count when threshold changes
    thresholdSelect.addEventListener('change', function() {
        thresholdCount.textContent = this.value;
    });
}

// Handle file selection
function handleFileSelection(files) {
    const imagePreview = document.getElementById('imagePreview');
    const totalShares = parseInt(document.getElementById('total_shares').value);
    
    // Clear previous previews
    imagePreview.innerHTML = '';
    selectedFiles = [];
    
    // Filter and validate image files
    const imageFiles = Array.from(files).filter(file => {
        return file.type.startsWith('image/');
    });
    
    if (imageFiles.length === 0) {
        FracturedKeys.showNotification('Please select valid image files', 'error');
        return;
    }
    
    if (imageFiles.length < totalShares) {
        FracturedKeys.showNotification(`Please select at least ${totalShares} images`, 'warning');
    }
    
    // Store selected files
    selectedFiles = imageFiles.slice(0, totalShares);
    
    // Create previews
    selectedFiles.forEach((file, index) => {
        FracturedKeys.createImagePreview(file, imagePreview);
    });
    
    // Update upload area
    const uploadArea = document.getElementById('imageUploadArea');
    const placeholder = uploadArea.querySelector('.upload-placeholder');
    if (selectedFiles.length > 0) {
        placeholder.innerHTML = `
            <i class="fas fa-check-circle" style="color: #059669;"></i>
            <p>${selectedFiles.length} images selected</p>
            <small>Click to select different images</small>
        `;
    }
}

// Download individual image
function downloadImage(imageData, filename) {
    const link = document.createElement('a');
    link.href = `data:image/png;base64,${imageData}`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Download all images as ZIP (simplified - individual downloads)
function downloadAllImages() {
    const stegoImages = document.querySelectorAll('.stego-image');
    stegoImages.forEach((imageDiv, index) => {
        const downloadBtn = imageDiv.querySelector('.download-btn');
        setTimeout(() => {
            downloadBtn.click();
        }, index * 500); // Stagger downloads
    });
}

// Start new encryption
function startNewEncryption() {
    // Reset form
    document.getElementById('encryptForm').reset();
    document.getElementById('imagePreview').innerHTML = '';
    selectedFiles = [];
    
    // Hide result section
    document.getElementById('resultSection').style.display = 'none';
    
    // Reset upload area
    const uploadArea = document.getElementById('imageUploadArea');
    const placeholder = uploadArea.querySelector('.upload-placeholder');
    placeholder.innerHTML = `
        <i class="fas fa-cloud-upload-alt"></i>
        <p>Click to select images or drag and drop</p>
        <small>Upload at least <span id="required-images">3</span> images (PNG, JPG, GIF, BMP, TIFF)</small>
    `;
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// Handle form submission
async function handleEncryption(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData();
    
    // Validate form
    if (!FracturedKeys.validateForm(form)) {
        FracturedKeys.showNotification('Please fill in all required fields', 'error');
        return;
    }
    
    // Check if enough images are selected
    const totalShares = parseInt(document.getElementById('total_shares').value);
    if (selectedFiles.length < totalShares) {
        FracturedKeys.showNotification(`Please select at least ${totalShares} images`, 'error');
        return;
    }
    
    // Add form data
    formData.append('password', document.getElementById('password').value);
    formData.append('master_password', document.getElementById('master_password').value);
    formData.append('threshold', document.getElementById('threshold').value);
    formData.append('total_shares', document.getElementById('total_shares').value);
    
    // Add image files
    selectedFiles.forEach((file, index) => {
        formData.append('images', file);
    });
    
    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (result.success) {
            displayEncryptionResults(result);
            FracturedKeys.showNotification('Encryption completed successfully!', 'success');
        } else {
            throw new Error(result.error);
        }
    } catch (error) {
        console.error('Encryption error:', error);
        FracturedKeys.showNotification(`Encryption failed: ${error.message}`, 'error');
    }
}

// Display encryption results
function displayEncryptionResults(result) {
    const resultSection = document.getElementById('resultSection');
    const stegoImagesContainer = document.getElementById('stegoImages');
    
    // Update result info
    document.getElementById('resultShares').textContent = result.total_shares;
    document.getElementById('resultThreshold').textContent = result.threshold;
    document.getElementById('warningThreshold').textContent = result.threshold;
    
    // Clear previous results
    stegoImagesContainer.innerHTML = '';
    
    // Display steganographic images
    result.images.forEach((imageInfo, index) => {
        const imageDiv = document.createElement('div');
        imageDiv.className = 'stego-image';
        imageDiv.innerHTML = `
            <img src="data:image/png;base64,${imageInfo.data}" alt="${imageInfo.filename}">
            <div class="image-title">Share ${imageInfo.share_index}</div>
            <button class="download-btn" onclick="downloadImage('${imageInfo.data}', '${imageInfo.filename}')">
                <i class="fas fa-download"></i> Download
            </button>
        `;
        stegoImagesContainer.appendChild(imageDiv);
    });
    
    // Show result section
    resultSection.style.display = 'block';
    
    // Scroll to results
    resultSection.scrollIntoView({ behavior: 'smooth' });
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Set up form submission
    const encryptForm = document.getElementById('encryptForm');
    if (encryptForm) {
        encryptForm.addEventListener('submit', handleEncryption);
    }
    
    // Set up file input
    const imageInput = document.getElementById('images');
    const uploadArea = document.getElementById('imageUploadArea');
    
    if (imageInput && uploadArea) {
        // Handle file input change
        imageInput.addEventListener('change', function(e) {
            handleFileSelection(e.target.files);
        });
        
        // Set up drag and drop
        FracturedKeys.setupDragAndDrop(uploadArea, imageInput);
    }
    
    // Initialize threshold options
    updateThresholdOptions();
    
    // Set up total shares change handler
    const totalSharesSelect = document.getElementById('total_shares');
    if (totalSharesSelect) {
        totalSharesSelect.addEventListener('change', function() {
            updateThresholdOptions();
            // Clear selected files if we need more
            const newTotal = parseInt(this.value);
            if (selectedFiles.length < newTotal) {
                const imagePreview = document.getElementById('imagePreview');
                imagePreview.innerHTML = '';
                selectedFiles = [];
                
                // Reset upload area
                const placeholder = uploadArea.querySelector('.upload-placeholder');
                placeholder.innerHTML = `
                    <i class="fas fa-cloud-upload-alt"></i>
                    <p>Click to select images or drag and drop</p>
                    <small>Upload at least <span id="required-images">${newTotal}</span> images (PNG, JPG, GIF, BMP, TIFF)</small>
                `;
            }
        });
    }
    
    // Password strength indicator (optional enhancement)
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            // Could add password strength indicator here
        });
    }
});

// Make functions available globally
window.updateThresholdOptions = updateThresholdOptions;
window.downloadImage = downloadImage;
window.downloadAllImages = downloadAllImages;
window.startNewEncryption = startNewEncryption;
