// Main JavaScript for Fractured Keys Web Interface

// Utility Functions
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${getNotificationIcon(type)}"></i>
            <span>${message}</span>
        </div>
        <button class="notification-close" onclick="closeNotification(this)">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

function getNotificationIcon(type) {
    const icons = {
        'success': 'check-circle',
        'error': 'exclamation-circle',
        'warning': 'exclamation-triangle',
        'info': 'info-circle'
    };
    return icons[type] || 'info-circle';
}

function closeNotification(button) {
    button.parentElement.remove();
}

// Password visibility toggle
function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;
    const icon = button.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type = 'password';
        icon.className = 'fas fa-eye';
    }
}

// Copy to clipboard
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showNotification('Copied to clipboard!', 'success');
        }).catch(() => {
            fallbackCopyToClipboard(text);
        });
    } else {
        fallbackCopyToClipboard(text);
    }
}

function fallbackCopyToClipboard(text) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.left = '-999999px';
    textArea.style.top = '-999999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        document.execCommand('copy');
        showNotification('Copied to clipboard!', 'success');
    } catch (err) {
        showNotification('Failed to copy to clipboard', 'error');
    }
    
    document.body.removeChild(textArea);
}

// File size formatting
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Image preview functionality
function createImagePreview(file, container) {
    const reader = new FileReader();
    
    reader.onload = function(e) {
        const imageItem = document.createElement('div');
        imageItem.className = 'image-item';
        imageItem.innerHTML = `
            <img src="${e.target.result}" alt="${file.name}">
            <div class="image-info">
                <div class="image-name">${file.name}</div>
                <div class="image-size">${formatFileSize(file.size)}</div>
            </div>
            <button class="remove-image" onclick="removeImage(this)" title="Remove image">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        container.appendChild(imageItem);
    };
    
    reader.readAsDataURL(file);
}

function removeImage(button) {
    const imageItem = button.parentElement;
    const container = imageItem.parentElement;
    imageItem.remove();
    
    // Update file input if needed
    updateFileInput(container);
}

function updateFileInput(container) {
    // This is a simplified approach - in a real implementation,
    // you'd need to maintain a separate array of files
    const remainingImages = container.querySelectorAll('.image-item').length;
    console.log(`${remainingImages} images remaining`);
}

// Drag and drop functionality
function setupDragAndDrop(uploadArea, fileInput) {
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        
        const files = Array.from(e.dataTransfer.files);
        const imageFiles = files.filter(file => file.type.startsWith('image/'));
        
        if (imageFiles.length > 0) {
            // Update file input
            const dt = new DataTransfer();
            imageFiles.forEach(file => dt.items.add(file));
            fileInput.files = dt.files;
            
            // Trigger change event
            fileInput.dispatchEvent(new Event('change'));
        }
    });
}

// Form validation
function validateForm(formElement) {
    const requiredFields = formElement.querySelectorAll('[required]');
    let isValid = true;
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            field.classList.add('error');
            isValid = false;
        } else {
            field.classList.remove('error');
        }
    });
    
    return isValid;
}

// Loading overlay
function showLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'flex';
    }
}

function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
        overlay.style.display = 'none';
    }
}

// API request helper
async function makeRequest(url, options = {}) {
    try {
        showLoading();
        
        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
            }
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('Request error:', error);
        throw error;
    } finally {
        hideLoading();
    }
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
    
    // Add form validation styles
    const style = document.createElement('style');
    style.textContent = `
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            padding: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            z-index: 1001;
            min-width: 300px;
            animation: slideIn 0.3s ease;
        }
        
        .notification-success {
            border-left: 4px solid #059669;
        }
        
        .notification-error {
            border-left: 4px solid #dc2626;
        }
        
        .notification-warning {
            border-left: 4px solid #d97706;
        }
        
        .notification-info {
            border-left: 4px solid #0284c7;
        }
        
        .notification-content {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex: 1;
        }
        
        .notification-close {
            background: none;
            border: none;
            cursor: pointer;
            color: #64748b;
            padding: 0.25rem;
        }
        
        .notification-close:hover {
            color: #1e293b;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .form-group input.error,
        .form-group select.error,
        .form-group textarea.error {
            border-color: #dc2626;
        }
    `;
    document.head.appendChild(style);
});

// Export functions for use in other scripts
window.FracturedKeys = {
    showNotification,
    togglePassword,
    copyToClipboard,
    formatFileSize,
    createImagePreview,
    removeImage,
    setupDragAndDrop,
    validateForm,
    showLoading,
    hideLoading,
    makeRequest
};
