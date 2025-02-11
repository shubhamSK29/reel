document.getElementById("addVideo").addEventListener("click", function() {
    document.getElementById("videoInput").click(); // Opens file selection
});

// Update the file input element to accept multiple files
document.querySelector('#videoInput').setAttribute('multiple', '');

// Modify the upload handling
document.querySelector('#videoInput').addEventListener('change', async function(e) {
    const files = e.target.files;
    const reelsContainer = document.querySelector('.reels-container');
    
    for (let file of files) {
        // Create video URL
        const videoURL = URL.createObjectURL(file);
        
        // Create reel element
        const reelDiv = document.createElement('div');
        reelDiv.className = 'reel';
        
        // Create video element
        const video = document.createElement('video');
        video.src = videoURL;
        video.loop = true;
        video.muted = true;
        
        // Create delete button
        const deleteButton = document.createElement('button');
        deleteButton.className = 'delete-button';
        deleteButton.innerHTML = '×';
        deleteButton.onclick = function() {
            reelDiv.remove();
            // No need to store deleted video names anymore
            handleVideoVisibility(); // Update video playback states
        };
        
        // Append elements
        reelDiv.appendChild(video);
        reelDiv.appendChild(deleteButton);
        reelsContainer.appendChild(reelDiv);
        
        // Add loading event listener
        video.addEventListener('loadedmetadata', () => {
            handleVideoVisibility();
        });
    }
    
    // Reset the input to allow re-uploading the same file
    e.target.value = '';
});

// Function to handle video visibility and playback
function handleVideoVisibility() {
    const videos = document.querySelectorAll('.reel video');
    
    videos.forEach(video => {
        const rect = video.getBoundingClientRect();
        const visibleHeight = Math.min(rect.bottom, window.innerHeight) - Math.max(rect.top, 0);
        const isVisible = visibleHeight > rect.height / 2;

        if (isVisible) {
            video.play();
            video.muted = false;  // Unmute the visible video
        } else {
            video.pause();
            video.currentTime = 0;  // Reset video position
            video.muted = true;  // Mute hidden videos
        }
    });
}

// Add scroll event listener to manage video playback
document.querySelector('.reels-container').addEventListener('scroll', handleVideoVisibility);

// Initial call to handle video visibility when page loads
handleVideoVisibility();

// Modify the existing keydown event listener
document.addEventListener('keydown', (e) => {
    const reelsContainer = document.querySelector('.reels-container');
    const videos = document.querySelectorAll('.reel video');
    
    const currentVideo = Array.from(videos).find(video => {
        const rect = video.getBoundingClientRect();
        const visibleHeight = Math.min(rect.bottom, window.innerHeight) - Math.max(rect.top, 0);
        return visibleHeight > rect.height / 2;
    });

    switch (e.code) {
        case 'Space':
            e.preventDefault();
            if (currentVideo) {
                if (currentVideo.paused) {
                    currentVideo.play();
                } else {
                    currentVideo.pause();
                }
            }
            break;

        case 'PageUp':
            e.preventDefault();
            const previousVideo = currentVideo?.closest('.reel')?.previousElementSibling;
            if (previousVideo) {
                previousVideo.scrollIntoView({ behavior: 'smooth' });
                // Wait for scroll to complete before handling visibility
                setTimeout(handleVideoVisibility, 500);
            }
            break;

        case 'PageDown':
            e.preventDefault();
            const nextVideo = currentVideo?.closest('.reel')?.nextElementSibling;
            if (nextVideo) {
                nextVideo.scrollIntoView({ behavior: 'smooth' });
                // Wait for scroll to complete before handling visibility
                setTimeout(handleVideoVisibility, 500);
            }
            break;
    }
});