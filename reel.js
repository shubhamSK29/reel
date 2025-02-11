document.getElementById("addVideo").addEventListener("click", function() {
    document.getElementById("videoInput").click(); // Opens file selection
});

document.getElementById("videoInput").addEventListener("change", function(event) {
    const file = event.target.files[0];

    if (file) {
        const videoURL = URL.createObjectURL(file); // Generate URL for the selected file
        const reelsContainer = document.getElementById("reelsContainer");

        // Create a new reel container
        const reel = document.createElement("div");
        reel.classList.add("reel");

        // Create a new video element
        const video = document.createElement("video");
        video.src = videoURL;
        video.controls = true;
        video.autoplay = true;
        video.loop = true;

        // Create a delete button
        const deleteButton = document.createElement("button");
        deleteButton.classList.add("delete-button");
        deleteButton.innerHTML = "❌";

        // Delete functionality
        deleteButton.addEventListener("click", function() {
            reelsContainer.removeChild(reel); // Remove the video from the list
        });

        // Append video and delete button to reel
        reel.appendChild(video);
        reel.appendChild(deleteButton);

        // Append reel to container
        reelsContainer.appendChild(reel);
    }
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