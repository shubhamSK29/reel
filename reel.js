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
