// Initialize Bootstrap components
document.addEventListener('DOMContentLoaded', function () {
    // Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize message polling if on messages page
    if (document.getElementById('messages-list')) {
        checkMessages();
    }
});

// Filter resources by category
function filterByCategory(value, username) {
    const baseUrl = `/dashboard/${username}`;
    const search = document.getElementById('search') ? document.getElementById('search').value : '';
    let url = baseUrl;
    if (value || search) {
        url += '?';
        if (value) url += `category=${encodeURIComponent(value)}`;
        if (search) url += (value ? '&' : '') + `search=${encodeURIComponent(search)}`;
    }
    window.location.href = url;
}

// Search resources
function searchResources(username) {
    const search = document.getElementById('search').value;
    const category = document.getElementById('filter') ? document.getElementById('filter').value : '';
    const baseUrl = `/dashboard/${username}`;
    let url = baseUrl;
    if (category || search) {
        url += '?';
        if (category) url += `category=${encodeURIComponent(category)}`;
        if (search) url += (category ? '&' : '') + `search=${encodeURIComponent(search)}`;
    }
    window.location.href = url;
}

// Preview file
function previewFile(filename, username) {
    if (filename.endsWith('.pdf')) {
        // Use PDF.js for PDF preview
        const url = `/download/${filename}?username=${encodeURIComponent(username)}`;
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Preview: ${filename}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <canvas id="pdf-canvas"></canvas>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();

        // Load PDF.js
        const script = document.createElement('script');
        script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js';
        script.onload = async () => {
            pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js';
            try {
                const response = await fetch(url);
                const arrayBuffer = await response.arrayBuffer();
                const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
                const page = await pdf.getPage(1);
                const canvas = document.getElementById('pdf-canvas');
                const context = canvas.getContext('2d');
                const viewport = page.getViewport({ scale: 1.0 });
                canvas.height = viewport.height;
                canvas.width = viewport.width;
                await page.render({ canvasContext: context, viewport: viewport }).promise;
            } catch (error) {
                console.error('PDF preview failed:', error);
                alert('Failed to load PDF preview.');
            }
        };
        document.head.appendChild(script);
    } else if (filename.match(/\.(jpg|jpeg|png|gif)$/i)) {
        // Image preview
        const url = `/download/${filename}?username=${encodeURIComponent(username)}`;
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Preview: ${filename}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <img src="${url}" class="img-fluid" alt="${filename}">
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
    } else {
        alert('Preview not supported for this file type.');
    }
}

// Check for new messages via AJAX polling
function checkMessages() {
    const username = document.getElementById('messages-list')?.dataset.username;
    if (!username) return;

    async function pollMessages() {
        try {
            const response = await fetch(`/check_messages/${username}`);
            if (response.status === 403) {
                console.error('Unauthorized access to messages');
                return;
            }
            const messages = await response.json();
            const messagesList = document.getElementById('messages-list');
            messagesList.innerHTML = '';
            if (messages.length === 0) {
                messagesList.innerHTML = '<p>No messages yet.</p>';
            } else {
                messages.forEach(msg => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item';
                    li.innerHTML = `
                        <strong>${msg.sender}</strong> to <strong>${msg.recipient}</strong>: ${msg.content}
                        <small class="text-muted float-end">${new Date(msg.timestamp).toLocaleString()}</small>
                    `;
                    messagesList.appendChild(li);
                });
            }
        } catch (error) {
            console.error('Error fetching messages:', error);
        }
        setTimeout(pollMessages, 5000);
    }

    pollMessages();
}