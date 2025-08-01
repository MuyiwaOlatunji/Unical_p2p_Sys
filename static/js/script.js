// Utility function to initialize Bootstrap components
function initializeBootstrap() {
    // Initialize tooltips
    const tooltipTriggers = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggers.forEach(trigger => new bootstrap.Tooltip(trigger));
}

// Navigate to dashboard with filters
function navigateWithFilters(username, category = '', search = '') {
    let url = `/dashboard/${encodeURIComponent(username)}`;
    const params = [];
    if (category) params.push(`category=${encodeURIComponent(category)}`);
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    if (params.length) url += `?${params.join('&')}`;
    window.location.href = url;
}

// Filter resources by category
function filterByCategory(value, username) {
    const searchInput = document.getElementById('search');
    const search = searchInput ? searchInput.value : '';
    navigateWithFilters(username, value, search);
}

// Search resources
function searchResources(username) {
    const search = document.getElementById('search')?.value || '';
    const category = document.getElementById('filterCategory')?.value || '';
    navigateWithFilters(username, category, search);
}

// Download a file
function downloadFile(filename, username) {
    try {
        const url = `/download/${encodeURIComponent(filename)}?username=${encodeURIComponent(username)}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    } catch (error) {
        console.error('Download failed:', error);
        alert('Failed to initiate download.');
    }
}

// Preview a file (PDF or image)
async function previewFile(filename, username) {
    const url = `/download/${encodeURIComponent(filename)}?username=${encodeURIComponent(username)}`;
    const modal = document.createElement('div');
    modal.className = 'modal fade';
    modal.innerHTML = `
        <div class="modal-dialog ${filename.endsWith('.pdf') ? 'modal-lg' : ''}">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Preview: ${filename}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body" id="previewContent">
                    ${filename.endsWith('.pdf') ? '<canvas id="pdf-canvas"></canvas>' : `<img src="${url}" class="img-fluid" alt="${filename}">`}
                </div>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    const bsModal = new bootstrap.Modal(modal);
    bsModal.show();

    if (filename.endsWith('.pdf')) {
        try {
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.min.js';
            script.onload = async () => {
                pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/2.10.377/pdf.worker.min.js';
                try {
                    const response = await fetch(url, { credentials: 'include' });
                    if (!response.ok) throw new Error(`HTTP ${response.status}`);
                    const arrayBuffer = await response.arrayBuffer();
                    const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
                    const page = await pdf.getPage(1);
                    const canvas = document.getElementById('pdf-canvas');
                    const context = canvas.getContext('2d');
                    const viewport = page.getViewport({ scale: 1.0 });
                    canvas.height = viewport.height;
                    canvas.width = viewport.width;
                    await page.render({ canvasContext: context, viewport }).promise;
                } catch (error) {
                    console.error('PDF preview failed:', error);
                    alert('Failed to load PDF preview.');
                    bsModal.hide();
                }
            };
            script.onerror = () => {
                console.error('Failed to load PDF.js');
                alert('Failed to load PDF preview library.');
                bsModal.hide();
            };
            document.head.appendChild(script);
        } catch (error) {
            console.error('PDF preview setup failed:', error);
            alert('Failed to set up PDF preview.');
            bsModal.hide();
        }
    } else if (!filename.match(/\.(jpg|jpeg|png|gif)$/i)) {
        console.warn('Unsupported file type for preview:', filename);
        alert('Preview not supported for this file type.');
        bsModal.hide();
    }

    // Clean up modal on hide
    modal.addEventListener('hidden.bs.modal', () => modal.remove());
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeBootstrap();
});