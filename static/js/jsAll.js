function showBootstrapToast(message, category = 'info', delay = 7000) {
    const toastContainer = document.querySelector('.toast-container');

    if (!toastContainer) {
        console.error('Toast container (.toast-container) not found in base.html!');
        alert(message);
        return;
    }

    const toastId = 'dynamic-toast-' + Date.now();
    const bgClass = `text-bg-${category}`;

    const toastHTML = `
    <div id="${toastId}" class="toast align-items-center ${bgClass} border-0" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body">
          ${message}  
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
      </div>
    </div>`;

    toastContainer.insertAdjacentHTML('beforeend', toastHTML);

    const toastElement = document.getElementById(toastId);

    if (toastElement) {
        const toast = new bootstrap.Toast(toastElement, {
            delay: delay
        });
        toast.show();

        toastElement.addEventListener('hidden.bs.toast', function () {
            toastElement.remove();
        });
    }
}
