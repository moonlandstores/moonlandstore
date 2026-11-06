// script.js - Moonland Store Shared Functions

function getCart() {
    return JSON.parse(localStorage.getItem('moonland_cart') || '[]');
}

function saveCart(cart) {
    localStorage.setItem('moonland_cart', JSON.stringify(cart));
    updateGlobalCartCount();
}

function updateGlobalCartCount() {
    let cart = getCart();
    let totalCount = cart.reduce((sum, item) => sum + (Number(item.quantity || item.qty || 1)), 0);
    const badges = document.querySelectorAll('#cartCountBadge');
    badges.forEach(badge => {
        badge.innerText = totalCount;
    });
}

function addToCart(title, price, quantity = 1) {
    let cart = getCart();
    let existing = cart.find(i => (i.title === title || i.name === title));
    if (existing) {
        existing.quantity = (Number(existing.quantity || existing.qty || 1)) + Number(quantity);
    } else {
        cart.push({ title: title, name: title, price: Number(price), quantity: Number(quantity) });
    }
    saveCart(cart);
    alert('Product successfully cart mein add ho gaya hai!');
}

// Compact & Responsive Key Features / Specifications Renderer for Mobile & Desktop
function renderCompactSpecs(specsStr) {
    if (!specsStr) return '<p class="text-zinc-500 text-[11px]">None</p>';
    
    let items = specsStr.split(',');
    return `<div class="grid grid-cols-2 gap-2">` + items.map(item => {
        let parts = item.split(':');
        let label = parts[0] ? parts[0].trim() : '';
        let val = parts[1] ? parts[1].trim() : '';
        if (!label) return '';
        return `
            <div class="bg-[#0c0c0c] border border-zinc-800 p-2 space-y-0.5">
                <div class="text-[9px] uppercase tracking-wider text-zinc-500 font-bold">${label}</div>
                <div class="text-[11px] text-white font-medium">${val}</div>
            </div>
        `;
    }).join('') + `</div>`;
}

window.addEventListener('DOMContentLoaded', () => {
    updateGlobalStoreState();
});

function updateGlobalStoreState() {
    updateGlobalCartCount();
}