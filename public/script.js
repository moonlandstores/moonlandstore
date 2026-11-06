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

window.addEventListener('DOMContentLoaded', () => {
    updateGlobalCartCount();
});