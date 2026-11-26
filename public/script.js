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

function addToCart(productOrTitle, price, quantity = 1) {
    let cart = getCart();

    let newItem;
    if (typeof productOrTitle === 'object' && productOrTitle !== null) {
        newItem = {
            id: productOrTitle.id || '',
            title: productOrTitle.title || productOrTitle.name || 'Product',
            name: productOrTitle.name || productOrTitle.title || 'Product',
            price: Number(productOrTitle.price) || 0,
            quantity: Number(productOrTitle.quantity || productOrTitle.qty || quantity)
        };
    } else {
        newItem = {
            title: productOrTitle,
            name: productOrTitle,
            price: Number(price) || 0,
            quantity: Number(quantity) || 1
        };
    }

    let existing = cart.find(i => (i.id && newItem.id && i.id === newItem.id) || (i.title === newItem.title || i.name === newItem.name));

    if (existing) {
        existing.quantity = Number(existing.quantity || existing.qty || 1) + Number(newItem.quantity);
    } else {
        cart.push(newItem);
    }

    saveCart(cart);
}

const MoonlandReferral = (function() {
    const STORAGE_KEY = 'moonland_active_ref';
    const LEGACY_KEY = 'moonland_ref_code';

    function cleanCode(val) {
        const str = String(val || '').trim();
        if (!str || str.toLowerCase() === 'none' || str.toLowerCase() === 'null' || str.toLowerCase() === 'undefined') {
            return '';
        }
        return str;
    }

    function set(code) {
        const cleaned = cleanCode(code);
        if (!cleaned) return '';
        try {
            localStorage.setItem(STORAGE_KEY, cleaned);
            localStorage.setItem(LEGACY_KEY, cleaned);
            localStorage.setItem('referralCode', cleaned);
        } catch (e) {}
        return cleaned;
    }

    function get() {
        try {
            const primary = cleanCode(localStorage.getItem(STORAGE_KEY));
            if (primary) return primary;

            const secondary = cleanCode(localStorage.getItem('referralCode'));
            if (secondary) {
                set(secondary);
                return secondary;
            }

            const legacy = cleanCode(localStorage.getItem(LEGACY_KEY));
            if (legacy) {
                set(legacy);
                return legacy;
            }
        } catch (e) {}
        return '';
    }

    function capture() {
        try {
            const params = new URLSearchParams(window.location.search);
            const rawRef = params.get('ref') || params.get('code') || params.get('referral') || '';
            const cleaned = cleanCode(rawRef);
            if (cleaned) {
                return set(cleaned);
            }
        } catch (e) {}
        return get();
    }

    function buildStoreUrl(code) {
        const refCode = cleanCode(code) || get();
        const url = new URL('store.html', window.location.origin);
        if (refCode) {
            url.searchParams.set('ref', refCode);
        }
        return url.toString();
    }

    function attachToOrder(payload) {
        const refCode = cleanCode(payload?.referralCode) || get();
        return {
            ...payload,
            referralCode: refCode,
            enteredRefCode: refCode || 'None',
            referredByCode: refCode || null
        };
    }

    return {
        set,
        get,
        capture,
        buildStoreUrl,
        attachToOrder
    };
})();

window.MoonlandReferral = MoonlandReferral;

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

MoonlandReferral.capture();

window.addEventListener('DOMContentLoaded', () => {
    MoonlandReferral.capture();
    updateGlobalStoreState();
});

function updateGlobalStoreState() {
    updateGlobalCartCount();
}
