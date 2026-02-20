// content.js - Injected into web pages

// Listen for messages from background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageInfo') {
        sendResponse({
            title: document.title,
            url: window.location.href,
            forms: document.forms.length,
            links: document.links.length
        });
    }
});

// Highlight suspicious elements
function highlightSuspiciousElements(findings) {
    // Highlight links that might be dangerous
    const links = document.getElementsByTagName('a');
    for (let link of links) {
        const href = link.href;
        if (href && findings.some(f => f.includes('shortener') || f.includes('suspicious'))) {
            link.style.border = '2px solid #ef4444';
            link.style.borderRadius = '4px';
            link.style.position = 'relative';
            
            // Add tooltip
            const tooltip = document.createElement('span');
            tooltip.textContent = '⚠️ Suspicious Link';
            tooltip.style.cssText = `
                position: absolute;
                background: #ef4444;
                color: white;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 10px;
                top: -20px;
                left: 0;
                display: none;
            `;
            link.appendChild(tooltip);
            
            link.addEventListener('mouseenter', () => {
                tooltip.style.display = 'block';
            });
            
            link.addEventListener('mouseleave', () => {
                tooltip.style.display = 'none';
            });
        }
    }
}