// background.js - COMPLETE FIXED VERSION WITH DEAD SITE DETECTION

// Configuration - USING YOUR ACTUAL ICON NAMES
const CONFIG = {
    apiUrl: "http://localhost:5000/check-url",
    healthUrl: "http://localhost:5000/health",
    icons: {
        safe: "icons/safe-one.png",
        warning: "icons/yellow-alert.png",
        danger: "icons/alertt.png"
    }
};

// Default settings
let settings = {
    autoScan: true,
    showWarnings: true,
    scanHistory: []
};

// Load settings on startup
chrome.storage.local.get(['settings'], function(result) {
    if (result.settings) {
        settings = {...settings, ...result.settings};
    }
    console.log('✅ Extension loaded with settings:', settings);
    checkApiHealth();
});

// Check if Flask API is running
function checkApiHealth() {
    fetch(CONFIG.healthUrl)
        .then(response => response.json())
        .then(data => console.log('✅ API is healthy:', data))
        .catch(error => console.error('❌ API not reachable - make sure Flask is running on port 5000'));
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && settings.autoScan) {
        if (!tab.url.startsWith('chrome://') && 
            !tab.url.startsWith('brave://') &&
            !tab.url.startsWith('about:')) {
            
            console.log(`📍 Navigating to: ${tab.url}`);
            scanUrl(tab.url, tabId);
        }
    }
});

// Listen for tab activation
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url && settings.autoScan) {
            scanUrl(tab.url, activeInfo.tabId);
        }
    });
});

// Main scanning function
async function scanUrl(url, tabId) {
    try {
        console.log(`🔍 Scanning: ${url}`);
        
        // Clear old cache
        await clearTabCache(tabId);
        
        // Set scanning icon
        safeSetIcon(tabId, CONFIG.icons.safe);
        
        // Try to fetch from API with timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);
        
        const response = await fetch(CONFIG.apiUrl, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ url: url }),
            signal: controller.signal
        }).catch(err => {
            clearTimeout(timeoutId);
            throw new Error('API not reachable - Is Flask running?');
        });
        
        clearTimeout(timeoutId);

        // ===== HANDLE DEAD SITES (NON-200 RESPONSES) =====
        if (!response.ok) {
            console.log(`⚠️ Site returned error ${response.status} - checking domain suspicion`);
            
            // Even if site is down, check if domain looks suspicious
            const domainCheck = await checkSuspiciousDomain(url);
            
            if (domainCheck.suspicious) {
                // Create a result for suspicious dead domain
                const result = {
                    score: domainCheck.score,
                    risk_level: domainCheck.risk_level,
                    findings: domainCheck.findings || [`⚠️ Domain ${url} appears suspicious but site is down (${response.status} error)`]
                };
                
                console.log(`📊 Domain analysis for dead site: ${result.score}%`);
                
                // Store result
                await storeScanResult(tabId, url, result);
                
                // Update icon based on score
                updateIconForScore(result.score, tabId);
                
                // Show warning for high risk
                if (result.score >= 70 && settings.showWarnings) {
                    showWarningSafely(tabId, result.score);
                }
                
                // Notify popup
                chrome.runtime.sendMessage({
                    action: 'scanComplete',
                    tabId: tabId,
                    result: result
                }).catch(() => {});
                
                return;
            } else {
                throw new Error(`API error: ${response.status}`);
            }
        }
        
        // If response is OK, parse JSON
        const result = await response.json();
        console.log(`📊 Scan result for ${url}:`, result);
        
        // Store result
        await storeScanResult(tabId, url, result);
        
        // Update icon based on score
        updateIconForScore(result.score, tabId);
        
        // Show warning for high risk
        if (result.score >= 70 && settings.showWarnings) {
            showWarningSafely(tabId, result.score);
        }
        
        // Notify popup
        chrome.runtime.sendMessage({
            action: 'scanComplete',
            tabId: tabId,
            result: result
        }).catch(() => {});
        
    } catch (error) {
        console.error('❌ Scan failed:', error.message);
        safeSetIcon(tabId, CONFIG.icons.safe);
    }
}

// ===== FUNCTION TO CHECK SUSPICIOUS DOMAINS (EVEN WHEN SITE IS DOWN) =====
async function checkSuspiciousDomain(url) {
    try {
        // Extract domain WITHOUT protocol
        let domain = url.replace(/^https?:\/\//, '').split('/')[0];
        // Remove www if present
        domain = domain.replace(/^www\./, '');
        
        console.log(`🔍 Checking suspicious domain: ${domain}`);
        
        // Comprehensive suspicious patterns
        const suspiciousPatterns = [
            // Microsoft impersonation
            { pattern: 'rnicrosoft', score: 95, brand: 'Microsoft', reason: 'rn冒充 m (rn looks like m)' },
            { pattern: 'micr0soft', score: 90, brand: 'Microsoft', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'micros0ft', score: 90, brand: 'Microsoft', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'mlcrosoft', score: 85, brand: 'Microsoft', reason: 'l冒充 i (l looks like i)' },
            { pattern: 'rnicro', score: 85, brand: 'Microsoft', reason: 'rn冒充 m' },
            
            // Google impersonation
            { pattern: 'g00gle', score: 95, brand: 'Google', reason: 'Zeros冒充 oo (00 looks like oo)' },
            { pattern: 'go0gle', score: 90, brand: 'Google', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'g0ogle', score: 90, brand: 'Google', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'googl', score: 70, brand: 'Google', reason: 'Missing letter' },
            
            // PayPal impersonation
            { pattern: 'paypa1', score: 95, brand: 'PayPal', reason: 'Number 1冒充 l (1 looks like l)' },
            { pattern: 'paypai', score: 90, brand: 'PayPal', reason: 'i冒充 l (i looks like l)' },
            { pattern: 'paypal', score: 0, brand: 'PayPal', reason: 'Legitimate' },
            
            // Facebook impersonation
            { pattern: 'faceb00k', score: 95, brand: 'Facebook', reason: 'Zeros冒充 oo (00 looks like oo)' },
            { pattern: 'faceb0ok', score: 90, brand: 'Facebook', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'face-book', score: 85, brand: 'Facebook', reason: 'Hyphenated' },
            
            // Amazon impersonation
            { pattern: 'amaz0n', score: 95, brand: 'Amazon', reason: 'Zero冒充 o (0 looks like o)' },
            { pattern: 'amazn', score: 80, brand: 'Amazon', reason: 'Missing o' },
            { pattern: 'arnazon', score: 90, brand: 'Amazon', reason: 'rn冒充 m' },
            
            // Apple impersonation
            { pattern: 'app1e', score: 95, brand: 'Apple', reason: 'Number 1冒充 l (1 looks like l)' },
            { pattern: 'appple', score: 85, brand: 'Apple', reason: 'Double p冒充' },
            { pattern: 'aple', score: 70, brand: 'Apple', reason: 'Missing p' },
            
            // Netflix impersonation
            { pattern: 'netfl1x', score: 95, brand: 'Netflix', reason: 'Number 1冒充 i (1 looks like i)' },
            { pattern: 'netfllx', score: 85, brand: 'Netflix', reason: 'Double l冒充' },
            
            // Chase impersonation
            { pattern: 'chase', score: 0, brand: 'Chase', reason: 'Legitimate' },
            { pattern: 'chase-bank', score: 75, brand: 'Chase', reason: 'Hyphenated' },
            
            // Instagram impersonation
            { pattern: 'instagrarn', score: 90, brand: 'Instagram', reason: 'rn冒充 m' },
            
            // LinkedIn impersonation
            { pattern: 'linkedln', score: 90, brand: 'LinkedIn', reason: 'ln冒充 in' },
            
            // Twitter impersonation
            { pattern: 'tw1tter', score: 90, brand: 'Twitter', reason: 'Number 1冒充 i' },
            { pattern: 'twltter', score: 85, brand: 'Twitter', reason: 'l冒充 i' }
        ];
        
        // Check domain against patterns
        for (const item of suspiciousPatterns) {
            if (domain.includes(item.pattern)) {
                console.log(`🚨 DETECTED: ${domain} matches ${item.pattern} (${item.brand})`);
                
                // Special case: if it's exactly the legitimate domain, return safe
                if (item.score === 0) {
                    return { suspicious: false };
                }
                
                return {
                    suspicious: true,
                    score: item.score,
                    risk_level: item.score >= 70 ? '🔴 HIGH RISK' : '🟡 MEDIUM RISK',
                    findings: [
                        `⚠️ Domain '${domain}' impersonates ${item.brand}`,
                        `⚠️ ${item.reason}`,
                        `⚠️ Site appears down but domain is suspicious`
                    ]
                };
            }
        }
        
        // Check for number substitution patterns
        if (/\d/.test(domain)) {
            // Convert numbers to letters and check against common brands
            let normalized = domain
                .replace(/0/g, 'o')
                .replace(/1/g, 'l')
                .replace(/3/g, 'e')
                .replace(/4/g, 'a')
                .replace(/5/g, 's')
                .replace(/7/g, 't');
            
            const brands = ['microsoft', 'google', 'paypal', 'facebook', 'amazon', 'apple', 'netflix'];
            for (const brand of brands) {
                if (normalized.includes(brand) && !domain.includes(brand)) {
                    return {
                        suspicious: true,
                        score: 85,
                        risk_level: '🔴 HIGH RISK',
                        findings: [
                            `⚠️ Domain '${domain}' uses number substitution to mimic '${brand}'`,
                            `⚠️ Site appears down but domain is clearly suspicious`
                        ]
                    };
                }
            }
        }
        
        return { suspicious: false };
        
    } catch (error) {
        console.log('Error checking suspicious domain:', error);
        return { suspicious: false };
    }
}

// Clear cache for a specific tab
function clearTabCache(tabId) {
    return new Promise((resolve) => {
        chrome.storage.local.remove([`scan_${tabId}`], () => {
            console.log(`🧹 Cleared cache for tab ${tabId}`);
            resolve();
        });
    });
}

// Store scan result
function storeScanResult(tabId, url, result) {
    return new Promise((resolve) => {
        chrome.storage.local.set({ 
            [`scan_${tabId}`]: result,
            [`scan_${url}`]: result,
            'lastScan': {
                tabId: tabId,
                url: url,
                result: result,
                timestamp: new Date().toISOString()
            }
        }, () => {
            console.log(`✅ Stored fresh scan data for tab ${tabId}`);
            
            // Add to history
            if (result.score !== undefined) {
                settings.scanHistory.unshift({
                    url: url,
                    score: result.score,
                    risk_level: result.risk_level,
                    timestamp: new Date().toISOString()
                });
                
                // Keep only last 20 scans
                if (settings.scanHistory.length > 20) {
                    settings.scanHistory.pop();
                }
                chrome.storage.local.set({ settings: settings });
            }
            resolve();
        });
    });
}

// Safely set icon with error handling
function safeSetIcon(tabId, iconPath) {
    try {
        chrome.action.setIcon({
            path: iconPath,
            tabId: tabId
        }, () => {
            // Silently ignore errors
            const lastError = chrome.runtime.lastError;
        });
    } catch (e) {
        // Silently ignore
    }
}

// Update icon based on score
function updateIconForScore(score, tabId) {
    let iconPath = CONFIG.icons.safe;
    
    if (score >= 70) {
        iconPath = CONFIG.icons.danger;
        console.log(`🔴 High risk (${score}%) - Setting red icon`);
    } else if (score >= 40) {
        iconPath = CONFIG.icons.warning;
        console.log(`🟡 Medium risk (${score}%) - Setting yellow icon`);
    } else {
        console.log(`🟢 Safe (${score}%) - Setting green icon`);
    }
    
    safeSetIcon(tabId, iconPath);
}

// Safely show warning banner
function showWarningSafely(tabId, score) {
    try {
        chrome.scripting.executeScript({
            target: { tabId: tabId },
            func: (score) => {
                // Remove existing banner
                const existing = document.getElementById('ai-scam-warning');
                if (existing) existing.remove();
                
                // Create banner
                const banner = document.createElement('div');
                banner.id = 'ai-scam-warning';
                banner.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    background: #dc2626;
                    color: white;
                    padding: 12px;
                    text-align: center;
                    z-index: 999999;
                    font-family: Arial, sans-serif;
                    font-size: 14px;
                    font-weight: bold;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
                `;
                banner.innerHTML = `
                    🚨 DANGEROUS SITE DETECTED! Risk: ${score}% 
                    <button style="margin-left: 10px; padding: 4px 12px; background: white; color: #dc2626; border: none; border-radius: 4px; cursor: pointer;" 
                            onclick="this.parentElement.remove()">
                        Dismiss
                    </button>
                `;
                document.body.prepend(banner);
                
                // Auto-remove after 8 seconds
                setTimeout(() => {
                    const el = document.getElementById('ai-scam-warning');
                    if (el) el.remove();
                }, 8000);
            },
            args: [score]
        }, () => {
            // Silently ignore scripting errors
            const lastError = chrome.runtime.lastError;
        });
    } catch (e) {
        // Silently ignore
    }
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getCurrentScan') {
        chrome.tabs.query({active: true, currentWindow: true}, async (tabs) => {
            if (!tabs || !tabs[0]) {
                sendResponse(null);
                return;
            }
            
            const tabId = tabs[0].id;
            
            chrome.storage.local.get([`scan_${tabId}`, 'lastScan'], (result) => {
                const scan = result[`scan_${tabId}`];
                const lastScan = result.lastScan;
                
                // If scan exists and is from this tab and less than 30 seconds old, return it
                if (scan && lastScan && lastScan.tabId === tabId) {
                    const scanTime = new Date(lastScan.timestamp).getTime();
                    const now = new Date().getTime();
                    
                    if (now - scanTime < 30000) {
                        sendResponse(scan);
                        return;
                    }
                }
                
                // Otherwise, trigger a new scan
                if (tabs[0].url) {
                    scanUrl(tabs[0].url, tabId);
                    setTimeout(() => {
                        chrome.storage.local.get([`scan_${tabId}`], (newResult) => {
                            sendResponse(newResult[`scan_${tabId}`] || null);
                        });
                    }, 1500);
                    return true;
                }
                
                sendResponse(null);
            });
        });
        return true;
    }
    
    if (request.action === 'scanUrl') {
        clearTabCache(request.tabId).then(() => {
            scanUrl(request.url, request.tabId);
        });
        sendResponse({success: true});
    }
    
    if (request.action === 'clearCache') {
        chrome.storage.local.clear(() => {
            console.log('✅ All cache cleared');
            sendResponse({success: true});
        });
        return true;
    }
    
    if (request.action === 'getHistory') {
        sendResponse(settings.scanHistory || []);
    }
});

console.log('🚀 AI Scam Detector extension loaded with dead site detection');