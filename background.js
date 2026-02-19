// background.js - COMPLETE FIXED VERSION WITH CACHE CLEARING

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

// Listen for tab activation (switching tabs)
chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        if (tab.url && settings.autoScan) {
            // Get fresh scan, not cached
            scanUrl(tab.url, activeInfo.tabId);
        }
    });
});

// Main scanning function - WITH CACHE CLEARING
async function scanUrl(url, tabId) {
    try {
        console.log(`🔍 Scanning: ${url}`);
        
        // STEP 1: Clear any old cached data for this tab FIRST
        await clearTabCache(tabId);
        
        // Set scanning icon
        safeSetIcon(tabId, CONFIG.icons.safe);
        
        // Call Flask API with timeout
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

// ===== NEW CODE FOR DEAD SITES =====
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
        
        // Skip the rest of the function
        return;
    } else {
        throw new Error(`API error: ${response.status}`);
    }
}
// ===== END OF NEW CODE =====
        
        // Parse response
        const result = await response.json();
        console.log(`📊 Scan result for ${url}:`, result);
        
        // STEP 2: Store fresh result
        await storeScanResult(tabId, url, result);
        
        // STEP 3: Update icon based on score
        updateIconForScore(result.score, tabId);
        
        // STEP 4: Show warning for high risk
        if (result.score >= 70 && settings.showWarnings) {
            showWarningSafely(tabId, result.score);
        }
        
        // STEP 5: Notify popup that new data is available
        chrome.runtime.sendMessage({
            action: 'scanComplete',
            tabId: tabId,
            result: result
        }).catch(() => {
            // Popup might not be open, ignore
        });
        
    } catch (error) {
        console.error('❌ Scan failed:', error.message);
        safeSetIcon(tabId, CONFIG.icons.safe);
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
            if (chrome.runtime.lastError) {
                // Silently ignore icon errors
            }
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
            if (chrome.runtime.lastError) {
                // Silently ignore scripting errors
            }
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
            
            // Check if we have a fresh scan (less than 30 seconds old)
            chrome.storage.local.get([`scan_${tabId}`, 'lastScan'], (result) => {
                const scan = result[`scan_${tabId}`];
                const lastScan = result.lastScan;
                
                // If scan exists and is from this tab and less than 30 seconds old, return it
                if (scan && lastScan && lastScan.tabId === tabId) {
                    const scanTime = new Date(lastScan.timestamp).getTime();
                    const now = new Date().getTime();
                    
                    if (now - scanTime < 30000) { // 30 seconds
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
                    return true; // Will respond asynchronously
                }
                
                sendResponse(null);
            });
        });
        return true; // Required for async response
    }
    
    if (request.action === 'scanUrl') {
        // Clear cache first, then scan
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

// REPLACE your existing checkSuspiciousDomain with this:

async function checkSuspiciousDomain(url) {
    try {
        // Extract domain WITHOUT protocol
        let domain = url.replace(/^https?:\/\//, '').split('/')[0];
        console.log(`🔍 Checking suspicious domain: ${domain}`);
        
        // ===== CRITICAL: Check domain patterns IGNORING site status =====
        const suspiciousPatterns = [
            // Apple impersonation
            { pattern: 'app1e', score: 90, brand: 'Apple', reason: 'Number 1冒充 letter l' },
            { pattern: 'appple', score: 85, brand: 'Apple', reason: 'Double p冒充' },
            { pattern: 'aple', score: 70, brand: 'Apple', reason: 'Missing p' },
            
            // Google impersonation
            { pattern: 'g00gle', score: 90, brand: 'Google', reason: 'Zeros冒充 letters o' },
            { pattern: 'go0gle', score: 85, brand: 'Google', reason: 'Zero冒充 o' },
            { pattern: 'g0ogle', score: 85, brand: 'Google', reason: 'Zero冒充 o' },
            
            // Microsoft impersonation
            { pattern: 'rnicrosoft', score: 95, brand: 'Microsoft', reason: 'rn冒充 m' },
            { pattern: 'micr0soft', score: 90, brand: 'Microsoft', reason: 'Zero冒充 o' },
            { pattern: 'micros0ft', score: 90, brand: 'Microsoft', reason: 'Zero冒充 o' },
            
            // PayPal impersonation
            { pattern: 'paypa1', score: 90, brand: 'PayPal', reason: 'Number 1冒充 l' },
            { pattern: 'paypai', score: 85, brand: 'PayPal', reason: 'i冒充 l' },
            
            // Facebook impersonation
            { pattern: 'faceb00k', score: 95, brand: 'Facebook', reason: 'Zeros冒充 oo' },
            { pattern: 'faceb0ok', score: 90, brand: 'Facebook', reason: 'Zero冒充 o' },
            
            // Amazon impersonation
            { pattern: 'amaz0n', score: 90, brand: 'Amazon', reason: 'Zero冒充 o' },
            { pattern: 'amazn', score: 80, brand: 'Amazon', reason: 'Missing o' }
        ];
        
        // Check domain against patterns (IGNORE site status)
        for (const item of suspiciousPatterns) {
            if (domain.includes(item.pattern)) {
                console.log(`🚨 DETECTED: ${domain} matches ${item.pattern} (${item.brand})`);
                
                // Return HIGH RISK even if site is down!
                return {
                    suspicious: true,
                    score: item.score,
                    risk_level: '🔴 HIGH RISK',
                    findings: [
                        `⚠️ Domain '${domain}' impersonates ${item.brand}`,
                        `⚠️ ${item.reason}`,
                        `⚠️ Site appears down (502 error) but domain is suspicious`
                    ]
                };
            }
        }
        
        // Check for number substitutions
        if (/\d/.test(domain)) {
            // Convert numbers to letters and check again
            let normalized = domain
                .replace(/0/g, 'o')
                .replace(/1/g, 'l')
                .replace(/3/g, 'e')
                .replace(/4/g, 'a')
                .replace(/5/g, 's')
                .replace(/7/g, 't');
            
            // Check normalized version against brand names
            const brands = ['apple', 'google', 'microsoft', 'paypal', 'facebook', 'amazon'];
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
console.log('🚀 AI Scam Detector extension loaded with cache clearing');