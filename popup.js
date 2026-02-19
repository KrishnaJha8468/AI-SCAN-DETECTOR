// popup.js - FIXED VERSION

document.addEventListener('DOMContentLoaded', function() {
    loadCurrentSite();
    setupButtons();
});

function loadCurrentSite() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (!tabs || !tabs[0]) {
            showError('No active tab');
            return;
        }
        
        document.getElementById('siteUrl').textContent = tabs[0].url || 'Unknown';
        
        chrome.storage.local.get([`scan_${tabs[0].id}`], function(result) {
            const scan = result[`scan_${tabs[0].id}`] || { score: 0, findings: ['No data yet'] };
            updateDisplay(scan.score, scan.findings || []);
        });
    });
}

function updateDisplay(score, findings) {
    document.getElementById('riskScore').textContent = `${score}%`;
    document.getElementById('riskFill').style.width = `${score}%`;
    
    const levelEl = document.getElementById('riskLevel');
    if (score >= 70) {
        levelEl.textContent = '🔴 CRITICAL';
        levelEl.style.color = '#ef4444';
    } else if (score >= 40) {
        levelEl.textContent = '🟡 MEDIUM';
        levelEl.style.color = '#eab308';
    } else {
        levelEl.textContent = '✅ SAFE';
        levelEl.style.color = '#22c55e';
    }
    
    const listEl = document.getElementById('findingsList');
    listEl.innerHTML = '';
    if (findings.length > 0) {
        findings.slice(0, 3).forEach(f => {
            const div = document.createElement('div');
            div.className = 'finding-item';
            div.textContent = f.length > 50 ? f.substring(0, 50) + '...' : f;
            listEl.appendChild(div);
        });
    } else {
        listEl.innerHTML = '<div class="loading">No issues found</div>';
    }
}

function setupButtons() {
    document.getElementById('scanNowBtn').addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (!tabs || !tabs[0]) return;
            
            document.getElementById('findingsList').innerHTML = 
                '<div class="loading">Scanning...</div>';
            
            chrome.runtime.sendMessage({
                action: 'scanUrl',
                url: tabs[0].url,
                tabId: tabs[0].id
            });
            
            setTimeout(loadCurrentSite, 1000);
        });
    });
    
    document.getElementById('reportBtn').addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (!tabs || !tabs[0]) return;
            chrome.tabs.create({ 
                url: `http://localhost:8501/?url=${encodeURIComponent(tabs[0].url)}` 
            });
        });
    });
    
    document.getElementById('trustBtn').addEventListener('click', function() {
        alert('✅ Added to trusted sites (coming soon)');
    });
    
    document.getElementById('toggleFindings').addEventListener('click', function() {
        const list = document.getElementById('findingsList');
        list.style.display = list.style.display === 'none' ? 'block' : 'none';
    });
    
    document.getElementById('openDashboard').addEventListener('click', function(e) {
        e.preventDefault();
        chrome.tabs.create({ url: 'http://localhost:8501' });
    });
}

function showError(msg) {
    document.getElementById('siteUrl').textContent = 'Error';
    document.getElementById('findingsList').innerHTML = `<div class="loading">${msg}</div>`;
}