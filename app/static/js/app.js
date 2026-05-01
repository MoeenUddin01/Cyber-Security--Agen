// CyberShield AI - Frontend JavaScript

let analysisHistory = [];
let threatChart = null;
let timelineChart = null;

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    updateSystemStatus();
    showSection('dashboard');
});

// Navigation
function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.section').forEach(section => {
        section.classList.add('hidden');
    });
    
    // Show selected section
    document.getElementById(sectionName).classList.remove('hidden');
    
    // Update navigation buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.closest('.nav-btn').classList.add('active');
    
    // Update history if showing history section
    if (sectionName === 'history') {
        updateHistoryDisplay();
    }
}

// Initialize Charts
function initializeCharts() {
    // Threat Distribution Chart
    const threatCtx = document.getElementById('threatChart').getContext('2d');
    threatChart = new Chart(threatCtx, {
        type: 'doughnut',
        data: {
            labels: ['Benign', 'DOS Attack', 'Web Attack', 'Brute Force', 'Infiltration', 'Port Scan'],
            datasets: [{
                data: [65, 15, 8, 5, 4, 3],
                backgroundColor: [
                    '#10b981',
                    '#ef4444',
                    '#f59e0b',
                    '#8b5cf6',
                    '#3b82f6',
                    '#ec4899'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#9ca3af' }
                }
            }
        }
    });

    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
            datasets: [{
                label: 'Threats Detected',
                data: [2, 5, 3, 8, 12, 6],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                tension: 0.4
            }, {
                label: 'IPs Blocked',
                data: [1, 3, 2, 6, 9, 4],
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#9ca3af' }
                }
            },
            scales: {
                x: {
                    grid: { color: '#374151' },
                    ticks: { color: '#9ca3af' }
                },
                y: {
                    grid: { color: '#374151' },
                    ticks: { color: '#9ca3af' }
                }
            }
        }
    });
}

// Update System Status
async function updateSystemStatus() {
    try {
        const response = await fetch('/health');
        const data = await response.json();
        
        // Update status indicators
        if (data.predictor_available && data.advisor_available) {
            console.log('All systems operational');
        }
    } catch (error) {
        console.error('Failed to update system status:', error);
    }
}

// Load Sample Data
function loadSampleData() {
    const sampleData = [
        443, 1000000, 50, 50, 5000, 3000, 200, 50, 100, 150, 30, 60, 10, 0.1, 50000, 10000, 100000
    ];
    
    const inputs = document.querySelectorAll('.feature-input');
    inputs.forEach((input, index) => {
        if (sampleData[index] !== undefined) {
            input.value = sampleData[index];
        }
    });
    
    document.getElementById('sourceIp').value = '192.168.1.100';
}

// Handle Analysis Form Submission
document.getElementById('analysisForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    // Show loading overlay
    document.getElementById('loadingOverlay').classList.remove('hidden');
    
    try {
        // Collect form data
        const features = [];
        document.querySelectorAll('.feature-input').forEach(input => {
            features.push(parseFloat(input.value) || 0);
        });
        
        const sourceIp = document.getElementById('sourceIp').value;
        
        // Send to API
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                features: features,
                source_ip: sourceIp || null
            })
        });
        
        const result = await response.json();
        
        // Display results
        displayResults(result);
        
        // Add to history
        addToHistory({
            timestamp: new Date().toISOString(),
            features: features,
            source_ip: sourceIp,
            result: result
        });
        
        // Update counters
        updateCounters(result);
        
    } catch (error) {
        console.error('Analysis failed:', error);
        displayError('Analysis failed. Please check your input and try again.');
    } finally {
        // Hide loading overlay
        document.getElementById('loadingOverlay').classList.add('hidden');
    }
});

// Display Analysis Results
function displayResults(result) {
    const resultsSection = document.getElementById('results');
    const resultContent = document.getElementById('resultContent');
    
    const threatLevel = result.prediction.is_threat ? 
        (result.prediction.threat_level === 'HIGH' ? 'threat-high' : 'threat-medium') : 
        'threat-low';
    
    const threatIcon = result.prediction.is_threat ? 
        '<i class="fas fa-exclamation-triangle text-red-400"></i>' : 
        '<i class="fas fa-check-circle text-green-400"></i>';
    
    resultContent.innerHTML = `
        <div class="result-card ${threatLevel} rounded-lg p-6 mb-4">
            <div class="flex items-center justify-between mb-4">
                <h4 class="text-xl font-semibold flex items-center">
                    ${threatIcon}
                    <span class="ml-2">Threat Analysis Result</span>
                </h4>
                <span class="px-3 py-1 rounded-full text-sm font-medium ${
                    result.prediction.is_threat ? 'bg-red-900 text-red-200' : 'bg-green-900 text-green-200'
                }">
                    ${result.prediction.label}
                </span>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div>
                    <p class="text-gray-400 text-sm">Confidence</p>
                    <p class="text-lg font-semibold">${result.prediction.confidence}</p>
                </div>
                <div>
                    <p class="text-gray-400 text-sm">Threat Level</p>
                    <p class="text-lg font-semibold">${result.prediction.threat_level}</p>
                </div>
            </div>
            
            ${result.ai_advice ? `
            <div class="mb-4 p-4 bg-blue-900 bg-opacity-30 rounded-lg border border-blue-700">
                <h5 class="font-semibold mb-2 flex items-center">
                    <i class="fas fa-robot text-blue-400 mr-2"></i>
                    AI Security Advisor
                </h5>
                <p class="text-gray-300">${result.ai_advice}</p>
            </div>
            ` : ''}
            
            ${result.mitigation_status ? `
            <div class="p-4 ${result.mitigation_status.blocked ? 'bg-yellow-900 bg-opacity-30 border-yellow-700' : 'bg-gray-700 bg-opacity-30 border-gray-600'} rounded-lg border">
                <h5 class="font-semibold mb-2 flex items-center">
                    <i class="fas ${result.mitigation_status.blocked ? 'fa-ban text-yellow-400' : 'fa-shield-alt text-gray-400'} mr-2"></i>
                    Mitigation Status
                </h5>
                <p class="text-gray-300">
                    ${result.mitigation_status.blocked ? 
                        `IP ${result.mitigation_status.ip} has been blocked. ${result.mitigation_status.action}` : 
                        result.mitigation_status.reason || result.mitigation_status.error
                    }
                </p>
            </div>
            ` : ''}
        </div>
    `;
    
    resultsSection.classList.remove('hidden');
}

// Display Error
function displayError(message) {
    const resultsSection = document.getElementById('results');
    const resultContent = document.getElementById('resultContent');
    
    resultContent.innerHTML = `
        <div class="alert-danger rounded-lg p-6">
            <h4 class="text-xl font-semibold mb-2 flex items-center">
                <i class="fas fa-exclamation-circle text-red-400 mr-2"></i>
                Analysis Error
            </h4>
            <p class="text-gray-300">${message}</p>
        </div>
    `;
    
    resultsSection.classList.remove('hidden');
}

// Add to History
function addToHistory(entry) {
    analysisHistory.unshift(entry);
    if (analysisHistory.length > 50) {
        analysisHistory.pop();
    }
}

// Update History Display
function updateHistoryDisplay() {
    const historyContent = document.getElementById('historyContent');
    
    if (analysisHistory.length === 0) {
        historyContent.innerHTML = '<p class="text-gray-400">No analysis history available</p>';
        return;
    }
    
    historyContent.innerHTML = analysisHistory.map((entry, index) => {
        const date = new Date(entry.timestamp);
        const threatClass = entry.result.prediction.is_threat ? 'border-red-700' : 'border-green-700';
        const threatIcon = entry.result.prediction.is_threat ? 
            '<i class="fas fa-exclamation-triangle text-red-400"></i>' : 
            '<i class="fas fa-check-circle text-green-400"></i>';
        
        return `
            <div class="history-item bg-gray-800 rounded-lg p-4 border ${threatClass} cursor-pointer" 
                 onclick="showHistoryDetails(${index})">
                <div class="flex items-center justify-between">
                    <div class="flex items-center">
                        ${threatIcon}
                        <div class="ml-3">
                            <p class="font-semibold">${entry.result.prediction.label}</p>
                            <p class="text-sm text-gray-400">
                                ${date.toLocaleString()} ${entry.source_ip ? `• ${entry.source_ip}` : ''}
                            </p>
                        </div>
                    </div>
                    <div class="text-right">
                        <p class="text-sm font-medium">${entry.result.prediction.confidence}</p>
                        <p class="text-xs text-gray-400">${entry.result.prediction.threat_level}</p>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Show History Details
function showHistoryDetails(index) {
    const entry = analysisHistory[index];
    displayResults(entry.result);
    showSection('analyze');
}

// Update Counters
function updateCounters(result) {
    if (result.prediction.is_threat) {
        const threatCount = document.getElementById('threatCount');
        threatCount.textContent = parseInt(threatCount.textContent) + 1;
        
        if (result.mitigation_status && result.mitigation_status.blocked) {
            const blockedCount = document.getElementById('blockedCount');
            blockedCount.textContent = parseInt(blockedCount.textContent) + 1;
        }
    }
}
