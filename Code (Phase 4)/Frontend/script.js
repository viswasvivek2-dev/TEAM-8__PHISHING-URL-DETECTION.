/* ==========================================
   CONFIG & VARIABLES
========================================== */

const API_BASE = (window.location.protocol.startsWith("http")) 
    ? window.location.origin 
    : "http://127.0.0.1:5000";

let totalInputs = 0;
let history = [];


/* ==========================================
   ELEMENTS
========================================== */

const urlInput = document.getElementById("urlInput");
const receiveButton = document.getElementById("receiveButton");
const totalInputsElement = document.getElementById("totalInputs");
const lastInputElement = document.getElementById("lastInput");
const backendStatus = document.getElementById("backendStatus");

const historyTable = document.getElementById("historyTable");
const clearHistory = document.getElementById("clearHistory");
const breadcrumbPage = document.getElementById("breadcrumbPage");
const menuItems = document.querySelectorAll(".menu-item");

const scannerPage = document.getElementById("scannerPage");
const historyPage = document.getElementById("historyPage");
const howPage = document.getElementById("howPage");

// Dynamic Result Elements
const resultCard = document.getElementById("resultCard");
const verdictBadge = document.getElementById("verdictBadge");
const verdictIcon = document.getElementById("verdictIcon");
const verdictUrl = document.getElementById("verdictUrl");
const confidenceValue = document.getElementById("confidenceValue");
const riskScoreLabel = document.getElementById("riskScoreLabel");
const meterFill = document.getElementById("meterFill");
const indicatorsSection = document.getElementById("indicatorsSection");
const indicatorsList = document.getElementById("indicatorsList");


/* ==========================================
   BACKEND HEALTH CHECK
========================================== */

async function checkBackendHealth() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        if (response.ok) {
            const data = await response.json();
            if (backendStatus) {
                backendStatus.textContent = "Online ✓";
                backendStatus.style.color = "#10b981";
            }
        } else {
            throw new Error("Server status error");
        }
    } catch (e) {
        if (backendStatus) {
            backendStatus.textContent = "Offline";
            backendStatus.style.color = "#ef4444";
        }
    }
}


/* ==========================================
   PAGE SWITCHING
========================================== */

menuItems.forEach(function(item) {
    item.addEventListener("click", function(event) {
        event.preventDefault();

        // Remove active from all
        menuItems.forEach(function(menu) {
            menu.classList.remove("active");
        });

        // Add active to clicked item
        item.classList.add("active");

        // Get requested page
        const page = item.getAttribute("data-page");

        // Hide all pages
        scannerPage.classList.remove("active-page");
        historyPage.classList.remove("active-page");
        howPage.classList.remove("active-page");

        // Show selected page
        if (page === "scanner") {
            scannerPage.classList.add("active-page");
            breadcrumbPage.textContent = "Scanner";
        } else if (page === "history") {
            historyPage.classList.add("active-page");
            breadcrumbPage.textContent = "History";
            displayHistory();
        } else if (page === "how") {
            howPage.classList.add("active-page");
            breadcrumbPage.textContent = "How it works";
        }
    });
});


/* ==========================================
   URL SCANNING & PREDICTION
========================================== */

async function scanUrl() {
    const url = urlInput.value.trim();

    if (url === "") {
        alert("Please enter a website URL.");
        urlInput.focus();
        return;
    }

    receiveButton.disabled = true;
    receiveButton.textContent = "Analyzing... ⏳";

    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        // Update Scan Result Card
        if (resultCard) {
            resultCard.classList.remove("hidden");
            verdictUrl.textContent = result.url;
            confidenceValue.textContent = `${result.confidence}%`;
            riskScoreLabel.textContent = `Phishing Probability: ${(result.risk_score * 100).toFixed(1)}%`;
            meterFill.style.width = `${Math.min(100, Math.max(3, result.risk_score * 100))}%`;

            if (result.is_phishing) {
                verdictIcon.textContent = "⚠️";
                verdictBadge.textContent = "Phishing Threat Detected!";
                verdictBadge.className = "verdict-badge danger";
                meterFill.className = "meter-fill danger";
            } else {
                verdictIcon.textContent = "🛡️";
                verdictBadge.textContent = "Verified Legitimate Website";
                verdictBadge.className = "verdict-badge safe";
                meterFill.className = "meter-fill safe";
            }

            // Populate suspicious indicators if found
            if (result.indicators && result.indicators.length > 0) {
                indicatorsList.innerHTML = "";
                result.indicators.forEach(function(ind) {
                    const li = document.createElement("li");
                    li.textContent = ind;
                    indicatorsList.appendChild(li);
                });
                indicatorsSection.classList.remove("hidden");
            } else {
                indicatorsSection.classList.add("hidden");
            }
        }

        // Update Status Stats
        totalInputs++;
        if (totalInputsElement) totalInputsElement.textContent = totalInputs;
        if (lastInputElement) {
            lastInputElement.textContent = `${result.label} (${result.confidence}%)`;
            lastInputElement.style.color = result.is_phishing ? "#dc2626" : "#0d8a50";
        }

        // Save to History
        const historyItem = {
            url: url,
            label: result.label,
            is_phishing: result.is_phishing,
            confidence: `${result.confidence}%`,
            time: getCurrentTime()
        };

        history.unshift(historyItem);
        saveHistory();

        // Button feedback
        receiveButton.textContent = "Scan Complete ✓";
        setTimeout(function() {
            receiveButton.textContent = "Scan URL →";
            receiveButton.disabled = false;
        }, 1200);

    } catch (error) {
        console.error("Scan API Error:", error);
        alert(`Could not connect to the Backend API at ${API_BASE}.\n\nPlease ensure the server is running by executing:\npython "Code (Phase 4)/app.py"`);
        receiveButton.textContent = "Scan URL →";
        receiveButton.disabled = false;
    }
}

receiveButton.addEventListener("click", scanUrl);

urlInput.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        scanUrl();
    }
});


/* ==========================================
   DISPLAY HISTORY
========================================== */

function displayHistory() {
    historyTable.innerHTML = "";

    if (history.length === 0) {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td colspan="4" class="empty-history">
                No URLs have been scanned yet.
            </td>
        `;
        historyTable.appendChild(row);
        return;
    }

    history.forEach(function(item, index) {
        const row = document.createElement("tr");

        let statusBadge;
        if (item.label) {
            const isPhish = item.is_phishing ?? (item.label === "Phishing");
            statusBadge = `
                <span class="${isPhish ? 'status-phishing' : 'status-safe'}">
                    ${isPhish ? '⚠️' : '🛡️'} ${escapeHTML(item.label)} (${escapeHTML(item.confidence || '')})
                </span>
            `;
        } else {
            statusBadge = `<span class="status-received">Received</span>`;
        }

        row.innerHTML = `
            <td>${index + 1}</td>
            <td class="url-history">${escapeHTML(item.url)}</td>
            <td>${statusBadge}</td>
            <td>${item.time}</td>
        `;

        historyTable.appendChild(row);
    });
}


/* ==========================================
   CLEAR HISTORY
========================================== */

clearHistory.addEventListener("click", function() {
    if (history.length === 0) return;

    const confirmClear = confirm("Are you sure you want to clear the scan history?");
    if (confirmClear) {
        history = [];
        saveHistory();
        displayHistory();
    }
});


/* ==========================================
   HELPERS & PERSISTENCE
========================================== */

function getCurrentTime() {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function saveHistory() {
    localStorage.setItem("phishshieldHistory", JSON.stringify(history));
}

function loadHistory() {
    const saved = localStorage.getItem("phishshieldHistory");
    if (saved) {
        try {
            history = JSON.parse(saved);
            totalInputs = history.length;
            if (totalInputsElement) totalInputsElement.textContent = totalInputs;
            if (history.length > 0 && lastInputElement) {
                lastInputElement.textContent = history[0].label 
                    ? `${history[0].label} (${history[0].confidence || ''})` 
                    : history[0].url;
            }
        } catch (e) {
            history = [];
        }
    }
}

function escapeHTML(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}


/* ==========================================
   START APPLICATION
========================================== */

loadHistory();
displayHistory();
checkBackendHealth();
setInterval(checkBackendHealth, 15000);
