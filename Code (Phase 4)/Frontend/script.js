/* ==========================================
   CONFIGURATION & API ENDPOINT
========================================== */

// Detect API base URL: if opened from file://, fallback to localhost:5000
const API_BASE_URL =
    window.location.protocol === "file:"
        ? "http://127.0.0.1:5000/api"
        : (window.location.origin + "/api");

let totalInputs = 0;
let history = [];
let isBackendOnline = false;


/* ==========================================
   DOM ELEMENTS
========================================== */

const urlInput = document.getElementById("urlInput");
const receiveButton = document.getElementById("receiveButton");
const totalInputsElement = document.getElementById("totalInputs");
const lastInputElement = document.getElementById("lastInput");
const lastVerdictElement = document.getElementById("lastVerdict");
const backendStatusElement = document.getElementById("backendStatus");
const sidebarDot = document.getElementById("sidebarDot");
const sidebarStatus = document.getElementById("sidebarStatus");

const historyTable = document.getElementById("historyTable");
const clearHistory = document.getElementById("clearHistory");
const breadcrumbPage = document.getElementById("breadcrumbPage");
const menuItems = document.querySelectorAll(".menu-item");

const scannerPage = document.getElementById("scannerPage");
const historyPage = document.getElementById("historyPage");
const howPage = document.getElementById("howPage");

// Result Card Elements
const scanResultContainer = document.getElementById("scanResultContainer");
const resultCard = document.getElementById("resultCard");
const verdictIcon = document.getElementById("verdictIcon");
const verdictTitle = document.getElementById("verdictTitle");
const verdictSubtitle = document.getElementById("verdictSubtitle");
const riskPill = document.getElementById("riskPill");
const resUrl = document.getElementById("resUrl");
const resConfidence = document.getElementById("resConfidence");
const resPhishProb = document.getElementById("resPhishProb");
const resLegitProb = document.getElementById("resLegitProb");
const barPercentage = document.getElementById("barPercentage");
const confidenceFill = document.getElementById("confidenceFill");
const featureChips = document.getElementById("featureChips");


/* ==========================================
   PAGE SWITCHING
========================================== */

menuItems.forEach(function(item) {
    item.addEventListener("click", function(event) {
        event.preventDefault();

        menuItems.forEach(function(menu) {
            menu.classList.remove("active");
        });

        item.classList.add("active");
        const page = item.getAttribute("data-page");

        scannerPage.classList.remove("active-page");
        historyPage.classList.remove("active-page");
        howPage.classList.remove("active-page");

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
   BACKEND HEALTH CHECK
========================================== */

async function checkBackendHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`, {
            method: "GET",
            headers: { "Accept": "application/json" }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.model_loaded) {
                setBackendStatus(true, "ML MODEL READY", "Online");
            } else {
                setBackendStatus(false, "MODEL LOADING", "Loading...");
            }
        } else {
            setBackendStatus(false, "BACKEND OFFLINE", "Offline");
        }
    } catch (err) {
        setBackendStatus(false, "BACKEND OFFLINE", "Offline");
    }
}

function setBackendStatus(online, sidebarMsg, cardMsg) {
    isBackendOnline = online;
    if (sidebarStatus) sidebarStatus.textContent = sidebarMsg;
    if (backendStatusElement) backendStatusElement.textContent = cardMsg;

    if (sidebarDot) {
        sidebarDot.className = "status-dot " + (online ? "green-dot" : "red-dot");
    }
}


/* ==========================================
   URL SCANNING (ML INFERENCE)
========================================== */

async function scanWebsite() {
    const rawUrl = urlInput.value.trim();

    if (rawUrl === "") {
        alert("Please enter a website URL to analyze.");
        urlInput.focus();
        return;
    }

    // Set UI to loading state
    receiveButton.disabled = true;
    receiveButton.classList.add("btn-loading");
    receiveButton.textContent = "Analyzing with ML...";

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify({ url: rawUrl, fetch_html: true })
        });

        if (!response.ok) {
            throw new Error(`HTTP Error ${response.status}`);
        }

        const data = await response.json();

        if (!data.success) {
            throw new Error(data.error || "Model scan failed.");
        }

        // Render result
        renderScanResult(data);

        // Update overall stats
        totalInputs++;
        totalInputsElement.textContent = totalInputs;
        lastInputElement.textContent = data.url;
        lastVerdictElement.textContent = data.prediction;

        // Save to history
        const historyItem = {
            url: data.url,
            prediction: data.prediction,
            confidence: data.confidence,
            risk_level: data.risk_level,
            is_phishing: data.is_phishing,
            time: getCurrentTime()
        };

        history.unshift(historyItem);
        saveHistory();

    } catch (error) {
        console.error("Scan error:", error);
        alert(
            `Unable to connect to the PhishShield ML Server at ${API_BASE_URL}.\n\nPlease ensure the backend is running with:\npython "Code (Phase 4)/Backend/app.py"`
        );
    } finally {
        receiveButton.disabled = false;
        receiveButton.classList.remove("btn-loading");
        receiveButton.textContent = "Scan URL →";
    }
}

receiveButton.addEventListener("click", scanWebsite);

urlInput.addEventListener("keydown", function(event) {
    if (event.key === "Enter") {
        scanWebsite();
    }
});


/* ==========================================
   RENDER RESULT CARD
========================================== */

function renderScanResult(data) {
    scanResultContainer.classList.remove("hidden");

    const isPhishing = data.is_phishing === 1;

    // Toggle card styles
    if (isPhishing) {
        resultCard.classList.add("is-phishing");
        verdictIcon.textContent = "⚠️";
        verdictTitle.textContent = "PHISHING DETECTED";
        verdictSubtitle.textContent = "Warning: This website exhibits high-risk phishing and fraudulent patterns.";

        riskPill.className = "risk-pill phishing";
        riskPill.textContent = data.risk_level.toUpperCase();
    } else {
        resultCard.classList.remove("is-phishing");
        verdictIcon.textContent = "🛡️";
        verdictTitle.textContent = "LEGITIMATE WEBSITE";
        verdictSubtitle.textContent = "This website appears safe and matches legitimate structural web patterns.";

        riskPill.className = "risk-pill safe";
        riskPill.textContent = data.risk_level.toUpperCase();
    }

    // Populate Metrics
    resUrl.textContent = data.url;
    resConfidence.textContent = `${data.confidence}%`;
    resPhishProb.textContent = `${data.prob_phishing}%`;
    resLegitProb.textContent = `${data.prob_legitimate}%`;

    // Animate Confidence Bar
    barPercentage.textContent = `Model Confidence: ${data.confidence}%`;
    confidenceFill.style.width = "0%";
    setTimeout(() => {
        confidenceFill.style.width = `${data.confidence}%`;
    }, 50);

    // Populate Feature Chips
    renderFeatureChips(data.features, isPhishing);

    // Smooth scroll into view
    scanResultContainer.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderFeatureChips(features, isPhishing) {
    featureChips.innerHTML = "";

    if (!features) return;

    const chips = [
        {
            label: features.is_https ? "HTTPS: Enabled" : "HTTPS: Insecure (HTTP)",
            type: features.is_https ? "success-chip" : "danger-chip"
        },
        {
            label: `Domain: ${escapeHTML(features.domain || "N/A")}`,
            type: "feature-chip"
        },
        {
            label: `TLD: .${escapeHTML(features.tld || "unknown")}`,
            type: "feature-chip"
        },
        {
            label: `URL Length: ${features.url_length} chars`,
            type: "feature-chip"
        },
        {
            label: `Subdomains: ${features.subdomain_count}`,
            type: features.subdomain_count > 2 ? "warning-chip" : "feature-chip"
        },
        {
            label: features.is_domain_ip ? "Direct IP Host: Yes" : "Direct IP Host: No",
            type: features.is_domain_ip ? "danger-chip" : "success-chip"
        },
        {
            label: features.has_shortener ? "Shortener Detected: Yes" : "Standard URL",
            type: features.has_shortener ? "warning-chip" : "feature-chip"
        },
        {
            label: features.has_password_field ? "Password Input: Yes" : "Password Input: None",
            type: (features.has_password_field && isPhishing) ? "danger-chip" : "feature-chip"
        }
    ];

    chips.forEach(chip => {
        const span = document.createElement("span");
        span.className = `feature-chip ${chip.type}`;
        span.textContent = chip.label;
        featureChips.appendChild(span);
    });
}


/* ==========================================
   DISPLAY HISTORY
========================================== */

function displayHistory() {
    historyTable.innerHTML = "";

    if (history.length === 0) {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td colspan="5" class="empty-history" style="text-align: center; padding: 24px; color: #8b9aac;">
                No URLs have been analyzed yet.
            </td>
        `;
        historyTable.appendChild(row);
        return;
    }

    history.forEach(function(item, index) {
        const row = document.createElement("tr");
        const isPhish = item.prediction === "Phishing";
        const badgeClass = isPhish ? "badge-phishing" : "badge-legitimate";

        row.innerHTML = `
            <td>${index + 1}</td>
            <td class="url-history">${escapeHTML(item.url)}</td>
            <td>
                <span class="status-badge ${badgeClass}">
                    ${item.prediction}
                </span>
            </td>
            <td><strong>${item.confidence}%</strong> (${item.risk_level})</td>
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
        totalInputs = 0;
        totalInputsElement.textContent = "0";
        lastInputElement.textContent = "—";
        lastVerdictElement.textContent = "Ready";
    }
});


/* ==========================================
   STORAGE & UTILITIES
========================================== */

function getCurrentTime() {
    const now = new Date();
    return now.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });
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
            totalInputsElement.textContent = totalInputs;

            if (history.length > 0) {
                lastInputElement.textContent = history[0].url;
                lastVerdictElement.textContent = history[0].prediction || "Ready";
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
   INITIALIZATION
========================================== */

loadHistory();
displayHistory();
checkBackendHealth();
setInterval(checkBackendHealth, 10000);
