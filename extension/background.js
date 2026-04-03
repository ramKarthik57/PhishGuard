const API_ENDPOINT = "http://127.0.0.1:5000/analyze"; // Future: Configure for production deployments

// Store the latest scan results indexed by tabId
let tabThreatStates = {};

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "ANALYZE_PAGE" && sender.tab) {
        let tabId = sender.tab.id;
        
        // Build payload mimicking the API structure but augmented
        let payload = {
            url: request.data.url,
            email_body: request.data.extracted_text, 
            extension_metadata: {
                has_password_field: request.data.has_password_field,
                insecure_password_field: request.data.insecure_password_field,
                external_forms_count: request.data.external_forms.length
            }
        };

        // Call our local PhishGuard API
        fetch(API_ENDPOINT, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        })
        .then(response => response.json())
        .then(result => {
            tabThreatStates[tabId] = result;

            // Trigger Enterprise Mode Blocking Action
            if (result.risk_level === "HIGH") {
                chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#d32f2f" });
                chrome.action.setBadgeText({ tabId: tabId, text: "!" });
                
                // Instruct the content script to inject the block overlay
                chrome.tabs.sendMessage(tabId, {
                    action: "SHOW_BLOCK_PAGE",
                    data: result
                });
            } else if (result.risk_level === "MEDIUM") {
                chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: "#f57c00" });
                chrome.action.setBadgeText({ tabId: tabId, text: "?" });
            } else {
                chrome.action.setBadgeText({ tabId: tabId, text: "" });
            }
        })
        .catch(error => console.log("PhishGuard Backend Unreachable", error));
    }
});

// Clean up state when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    delete tabThreatStates[tabId];
});
