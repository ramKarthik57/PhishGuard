// Inject logic to analyze page DOM
function analyzePageContent() {
    let forms = document.querySelectorAll("form");
    let passwordInputs = document.querySelectorAll("input[type='password']");
    
    // Check if the page is asking for passwords but not using HTTPS
    let askingPasswordNoHttps = passwordInputs.length > 0 && window.location.protocol !== "https:";
    
    // Check external script sources
    let scripts = document.querySelectorAll("script[src]");
    let externalScripts = Array.from(scripts).map(s => s.src).filter(src => {
        try {
            return new URL(src).hostname !== window.location.hostname;
        } catch { return false; }
    });
    
    // Check form actions
    let formActions = Array.from(forms).map(f => f.action).filter(a => a);
    let externalForms = formActions.filter(action => {
        try {
            return new URL(action).hostname !== window.location.hostname;
        } catch { return false; }
    });

    let bodyText = document.body.innerText || "";
    
    // We send this structured context to the background script
    return {
        url: window.location.href,
        has_password_field: passwordInputs.length > 0,
        insecure_password_field: askingPasswordNoHttps,
        external_scripts: externalScripts,
        external_forms: externalForms,
        extracted_text: bodyText.substring(0, 500) // First 500 chars for NLP ML scoring
    };
}

// Receive message from background if we need to block the page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "SHOW_BLOCK_PAGE") {
        injectBlockOverlay(request.data);
    }
});

function injectBlockOverlay(data) {
    // If the overlay already exists, don't inject again
    if (document.getElementById("phishguard-overlay")) return;

    let overlay = document.createElement("div");
    overlay.id = "phishguard-overlay";
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
        background-color: #d32f2f; color: white; z-index: 9999999;
        display: flex; flex-direction: column; justify-content: center; align-items: center;
        font-family: sans-serif; text-align: center; padding: 20px;
    `;

    overlay.innerHTML = `
        <h1 style="font-size: 48px; margin-bottom: 20px;">🛑 Threat Blocked by PhishGuard</h1>
        <p style="font-size: 24px; max-width: 800px;">This website has been classified as a <b>HIGH RISK</b> phishing threat.</p>
        <div style="background: rgba(0,0,0,0.2); padding: 20px; border-radius: 8px; margin: 20px; max-width: 800px; text-align: left;">
            <h3 style="margin-top: 0;">Explainable AI Analysis:</h3>
            <p>${data.explanation.summary}</p>
            <ul>
                ${data.explanation.reasoning.map(r => `<li>${r.explanation}</li>`).join('')}
            </ul>
        </div>
        <button id="phishguard-bypass" style="margin-top: 30px; padding: 10px 20px; font-size: 16px; background: transparent; border: 2px solid white; color: white; cursor: pointer; border-radius: 4px;">Ignore Warning (Not Recommended)</button>
    `;

    document.documentElement.appendChild(overlay);
    
    // Stop body scrolling
    document.body.style.overflow = "hidden";

    document.getElementById("phishguard-bypass").addEventListener("click", () => {
        overlay.remove();
        document.body.style.overflow = "auto";
    });
}

// Automatically analyze the page once idle
requestIdleCallback(() => {
    let payload = analyzePageContent();
    chrome.runtime.sendMessage({ action: "ANALYZE_PAGE", data: payload });
});
