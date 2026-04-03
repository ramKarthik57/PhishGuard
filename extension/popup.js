document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        let activeTab = tabs[0];
        
        // Grab the background page state
        chrome.runtime.getBackgroundPage(function(bg) {
            let state = bg.tabThreatStates[activeTab.id];
            
            if (state) {
                renderState(state);
            } else {
                // If no state exists (maybe page didn't load completely or isn't HTTP),
                // we'll just wait or show unknown
                document.getElementById('loading').innerText = "Safe or unanalyzed page.";
            }
        });
    });

    document.getElementById('view-dashboard').addEventListener('click', () => {
        chrome.tabs.create({ url: "http://127.0.0.1:5000" });
    });
});

function renderState(data) {
    document.getElementById('loading').style.display = 'none';
    document.getElementById('results').style.display = 'block';

    const scoreCircle = document.getElementById('score-circle');
    const scoreVal = document.getElementById('score-val');
    const threatLevel = document.getElementById('threat-level');
    const triggersList = document.getElementById('triggers-list');
    const xaiSummary = document.getElementById('xai-summary');

    // Update Score Circle and Level
    scoreVal.innerText = data.risk_score;
    threatLevel.innerText = data.risk_level.toUpperCase();
    
    // Reset Classes
    scoreCircle.className = "score-circle";
    if (data.risk_level === "MEDIUM") {
        scoreCircle.classList.add("medium");
        threatLevel.style.color = "#f59e0b";
    } else if (data.risk_level === "HIGH") {
        scoreCircle.classList.add("high");
        threatLevel.style.color = "#ef4444";
    } else {
        threatLevel.style.color = "#4ade80";
    }

    // Populate Indicators
    triggersList.innerHTML = "";
    if (data.triggered_rules && data.triggered_rules.length > 0) {
        data.triggered_rules.forEach(rule => {
            let li = document.createElement("li");
            li.innerText = rule;
            triggersList.appendChild(li);
        });
    } else {
        triggersList.innerHTML = "<li>No threats detected.</li>";
    }

    // XAI Summary
    if (data.explanation && data.explanation.summary) {
        xaiSummary.innerText = data.explanation.summary;
    } else {
        xaiSummary.style.display = 'none';
    }
}
