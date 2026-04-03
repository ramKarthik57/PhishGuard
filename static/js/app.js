/**
 * PhishGuard v2 — Frontend Application Logic
 * Handles tabs, analysis, SOC monitor, phishing simulator, and all rendering.
 */
(function () {
    "use strict";

    // ═══════════════════════════════════════════════
    // DOM References
    // ═══════════════════════════════════════════════

    var $ = function (id) { return document.getElementById(id); };

    // Tabs
    var tabNav = $("tab-nav");
    var panels = document.querySelectorAll(".tab-panel");
    var tabBtns = document.querySelectorAll(".tab-btn");

    // Analyze
    var form = $("analyze-form");
    var urlInput = $("url-input");
    var emailInput = $("email-input");
    var analyzeBtn = $("analyze-btn");
    var btnText = analyzeBtn.querySelector(".btn__text");
    var btnLoader = analyzeBtn.querySelector(".btn__loader");
    var resultCard = $("result-section");
    var historyList = $("history-list");

    // Gauge
    var gaugeFill = $("gauge-fill");
    var gaugeValue = $("gauge-value");
    var riskBadge = $("risk-badge");

    // Confidence
    var confidencePct = $("confidence-pct");
    var confidenceNote = $("confidence-note");

    // Action
    var actionBanner = $("action-banner");
    var actionIcon = $("action-icon");
    var actionText = $("action-text");

    // Detail sections
    var breakdownBars = $("breakdown-bars");
    var ruleList = $("rule-list");
    var explainSummary = $("explain-summary");
    var evidenceChain = $("evidence-chain");
    var intelGrid = $("intel-grid");
    var spoofSection = $("spoof-section");
    var spoofAlert = $("spoof-alert");
    var emailSection = $("email-section");
    var emailList = $("email-list");
    var behaviorSection = $("behavior-section");
    var behaviorInfo = $("behavior-info");
    var vtResult = $("vt-result");
    var metaFp = $("meta-fingerprint");
    var metaTs = $("meta-timestamp");

    // SOC
    var threatIndicator = $("threat-indicator");
    var socThreatCard = $("soc-threat-card");
    var socThreatLabel = $("soc-threat-label");
    var socTotalEvents = $("soc-total-events");
    var socCriticalCount = $("soc-critical-count");
    var socWarningCount = $("soc-warning-count");
    var eventFeed = $("event-feed");

    // Simulator
    var simModeToggle = $("sim-mode-toggle");
    var simGenView = $("sim-generator-view");
    var simQuizView = $("sim-quiz-view");
    var simResults = $("sim-results");
    var simGenerateBtn = $("sim-generate-btn");
    
    // Quiz
    var quizStartBtn = $("quiz-start-btn");
    var quizContainer = $("quiz-container");
    var quizScore = $("quiz-score");
    var quizStreak = $("quiz-streak");
    var quizAccuracy = $("quiz-accuracy");
    var currentQuiz = [];
    var quizIndex = 0;

    var ARC_LENGTH = 251.33;

    var ACTION_CONFIG = {
        allow:   { icon: "\u2713", label: "Allow Access", cls: "allow" },
        caution: { icon: "\u26A0", label: "Proceed with Caution", cls: "caution" },
        block:   { icon: "\u2716", label: "Block \u2014 High Risk", cls: "block" },
    };

    // ═══════════════════════════════════════════════
    // Tab Navigation
    // ═══════════════════════════════════════════════

    tabNav.addEventListener("click", function (e) {
        var btn = e.target.closest(".tab-btn");
        if (!btn) return;
        var tab = btn.dataset.tab;
        tabBtns.forEach(function (b) { b.classList.toggle("active", b === btn); });
        panels.forEach(function (p) { p.classList.toggle("active", p.id === "panel-" + tab); });
        if (tab === "soc") refreshSOC();
    });

    // ═══════════════════════════════════════════════
    // Helpers
    // ═══════════════════════════════════════════════

    function escapeHtml(t) { var d = document.createElement("div"); d.appendChild(document.createTextNode(t)); return d.innerHTML; }
    function truncate(s, n) { return s.length > n ? s.substring(0, n) + "\u2026" : s; }
    function getGaugeColor(s) { return s < 30 ? "#34d399" : s < 60 ? "#fbbf24" : "#f87171"; }
    function setLoading(on) { analyzeBtn.disabled = on; btnText.hidden = on; btnLoader.hidden = !on; }
    function fmtTime(ts) {
        var d = new Date(ts * 1000);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    // ═══════════════════════════════════════════════
    // Gauge Animation
    // ═══════════════════════════════════════════════

    function animateGauge(score) {
        var offset = ARC_LENGTH - (score / 100) * ARC_LENGTH;
        var color = getGaugeColor(score);
        gaugeFill.style.stroke = color;
        gaugeFill.style.strokeDashoffset = offset;
        var cur = 0, step = Math.max(1, Math.floor(score / 40));
        var iv = setInterval(function () {
            cur += step;
            if (cur >= score) { cur = score; clearInterval(iv); }
            gaugeValue.textContent = cur;
            gaugeValue.style.color = getGaugeColor(cur);
        }, 25);
    }

    // ═══════════════════════════════════════════════
    // Render Scoring Breakdown
    // ═══════════════════════════════════════════════

    function renderBreakdown(bd) {
        var rows = [
            { label: "Rule Engine", key: "rule_engine", cls: "rule" },
            { label: "ML Classifier", key: "ml_classifier", cls: "ml" },
            { label: "Threat Intel", key: "threat_intel", cls: "intel" },
            { label: "Anomaly", key: "anomaly", cls: "anomaly" },
            { label: "Email Bonus", key: "email_bonus", cls: "email" },
            { label: "Behavior", key: "behavior_bonus", cls: "behavior" },
        ];
        var maxVal = 0;
        rows.forEach(function (r) { maxVal = Math.max(maxVal, bd[r.key] || 0); });
        if (maxVal < 1) maxVal = 1;

        breakdownBars.innerHTML = rows.map(function (r) {
            var val = bd[r.key] || 0;
            var pct = Math.min(100, (val / maxVal) * 100);
            return '<div class="breakdown-row">' +
                '<span class="breakdown-row__label">' + r.label + '</span>' +
                '<div class="breakdown-row__bar-wrap"><div class="breakdown-row__bar ' + r.cls + '" style="width:' + pct + '%"></div></div>' +
                '<span class="breakdown-row__val">' + val.toFixed(1) + '</span>' +
                '</div>';
        }).join("");
    }

    // ═══════════════════════════════════════════════
    // Render Evidence Chain
    // ═══════════════════════════════════════════════

    function renderEvidence(chain) {
        if (!chain || chain.length === 0) {
            evidenceChain.innerHTML = '<p style="color:var(--text-muted);font-size:.82rem">No evidence steps to display.</p>';
            return;
        }
        evidenceChain.innerHTML = chain.map(function (step) {
            return '<div class="evidence-step ' + (step.severity || "medium") + '">' +
                '<div class="evidence-step__num">' + step.step + '</div>' +
                '<div class="evidence-step__body">' +
                    '<div class="evidence-step__source">' + escapeHtml(step.source) + '</div>' +
                    '<div class="evidence-step__indicator">' + escapeHtml(step.indicator) + '</div>' +
                '</div>' +
                '</div>';
        }).join("");
    }

    // ═══════════════════════════════════════════════
    // Render Threat Intel
    // ═══════════════════════════════════════════════

    function renderIntel(ti) {
        if (!ti) { intelGrid.innerHTML = ""; return; }
        var repClass = ti.reputation_score >= 0.7 ? "good" : ti.reputation_score >= 0.4 ? "warn" : "bad";
        var html = '';
        html += '<div class="intel-item"><div class="intel-item__label">Domain</div><div class="intel-item__value">' + escapeHtml(ti.domain) + '</div></div>';
        html += '<div class="intel-item"><div class="intel-item__label">Reputation</div><div class="intel-item__value ' + repClass + '">' + ti.reputation_score + ' / 1.0</div></div>';
        html += '<div class="intel-item"><div class="intel-item__label">Blacklisted</div><div class="intel-item__value ' + (ti.is_blacklisted ? "bad" : "good") + '">' + (ti.is_blacklisted ? "YES (" + escapeHtml(ti.blacklist_source || "") + ")" : "No") + '</div></div>';
        html += '<div class="intel-item"><div class="intel-item__label">Domain Age</div><div class="intel-item__value ' + (ti.is_young_domain ? "warn" : "") + '">' + (ti.domain_age_days >= 0 ? ti.domain_age_days + " days" : "Unknown") + '</div></div>';
        if (ti.threat_tags && ti.threat_tags.length > 0) {
            html += '<div class="intel-tags">' + ti.threat_tags.map(function (t) { return '<span class="intel-tag">' + escapeHtml(t) + '</span>'; }).join("") + '</div>';
        }
        intelGrid.innerHTML = html;
    }

    // ═══════════════════════════════════════════════
    // Render Full Result
    // ═══════════════════════════════════════════════

    function renderResult(data) {
        var level = data.risk_level.toLowerCase();

        // Gauge
        riskBadge.textContent = data.risk_level;
        riskBadge.className = "risk-badge " + level;
        gaugeFill.style.strokeDashoffset = ARC_LENGTH;
        gaugeValue.textContent = "0";
        setTimeout(function () { animateGauge(data.risk_score); }, 100);

        // Confidence
        var conf = data.explanation ? data.explanation.confidence : null;
        if (conf) {
            confidencePct.textContent = conf.percentage + "%";
            confidenceNote.textContent = conf.label;
        }

        // Action
        var ac = ACTION_CONFIG[data.action] || ACTION_CONFIG.allow;
        actionBanner.className = "action-banner " + ac.cls;
        actionIcon.textContent = ac.icon;
        actionText.textContent = ac.label;

        // Scoring Breakdown
        if (data.scoring_breakdown) renderBreakdown(data.scoring_breakdown);

        // Rules
        ruleList.innerHTML = "";
        if (data.triggered_rules && data.triggered_rules.length > 0) {
            data.triggered_rules.forEach(function (r) {
                var li = document.createElement("li");
                li.textContent = r;
                ruleList.appendChild(li);
            });
        } else {
            var li = document.createElement("li");
            li.className = "rule--safe";
            li.textContent = "No phishing indicators detected.";
            ruleList.appendChild(li);
        }

        // Explainability
        if (data.explanation) {
            explainSummary.textContent = data.explanation.summary || "";
            renderEvidence(data.explanation.evidence_chain);
        }

        // Threat Intel
        renderIntel(data.threat_intel);

        // Brand Spoofing
        if (data.brand_spoofing && data.brand_spoofing.is_spoofing) {
            spoofSection.classList.remove("hidden");
            var spInfo = data.brand_spoofing;
            var spHtml = '<strong>' + escapeHtml(spInfo.matched_brand) + ' Impersonation</strong> (' + Math.round(spInfo.similarity_score * 100) + '% match)<br>';
            if (spInfo.details && spInfo.details.length > 0) {
                spHtml += '<ul class="rule-list rule-list--email" style="margin-top:8px">';
                spInfo.details.forEach(function(d){ spHtml += '<li>' + escapeHtml(d) + '</li>'; });
                spHtml += '</ul>';
            }
            spoofAlert.innerHTML = spHtml;
        } else {
            spoofSection.classList.add("hidden");
        }

        // Email
        if (data.email_flags && data.email_flags.length > 0) {
            emailSection.classList.remove("hidden");
            emailList.innerHTML = "";
            data.email_flags.forEach(function (f) {
                var li = document.createElement("li");
                li.textContent = f;
                emailList.appendChild(li);
            });
        } else {
            emailSection.classList.add("hidden");
        }

        // Behavior
        if (data.behavior && (data.behavior.behavior_flags.length > 0 || data.behavior.session_stats)) {
            behaviorSection.classList.remove("hidden");
            var bhtml = '';
            var ss = data.behavior.session_stats;
            if (ss) {
                bhtml += '<div class="behavior-stat"><div class="behavior-stat__label">Total Scans</div><div class="behavior-stat__value">' + ss.total_scans + '</div></div>';
                bhtml += '<div class="behavior-stat"><div class="behavior-stat__label">Avg Risk</div><div class="behavior-stat__value">' + ss.avg_risk + '</div></div>';
                bhtml += '<div class="behavior-stat"><div class="behavior-stat__label">Escalation</div><div class="behavior-stat__value">Level ' + data.behavior.escalation_level + '</div></div>';
            }
            if (data.behavior.behavior_flags.length > 0) {
                bhtml += '<ul class="rule-list behavior-flags">';
                data.behavior.behavior_flags.forEach(function (f) {
                    bhtml += '<li>' + escapeHtml(f) + '</li>';
                });
                bhtml += '</ul>';
            }
            behaviorInfo.innerHTML = bhtml;
        } else {
            behaviorSection.classList.add("hidden");
        }

        // VirusTotal
        if (data.virustotal) {
            var vt = data.virustotal;
            vtResult.innerHTML = "<strong>" + vt.positives + " / " + vt.total + "</strong> engines flagged as malicious";
        } else {
            vtResult.innerHTML = '<span style="color:var(--text-muted)">VirusTotal API key not set. Set <code>VIRUSTOTAL_API_KEY</code> env var to enable.</span>';
        }

        // Meta
        metaFp.textContent = "SHA-256: " + (data.fingerprint || "").substring(0, 16) + "\u2026";
        metaTs.textContent = data.timestamp || new Date().toISOString();

        // Show
        resultCard.classList.remove("hidden", "fade-in");
        void resultCard.offsetWidth;
        resultCard.classList.add("fade-in");
        resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ═══════════════════════════════════════════════
    // History
    // ═══════════════════════════════════════════════

    function addToHistory(data) {
        var lvl = data.risk_level.toLowerCase();
        var empty = historyList.querySelector(".history-empty");
        if (empty) empty.remove();
        var div = document.createElement("div");
        div.className = "history-item";
        div.innerHTML =
            '<span class="history-item__url" title="' + escapeHtml(data.url) + '">' + escapeHtml(truncate(data.url, 50)) + '</span>' +
            '<div class="history-item__meta"><span class="history-item__score ' + lvl + '">' + data.risk_score + ' ' + data.risk_level + '</span></div>';
        historyList.prepend(div);
        while (historyList.children.length > 10) historyList.lastElementChild.remove();
    }

    // ═══════════════════════════════════════════════
    // Form Submit
    // ═══════════════════════════════════════════════

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var url = urlInput.value.trim();
        if (!url) return;
        setLoading(true);
        fetch("/analyze", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-API-Key": "TEST-KEY"
            },
            body: JSON.stringify({ url: url, email_body: emailInput.value.trim() || null }),
        })
        .then(function (r) {
            if (!r.ok) return r.json().then(function (e) { throw new Error(e.error || "Request failed"); });
            return r.json();
        })
        .then(function (data) {
            renderResult(data);
            addToHistory(data);
        })
        .catch(function (err) { alert("Analysis error: " + err.message); })
        .finally(function () { setLoading(false); });
    });

    // Quick test chips
    document.querySelectorAll(".quick-tests .chip").forEach(function (chip) {
        chip.addEventListener("click", function () {
            urlInput.value = chip.dataset.url || "";
            emailInput.value = chip.dataset.email || "";
            form.dispatchEvent(new Event("submit"));
        });
    });

    // ═══════════════════════════════════════════════
    // SOC Monitor
    // ═══════════════════════════════════════════════

    function refreshSOC() {
        // Threat level
        fetch("/api/soc/threat-level", {
            headers: { "X-API-Key": "TEST-KEY" }
        })
            .then(function (r) { return r.json(); })
            .then(function (tl) {
                socThreatLabel.textContent = tl.label;
                socTotalEvents.textContent = tl.total_all_time;
                socCriticalCount.textContent = tl.critical_events;
                socWarningCount.textContent = tl.warning_events;

                ["level-0","level-1","level-2","level-3","level-4"].forEach(function(c){
                    threatIndicator.classList.remove(c);
                    socThreatCard.classList.remove(c);
                });
                threatIndicator.classList.add("level-" + tl.level);
                socThreatCard.classList.add("level-" + tl.level);
                threatIndicator.querySelector(".threat-indicator__label").textContent = tl.label;
            });

        // Events
        refreshEvents("all");
    }

    function refreshEvents(severity) {
        var url = "/api/soc/events?limit=30";
        if (severity && severity !== "all") url += "&severity=" + severity;
        fetch(url, {
            headers: { "X-API-Key": "TEST-KEY" }
        })
            .then(function (r) { return r.json(); })
            .then(function (events) {
                if (events.length === 0) {
                    eventFeed.innerHTML = '<p class="history-empty">No events recorded yet.</p>';
                    return;
                }
                eventFeed.innerHTML = events.map(function (ev) {
                    return '<div class="event-item ' + ev.severity + '">' +
                        '<span class="event-item__severity ' + ev.severity + '">' + ev.severity + '</span>' +
                        '<div class="event-item__body">' +
                            '<div class="event-item__title">' + escapeHtml(ev.title) + '</div>' +
                            '<div class="event-item__detail">' + escapeHtml(ev.detail) + '</div>' +
                        '</div>' +
                        '<span class="event-item__time">' + fmtTime(ev.timestamp) + '</span>' +
                        '</div>';
                }).join("");
            });
    }

    // Filter pills
    document.querySelectorAll(".filter-pill").forEach(function (pill) {
        pill.addEventListener("click", function () {
            document.querySelectorAll(".filter-pill").forEach(function (p) { p.classList.remove("active"); });
            pill.classList.add("active");
            refreshEvents(pill.dataset.severity);
        });
    });

    // ═══════════════════════════════════════════════
    // Phishing Simulator & Training Mode
    // ═══════════════════════════════════════════════

    // Mode Toggle
    simModeToggle.addEventListener("click", function (e) {
        if(e.target.tagName !== "BUTTON") return;
        var mode = e.target.dataset.mode;
        document.querySelectorAll("#sim-mode-toggle .chip").forEach(function(c) { c.classList.remove("active"); });
        e.target.classList.add("active");
        
        if (mode === "generator") {
            simGenView.classList.remove("hidden");
            simQuizView.classList.add("hidden");
        } else {
            simGenView.classList.add("hidden");
            simQuizView.classList.remove("hidden");
        }
    });

    // Generator logic
    var simDifficulty = "medium";

    document.querySelectorAll("#sim-difficulty .chip").forEach(function (chip) {
        chip.addEventListener("click", function () {
            document.querySelectorAll("#sim-difficulty .chip").forEach(function (c) { c.classList.remove("active"); });
            chip.classList.add("active");
            simDifficulty = chip.dataset.diff;
        });
    });

    simGenerateBtn.addEventListener("click", function () {
        simGenerateBtn.disabled = true;
        fetch("/api/simulate", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-API-Key": "TEST-KEY"
            },
            body: JSON.stringify({ difficulty: simDifficulty, count: 3 }),
        })
        .then(function (r) { return r.json(); })
        .then(function (samples) {
            simGenerateBtn.disabled = false;
            simResults.innerHTML = samples.map(function (s, i) {
                return '<div class="sim-card">' +
                    '<div class="sim-card__header">' +
                        '<span class="sim-card__type ' + s.difficulty + '">' + s.difficulty.toUpperCase() + ' - ' + s.attack_type.replace(/_/g, " ") + '</span>' +
                        '<span class="sim-card__attack">Expected: ' + s.expected_risk + '</span>' +
                    '</div>' +
                    '<div class="sim-card__url">' + escapeHtml(s.url) + '</div>' +
                    '<div class="sim-card__subject">' + escapeHtml(s.email_subject || "") + '</div>' +
                    '<div class="sim-card__body">' + escapeHtml(s.email_body || "") + '</div>' +
                    '<div class="sim-card__actions">' +
                        '<button class="sim-card__btn sim-test-btn" data-url="' + escapeHtml(s.url) + '" data-email="' + escapeHtml(s.email_body || "") + '">Test with PhishGuard</button>' +
                    '</div>' +
                    '</div>';
            }).join("");

            simResults.querySelectorAll(".sim-test-btn").forEach(function (btn) {
                btn.addEventListener("click", function () {
                    urlInput.value = btn.dataset.url;
                    emailInput.value = btn.dataset.email;
                    tabBtns.forEach(function (b) { b.classList.toggle("active", b.dataset.tab === "analyze"); });
                    panels.forEach(function (p) { p.classList.toggle("active", p.id === "panel-analyze"); });
                    form.dispatchEvent(new Event("submit"));
                });
            });
        });
    });

    // Quiz logic
    quizStartBtn.addEventListener("click", function() {
        quizStartBtn.disabled = true;
        quizStartBtn.innerHTML = '<div class="spinner"></div> Loading...';
        
        fetch("/api/quiz/generate?difficulty=" + simDifficulty + "&count=5", {
            headers: { "X-API-Key": "TEST-KEY" }
        })
        .then(function(r) { return r.json(); })
        .then(function(challenges) {
            quizStartBtn.style.display = "none";
            currentQuiz = challenges;
            quizIndex = 0;
            renderQuizCard();
        });
    });

    function renderQuizCard() {
        if (quizIndex >= currentQuiz.length) {
            quizContainer.innerHTML = '<div class="sim-card" style="text-align:center"><h3 style="margin-bottom:10px">Session Complete!</h3><button class="btn btn--primary" onclick="$(\'quiz-start-btn\').click()">Play Again</button></div>';
            quizStartBtn.style.display = "flex";
            quizStartBtn.disabled = false;
            quizStartBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="btn__icon"><polygon points="5 3 19 12 5 21 5 3"/></svg> Start Another Session';
            return;
        }

        var ch = currentQuiz[quizIndex];
        var html = '<div class="quiz-card" id="quiz-card-' + ch.challenge_id + '">' +
            '<div style="font-size:0.75rem; color:var(--text-muted); font-weight:700; text-transform:uppercase; margin-bottom:10px;">Challenge ' + (quizIndex + 1) + ' of ' + currentQuiz.length + '</div>' +
            '<div class="quiz-card__url">' + escapeHtml(ch.url) + '</div>';
            
        if (ch.email_body) {
            html += '<div class="sim-card__subject">' + escapeHtml(ch.email_subject || "(No subject)") + '</div>';
            html += '<div class="sim-card__body" style="margin-bottom:15px">' + escapeHtml(ch.email_body) + '</div>';
        }
        
        html += '<div class="quiz-card__hint">💡 Hint: ' + escapeHtml(ch.hint) + '</div>' +
            '<div class="quiz-card__actions" id="quiz-actions">' +
                '<button class="quiz-btn quiz-btn--safe" data-ans="safe">Safe</button>' +
                '<button class="quiz-btn quiz-btn--phish" data-ans="phishing">Phishing</button>' +
            '</div>' +
            '<div class="quiz-feedback" id="quiz-feedback"></div>' +
        '</div>';
        
        quizContainer.innerHTML = html;

        // Bind answers
        var actions = $("quiz-actions");
        actions.querySelectorAll(".quiz-btn").forEach(function(btn) {
            btn.addEventListener("click", function() {
                var ans = btn.dataset.ans;
                actions.querySelectorAll(".quiz-btn").forEach(function(b){ b.disabled = true; });
                submitQuizAnswer(ch.challenge_id, ans);
            });
        });
    }

    function submitQuizAnswer(cid, ans) {
        fetch("/api/quiz/evaluate", {
            method: "POST",
            headers: { 
                "Content-Type": "application/json",
                "X-API-Key": "TEST-KEY"
            },
            body: JSON.stringify({ challenge_id: cid, answer: ans })
        })
        .then(function(r) { return r.json(); })
        .then(function(res) {
            var fb = $("quiz-feedback");
            var act = $("quiz-actions");
            var cClass = res.is_correct ? "correct" : "incorrect";
            var header = res.is_correct ? "🎯 Correct!" : "❌ Incorrect";
            
            // Highlight selected button
            act.querySelectorAll(".quiz-btn").forEach(function(b){
                if(b.dataset.ans !== ans) b.style.opacity = 0.3;
            });

            var fbHtml = '<div class="quiz-feedback__title">' + header + '</div>' +
                '<div class="quiz-feedback__expl">' + escapeHtml(res.explanation) + '</div>';
                
            if (res.indicators && res.indicators.length > 0) {
                fbHtml += '<ul class="rule-list" style="margin-top:10px">';
                res.indicators.forEach(function(ind) { fbHtml += '<li>' + escapeHtml(ind) + '</li>'; });
                fbHtml += '</ul>';
            }
            
            fbHtml += '<button class="btn btn--primary" style="margin-top:15px" id="quiz-next">Next Challenge &rarr;</button>';
            
            fb.innerHTML = fbHtml;
            fb.className = "quiz-feedback show " + cClass;

            // Update stats
            if (res.session_score) {
                var ss = res.session_score;
                quizScore.textContent = ss.correct + '/' + ss.total;
                quizStreak.textContent = ss.streak;
                quizAccuracy.textContent = ss.accuracy + '%';
            }

            $("quiz-next").addEventListener("click", function() {
                quizIndex++;
                renderQuizCard();
            });
        });
    }

    // ═══════════════════════════════════════════════
    // Auto-refresh threat indicator
    // ═══════════════════════════════════════════════

    setInterval(function () {
        fetch("/api/soc/threat-level", {
            headers: { "X-API-Key": "TEST-KEY" }
        })
            .then(function (r) { return r.json(); })
            .then(function (tl) {
                ["level-0","level-1","level-2","level-3","level-4"].forEach(function(c){
                    threatIndicator.classList.remove(c);
                });
                threatIndicator.classList.add("level-" + tl.level);
                threatIndicator.querySelector(".threat-indicator__label").textContent = tl.label;
            })
            .catch(function () {});
    }, 10000);

})();
