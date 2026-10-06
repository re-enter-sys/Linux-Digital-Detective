/*
 * Linux Digital Detective
 * Dashboard Application Controller
 *
 * Central controller for:
 * - Police Station
 * - Case Investigation
 * - Evidence
 * - Timeline
 * - Findings
 * - Attack Board
 * - Attack Story
 * - MITRE ATT&CK
 * - Report
 *
 * Theme-safe:
 * this controller contains functionality only.
 */


/* ============================================================
   GLOBAL STATE
   ============================================================ */

window.LDD = window.LDD || {};

LDD.state = {

    cases: [],

    currentCase: null,

    investigationData: null,

    evidence: [],

    events: [],

    findings: [],

    attackChains: [],

    mitre: [],

    attackStory: null,

    riskScore: null,

    caseDetails: null

};

LDD.currentCase = null;


/* ============================================================
   UTILITY FUNCTIONS
   ============================================================ */

LDD.escape = function(value) {

    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
};


LDD.severityClass = function(
    severity
) {

    return String(
        severity || "INFO"
    )
        .toLowerCase()
        .replaceAll(
            "_",
            "-"
        );
};


LDD.formatDate = function(
    value
) {

    if (!value) {
        return "-";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString();
};


/* ============================================================
   API REQUEST
   ============================================================ */

LDD.request = async function(
    url,
    options = {}
) {

    const response =
        await fetch(
            url,
            options
        );


    if (!response.ok) {

        throw new Error(
            `HTTP ${response.status}: ${response.statusText}`
        );

    }


    const contentType =
        response.headers.get(
            "content-type"
        ) || "";


    if (
        contentType.includes(
            "application/json"
        )
    ) {

        return response.json();

    }


    return response.text();
};


/* ============================================================
   PAGE CONTROL
   ============================================================ */

function showPage(
    pageId
) {

    document
        .querySelectorAll(
            ".page"
        )
        .forEach(
            (
                page
            ) => {

                page.classList.toggle(
                    "active",
                    page.id === pageId
                );

            }
        );
}


/* ============================================================
   TAB CONTROL
   ============================================================ */

function switchTab(
    tabName
) {

    document
        .querySelectorAll(
            ".tab"
        )
        .forEach(
            (
                tab
            ) => {

                tab.classList.toggle(
                    "active",
                    tab.dataset.tab ===
                        tabName
                );

            }
        );


    document
        .querySelectorAll(
            ".tab-content"
        )
        .forEach(
            (
                content
            ) => {

                content.classList.toggle(
                    "active",
                    content.id ===
                        `tab-${tabName}`
                );

            }
        );


    const caseId =
        LDD.currentCase;


    if (!caseId) {
        return;
    }


    loadTabData(
        tabName,
        caseId
    );
}


/* ============================================================
   TAB DATA
   ============================================================ */

function loadTabData(
    tabName,
    caseId
) {

    switch (
        String(
            tabName
        ).toLowerCase()
    ) {

        case "case":

            loadCaseSummary(
                caseId
            );

            break;


        case "evidence":

            if (
                typeof loadEvidence ===
                "function"
            ) {

                loadEvidence(
                    caseId
                );

            }

            break;


        case "timeline":

            if (
                typeof loadTimeline ===
                "function"
            ) {

                loadTimeline(
                    caseId
                );

            }

            break;


        case "findings":

            if (
                typeof loadFindings ===
                "function"
            ) {

                loadFindings(
                    caseId
                );

            }

            break;


        case "attack-board":

            if (
                typeof loadAttackBoard ===
                "function"
            ) {

                loadAttackBoard(
                    caseId
                );

            }

            break;


        case "attack-story":

            if (
                typeof loadAttackStory ===
                "function"
            ) {

                loadAttackStory(
                    caseId
                );

            }

            break;


        case "mitre":

            if (
                typeof loadMitre ===
                "function"
            ) {

                loadMitre(
                    caseId
                );

            }

            break;


        case "report":

            if (
                typeof loadReport ===
                "function"
            ) {

                loadReport(
                    caseId
                );

            }

            break;

    }
}


/* ============================================================
   OPEN CASE
   ============================================================ */

function resetStationRooms() {

    const selectedCase =
        document.getElementById(
            "station-selected-case"
        );

    const boardStatus =
        document.getElementById(
            "board-status"
        );

    const evidence =
        document.getElementById(
            "station-evidence-content"
        );

    const board =
        document.getElementById(
            "board-content"
        );

    if (selectedCase) {
        selectedCase.textContent =
            "NO CASE SELECTED";
    }

    if (boardStatus) {
        boardStatus.textContent =
            "AWAITING CASE";
    }

    if (evidence) {
        evidence.innerHTML = `
            <div class="empty-state">
                <strong>NO CASE SELECTED</strong>
                <br>
                Select a case from Room 01 to inspect
                its evidence.
            </div>
        `;
    }

    if (board) {
        board.innerHTML = `
            <div class="empty-state station-board-empty">
                <strong>NO CASE SELECTED</strong>
                <br>
                Select a case from Room 01 to begin
                the investigation.
            </div>
        `;
    }
}


async function loadStationEvidence(
    caseId
) {

    const container =
        document.getElementById(
            "station-evidence-content"
        );

    if (!container || !caseId) {
        return;
    }

    container.innerHTML =
        '<div class="loading">Loading evidence...</div>';

    try {

        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/evidence`
            );

        const evidence =
            Array.isArray(data)
                ? data
                : Array.isArray(data.evidence)
                    ? data.evidence
                    : [];

        LDD.state.evidence =
            evidence;

        if (!evidence.length) {

            container.innerHTML = `
                <div class="empty-state">
                    <strong>NO EVIDENCE COLLECTED</strong>
                    <br>
                    This case has no registered forensic artifacts.
                </div>
            `;

            return;
        }

        container.innerHTML = `
            <div class="station-evidence-summary">

                <div>
                    <span>ARTIFACTS</span>
                    <strong>${evidence.length}</strong>
                </div>

                <div>
                    <span>CASE</span>
                    <strong>
                        ${LDD.escape(caseId)}
                    </strong>
                </div>

            </div>

            <div class="station-evidence-list">

                ${
                    evidence
                        .map((item) => {

                            const name =
                                item.filename ||
                                item.name ||
                                item.path ||
                                "Unknown artifact";

                            const integrity =
                                item.integrity ||
                                item.status ||
                                "VERIFIED";

                            return `
                                <div class="station-evidence-item">

                                    <div class="station-evidence-icon">
                                        E
                                    </div>

                                    <div class="station-evidence-main">

                                        <strong>
                                            ${LDD.escape(name)}
                                        </strong>

                                        <span>
                                            ${LDD.escape(
                                                String(
                                                    integrity
                                                ).toUpperCase()
                                            )}
                                        </span>

                                    </div>

                                </div>
                            `;
                        })
                        .join("")
                }

            </div>
        `;

    } catch (error) {

        console.error(
            "Linux Digital Detective: station evidence failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                <strong>EVIDENCE UNAVAILABLE</strong>
                <br>
                Unable to load evidence for this case.
            </div>
        `;
    }
}


function updateStationInvestigationBoard() {

    const board =
        document.getElementById(
            "board-content"
        );

    if (!board) {
        return;
    }

    const details =
        LDD.state.caseDetails ||
        {};

    const investigation =
        LDD.state.investigationData ||
        {};

    const findings =
        Array.isArray(
            LDD.state.findings
        )
            ? LDD.state.findings
            : [];

    const chains =
        Array.isArray(
            LDD.state.attackChains
        )
            ? LDD.state.attackChains
            : [];

    const mitre =
        Array.isArray(
            LDD.state.mitre
        )
            ? LDD.state.mitre
            : [];

    const caseId =
        details.case_id ||
        LDD.state.currentCase ||
        "UNKNOWN";

    const title =
        details.title ||
        investigation.title ||
        "Investigation";

    const severity =
        details.severity ||
        investigation.severity ||
        "UNKNOWN";

    const status =
        details.status ||
        investigation.status ||
        "NEW";

    let riskScore =
        LDD.state.riskScore;

    if (
        riskScore &&
        typeof riskScore === "object"
    ) {
        riskScore =
            riskScore.score ||
            riskScore.risk_score ||
            riskScore.value ||
            0;
    }

    if (
        typeof riskScore !== "number"
    ) {
        riskScore =
            Number(riskScore) || 0;
    }

    board.innerHTML = `
        <div class="station-board-header">

            <div>
                <span>ACTIVE INVESTIGATION</span>

                <h3>
                    ${LDD.escape(title)}
                </h3>

                <p>
                    ${LDD.escape(caseId)}
                </p>
            </div>

            <div class="station-board-severity">
                <span>SEVERITY</span>

                <strong>
                    ${LDD.escape(
                        String(severity).toUpperCase()
                    )}
                </strong>
            </div>

        </div>

        <div class="station-board-stats">

            <div class="stat-card">
                <span>RISK SCORE</span>
                <strong>${riskScore}</strong>
            </div>

            <div class="stat-card">
                <span>FINDINGS</span>
                <strong>${findings.length}</strong>
            </div>

            <div class="stat-card">
                <span>ATTACK CHAINS</span>
                <strong>${chains.length}</strong>
            </div>

            <div class="stat-card">
                <span>MITRE</span>
                <strong>${mitre.length}</strong>
            </div>

        </div>

        <div class="station-board-status">

            <span>CASE STATUS</span>

            <strong>
                ${LDD.escape(
                    String(status).toUpperCase()
                )}
            </strong>

        </div>

        <div class="station-board-actions">

            <button
                id="open-full-investigation"
                type="button"
                class="button button-primary"
            >
                OPEN FULL INVESTIGATION
            </button>

        </div>
    `;

    const button =
        document.getElementById(
            "open-full-investigation"
        );

    if (button) {

        button.addEventListener(
            "click",
            async () => {

                showPage(
                    "investigation-page"
                );

                await loadInvestigation(
                    caseId
                );

                switchTab(
                    "case"
                );
            }
        );
    }
}


async function openCase(
    caseId
) {

    if (!caseId) {
        return;
    }

    LDD.currentCase =
        caseId;

    LDD.state.currentCase =
        caseId;

    /*
     * Keep the original Case Cell interaction:
     * clicking a cell opens the complete Investigation Page.
     *
     * The station rooms are populated first so the selected
     * case remains available when returning to the station.
     */

    const selectedCase =
        document.getElementById(
            "station-selected-case"
        );

    if (selectedCase) {
        selectedCase.textContent =
            caseId;
    }

    const boardStatus =
        document.getElementById(
            "board-status"
        );

    if (boardStatus) {
        boardStatus.textContent =
            "CASE SELECTED";
    }

    document.dispatchEvent(
        new CustomEvent(
            "ldd:case-selected",
            {
                detail: {
                    caseId
                }
            }
        )
    );

    await loadInvestigation(
        caseId
    );

    await loadStationEvidence(
        caseId
    );

    updateStationInvestigationBoard();

    /*
     * ORIGINAL BEHAVIOR:
     * Open the complete investigation interface
     * with all existing tabs.
     */

    showPage(
        "investigation-page"
    );

    const caseIdElement =
        document.getElementById(
            "active-case-id"
        );

    if (caseIdElement) {
        caseIdElement.textContent =
            caseId;
    }

    switchTab(
        "case"
    );
}


/* ============================================================
   BACK TO STATION
   ============================================================ */

async function backToStation() {

    /*
     * Preserve the currently selected case.
     * Returning to the station should not forget
     * which case the analyst was investigating.
     */

    const caseId =
        LDD.currentCase ||
        LDD.state.currentCase;

    showPage(
        "station-page"
    );

    if (!caseId) {

        resetStationRooms();

        return;
    }

    LDD.currentCase =
        caseId;

    LDD.state.currentCase =
        caseId;

    const selectedCase =
        document.getElementById(
            "station-selected-case"
        );

    if (selectedCase) {
        selectedCase.textContent =
            caseId;
    }

    const boardStatus =
        document.getElementById(
            "board-status"
        );

    if (boardStatus) {
        boardStatus.textContent =
            "CASE SELECTED";
    }

    /*
     * Reload the selected case so Room 02 and
     * Room 03 always contain current data.
     */

    try {

        await loadInvestigation(
            caseId
        );

        await loadStationEvidence(
            caseId
        );

        updateStationInvestigationBoard();

    } catch (error) {

        console.error(
            "Linux Digital Detective: failed to restore station case.",
            error
        );

    }
}


/* ============================================================
   LOAD COMPLETE INVESTIGATION
   ============================================================ */

async function loadInvestigation(
    caseId
) {

    const caseSummary =
        document.getElementById(
            "case-summary"
        );


    try {

        /*
         * The report endpoint contains the complete
         * investigation result generated by the backend.
         */

        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/report`
            );


        const investigation =
            data || {};


        LDD.state.investigationData =
            investigation;


        /*
         * Normalize investigation components.
         */

        LDD.state.events =
            Array.isArray(
                investigation.events
            )
                ? investigation.events
                : [];


        LDD.state.findings =
            Array.isArray(
                investigation.findings
            )
                ? investigation.findings
                : [];


        LDD.state.attackChains =
            Array.isArray(
                investigation.attack_chains
            )
                ? investigation.attack_chains
                : [];


        LDD.state.mitre =
            Array.isArray(
                investigation.mitre
            )
                ? investigation.mitre
                : [];


        LDD.state.attackStory =
            investigation.attack_story ||
            null;


        LDD.state.riskScore =
            investigation.risk_score ||
            null;


        /*
         * Load case metadata separately.
         */

        try {

            const caseData =
                await LDD.request(
                    `/api/cases/${encodeURIComponent(caseId)}`
                );


            LDD.state.caseDetails =
                caseData || null;

        } catch (caseError) {

            console.warn(
                "Linux Digital Detective: case metadata unavailable.",
                caseError
            );

        }


        /*
         * Render all primary investigation views.
         */

        loadCaseSummary(
            caseId
        );


        /*
         * Populate the dedicated Risk Assessment
         * and Investigation Story cards in the
         * Case tab.
         *
         * These use the same investigation state
         * already loaded above.
         */

        renderCaseRiskSummary();

        renderCaseStoryPreview();


        if (
            typeof renderEvidenceData ===
            "function"
        ) {

            if (
                LDD.state.evidence.length
            ) {

                renderEvidenceData(
                    LDD.state.evidence
                );

            }

        }


        if (
            typeof renderTimeline ===
            "function"
        ) {

            if (
                LDD.state.events.length
            ) {

                renderTimeline(
                    LDD.state.events
                );

            }

        }


        if (
            typeof renderFindings ===
            "function"
        ) {

            renderFindings(
                LDD.state.findings
            );

        }


        if (
            typeof renderAttackBoard ===
            "function"
        ) {

            renderAttackBoard(
                investigation
            );

        }


        if (
            typeof renderAttackStory ===
            "function"
        ) {

            renderAttackStory(
                LDD.state.attackStory ||
                investigation
            );

        }


        if (
            typeof renderMitreView ===
            "function"
        ) {

            renderMitreView(
                LDD.state.mitre
            );

        }


        /*
         * Dispatch after the investigation is ready.
         * Components can safely consume LDD.state.
         */

        document.dispatchEvent(
            new CustomEvent(
                "ldd:investigation-loaded",
                {
                    detail: {
                        caseId,
                        investigation
                    }
                }
            )
        );


        /*
         * Case summary is now authoritative.
         */

        if (caseSummary) {

            caseSummary.dataset.loaded =
                "true";

        }

    } catch (error) {

        console.error(
            "Linux Digital Detective: investigation load failed.",
            error
        );


        if (caseSummary) {

            caseSummary.innerHTML = `
                <div class="empty-state">

                    <strong>
                        Investigation data could not be loaded.
                    </strong>

                    <br>

                    ${LDD.escape(
                        error.message
                    )}

                </div>
            `;

        }

    }
}


/* ============================================================
   CASE SUMMARY
   ============================================================ */

function loadCaseSummary(
    caseId
) {

    const container =
        document.getElementById(
            "case-summary"
        );


    if (!container) {
        return;
    }


    const investigation =
        LDD.state.investigationData ||
        {};


    const caseDetails =
        LDD.state.caseDetails ||
        {};


    const events =
        Array.isArray(
            LDD.state.events
        )
            ? LDD.state.events
            : [];


    const findings =
        Array.isArray(
            LDD.state.findings
        )
            ? LDD.state.findings
            : [];


    const evidence =
        Array.isArray(
            LDD.state.evidence
        )
            ? LDD.state.evidence
            : [];


    const chains =
        Array.isArray(
            LDD.state.attackChains
        )
            ? LDD.state.attackChains
            : [];


    const mitre =
        Array.isArray(
            LDD.state.mitre
        )
            ? LDD.state.mitre
            : [];


    const risk =
        LDD.state.riskScore ||
        investigation.risk_score ||
        {};


    const story =
        LDD.state.attackStory ||
        investigation.attack_story ||
        {};


    const title =
        caseDetails.title ||
        story.title ||
        "Investigation";


    const description =
        caseDetails.description ||
        "Forensic investigation case";


    const status =
        caseDetails.status ||
        "NEW";


    const severity =
        caseDetails.severity ||
        risk.severity ||
        "INFO";


    const confidence =
        Number(
            story.confidence ||
            risk.confidence ||
            0
        );


    const riskScore =
        Number(
            risk.score ||
            0
        );


    const attackPath =
        Array.isArray(
            story.attack_path
        )
            ? story.attack_path
            : [];


    container.innerHTML = `

        <section class="ldd-case-overview">

            <!-- ============================================
                 CASE HEADER
                 ============================================ -->

            <header class="ldd-case-overview-header">

                <div>

                    <span class="eyebrow">
                        CASE INVESTIGATION
                    </span>

                    <h2>
                        ${LDD.escape(
                            title
                        )}
                    </h2>

                    <p>
                        ${LDD.escape(
                            description
                        )}
                    </p>

                </div>


                <div class="ldd-case-overview-status">

                    <span>
                        INCIDENT SEVERITY
                    </span>

                    <strong class="${LDD.severityClass(
                        severity
                    )}">
                        ${LDD.escape(
                            severity
                        )}
                    </strong>

                    <small>
                        ${LDD.escape(
                            status
                        )}
                    </small>

                </div>

            </header>


            <!-- ============================================
                 METRICS
                 ============================================ -->

            <section class="ldd-case-metrics">

                ${renderCaseMetric(
                    "EVENTS",
                    events.length
                )}

                ${renderCaseMetric(
                    "FINDINGS",
                    findings.length
                )}

                ${renderCaseMetric(
                    "EVIDENCE",
                    evidence.length
                )}

                ${renderCaseMetric(
                    "MITRE",
                    mitre.length
                )}

                ${renderCaseMetric(
                    "CHAINS",
                    chains.length
                )}

            </section>


            <!-- ============================================
                 RISK
                 ============================================ -->

            <section class="ldd-case-risk">

                <div class="ldd-case-section-heading">

                    <span>
                        01
                    </span>

                    <div>

                        <strong>
                            RISK ASSESSMENT
                        </strong>

                        <p>
                            Composite assessment generated
                            from detection findings and
                            correlated attack activity.
                        </p>

                    </div>

                </div>


                <div class="ldd-case-risk-grid">

                    <div class="ldd-case-risk-score">

                        <span>
                            RISK SCORE
                        </span>

                        <strong>
                            ${riskScore}
                            <small>/100</small>
                        </strong>

                        <em class="${LDD.severityClass(
                            severity
                        )}">
                            ${LDD.escape(
                                risk.severity ||
                                severity
                            )}
                        </em>

                    </div>


                    <div class="ldd-case-risk-confidence">

                        <span>
                            INVESTIGATION CONFIDENCE
                        </span>

                        <strong>
                            ${confidence}%
                        </strong>

                        <div
                            class="ldd-case-confidence-bar"
                        >

                            <div
                                style="width:${Math.min(
                                    100,
                                    Math.max(
                                        0,
                                        confidence
                                    )
                                )}%"
                            ></div>

                        </div>

                    </div>

                </div>

            </section>


            <!-- ============================================
                 ATTACK PATH
                 ============================================ -->

            <section class="ldd-case-path">

                <div class="ldd-case-section-heading">

                    <span>
                        02
                    </span>

                    <div>

                        <strong>
                            RECONSTRUCTED ATTACK PATH
                        </strong>

                        <p>
                            Primary sequence identified
                            during investigation correlation.
                        </p>

                    </div>

                </div>


                ${
                    attackPath.length
                        ? `
                            <div class="ldd-case-path-track">

                                ${attackPath
                                    .map(
                                        (
                                            stage,
                                            index
                                        ) => `

                                            <div class="ldd-case-path-node">

                                                <span>
                                                    ${String(
                                                        index + 1
                                                    ).padStart(
                                                        2,
                                                        "0"
                                                    )}
                                                </span>

                                                <strong>
                                                    ${LDD.escape(
                                                        formatCaseStage(
                                                            stage
                                                        )
                                                    )}
                                                </strong>

                                            </div>

                                            ${
                                                index <
                                                attackPath.length - 1
                                                    ? `
                                                        <div class="ldd-case-path-arrow">
                                                            →
                                                        </div>
                                                    `
                                                    : ""
                                            }

                                        `
                                    )
                                    .join("")}

                            </div>
                        `
                        : `
                            <div class="empty-state">
                                No reconstructed attack path available.
                            </div>
                        `
                }

            </section>


            <!-- ============================================
                 INVESTIGATOR ASSESSMENT
                 ============================================ -->

            <section class="ldd-case-assessment">

                <div class="ldd-case-section-heading">

                    <span>
                        03
                    </span>

                    <div>

                        <strong>
                            INVESTIGATOR ASSESSMENT
                        </strong>

                        <p>
                            Current conclusion from the
                            available forensic evidence.
                        </p>

                    </div>

                </div>


                <div class="ldd-case-assessment-box">

                    <p>
                        ${LDD.escape(
                            story.conclusion ||
                            "The investigation has not generated a final conclusion."
                        )}
                    </p>

                </div>

            </section>


            <!-- ============================================
                 CASE INFORMATION
                 ============================================ -->

            <section class="ldd-case-information">

                <div class="ldd-case-section-heading">

                    <span>
                        04
                    </span>

                    <div>

                        <strong>
                            CASE INFORMATION
                        </strong>

                    </div>

                </div>


                <div class="ldd-case-information-grid">

                    ${renderCaseInformation(
                        "CASE ID",
                        caseId
                    )}

                    ${renderCaseInformation(
                        "STATUS",
                        status
                    )}

                    ${renderCaseInformation(
                        "SEVERITY",
                        severity
                    )}

                    ${renderCaseInformation(
                        "INVESTIGATOR",
                        caseDetails.investigator ||
                        "Linux Digital Detective"
                    )}

                    ${renderCaseInformation(
                        "CREATED",
                        caseDetails.created_at
                            ? LDD.formatDate(
                                  caseDetails.created_at
                              )
                            : "-"
                    )}

                    ${renderCaseInformation(
                        "UPDATED",
                        caseDetails.updated_at
                            ? LDD.formatDate(
                                  caseDetails.updated_at
                              )
                            : "-"
                    )}

                </div>

            </section>

        </section>
    `;
}


/* ============================================================
   CASE RISK SUMMARY + INVESTIGATION STORY PREVIEW
   ============================================================ */

function renderCaseRiskSummary() {

    const container =
        document.getElementById(
            "risk-summary"
        );

    if (!container) {
        return;
    }

    const investigation =
        LDD.state.investigationData ||
        {};

    const risk =
        LDD.state.riskScore ||
        investigation.risk_score ||
        {};

    const findings =
        Array.isArray(
            LDD.state.findings
        )
            ? LDD.state.findings
            : [];

    const chains =
        Array.isArray(
            LDD.state.attackChains
        )
            ? LDD.state.attackChains
            : [];

    const mitre =
        Array.isArray(
            LDD.state.mitre
        )
            ? LDD.state.mitre
            : [];

    const score =
        Number(
            risk.score ??
            risk.risk_score ??
            0
        );

    const severity =
        risk.severity ||
        LDD.state.caseDetails?.severity ||
        "INFO";

    const confidence =
        Number(
            risk.confidence ??
            LDD.state.attackStory?.confidence ??
            0
        );

    console.log(
        "LDD DEBUG: rendering risk-summary",
        {
            score,
            severity,
            confidence,
            findings: findings.length,
            chains: chains.length,
            mitre: mitre.length
        }
    );

    container.innerHTML = `

        <section class="ldd-case-risk">

            <div class="ldd-case-section-heading">

                <span>
                    01
                </span>

                <div>

                    <strong>
                        RISK ASSESSMENT
                    </strong>

                    <p>
                        Composite assessment generated
                        from detection findings and
                        correlated attack activity.
                    </p>

                </div>

            </div>


            <div class="ldd-case-risk-grid">

                <div class="ldd-case-risk-score">

                    <span>
                        RISK SCORE
                    </span>

                    <strong>
                        ${LDD.escape(
                            score
                        )}
                        <small>/100</small>
                    </strong>

                    <em class="${LDD.severityClass(
                        severity
                    )}">
                        ${LDD.escape(
                            severity
                        )}
                    </em>

                </div>


                <div class="ldd-case-risk-confidence">

                    <span>
                        INVESTIGATION CONFIDENCE
                    </span>

                    <strong>
                        ${
                            confidence > 0
                                ? `${LDD.escape(
                                      confidence
                                  )}%`
                                : "N/A"
                        }
                    </strong>

                </div>

            </div>


            <div class="ldd-case-metrics">

                ${renderCaseMetric(
                    "FINDINGS",
                    findings.length
                )}

                ${renderCaseMetric(
                    "ATTACK CHAINS",
                    chains.length
                )}

                ${renderCaseMetric(
                    "MITRE TECHNIQUES",
                    mitre.length
                )}

            </div>

        </section>

    `;
}


function renderCaseStoryPreview() {

    const container =
        document.getElementById(
            "case-story-preview"
        );

    if (!container) {
        return;
    }

    const investigation =
        LDD.state.investigationData ||
        {};

    const story =
        LDD.state.attackStory ||
        investigation.attack_story ||
        {};

    const risk =
        LDD.state.riskScore ||
        investigation.risk_score ||
        {};

    const findings =
        Array.isArray(
            LDD.state.findings
        )
            ? LDD.state.findings
            : [];

    const riskScore =
        Number(
            risk.score ??
            risk.risk_score ??
            0
        );

    const riskSeverity =
        risk.severity ||
        LDD.state.caseDetails?.severity ||
        "INFO";

    const title =
        story.title ||
        "Investigation Story";

    const conclusion =
        story.conclusion ||
        (
            findings.length
                ? `The investigation identified ${findings.length} detection finding(s). ` +
                  `The resulting risk assessment is ${riskScore}/100 (${riskSeverity}). ` +
                  `The available evidence should be reviewed alongside the correlated attack chains ` +
                  `before final incident disposition.`
                : "No confirmed detection findings were generated from the available evidence."
        );

    console.log(
        "LDD DEBUG: rendering case-story-preview",
        {
            title,
            conclusion,
            findings: findings.length,
            riskScore,
            riskSeverity
        }
    );

    container.innerHTML = `

        <section class="ldd-case-assessment">

            <div class="ldd-case-section-heading">

                <span>
                    02
                </span>

                <div>

                    <strong>
                        INVESTIGATION STORY
                    </strong>

                    <p>
                        Correlated narrative generated
                        from the forensic investigation.
                    </p>

                </div>

            </div>


            <div class="ldd-case-assessment-box">

                <strong>
                    ${LDD.escape(
                        title
                    )}
                </strong>

                <p>
                    ${LDD.escape(
                        conclusion
                    )}
                </p>

            </div>

        </section>

    `;
}


/* ============================================================
   CASE METRIC
   ============================================================ */

function renderCaseMetric(
    label,
    value
) {

    return `

        <div class="ldd-case-metric">

            <span>
                ${LDD.escape(
                    label
                )}
            </span>

            <strong>
                ${LDD.escape(
                    value
                )}
            </strong>

        </div>

    `;
}


/* ============================================================
   CASE INFORMATION
   ============================================================ */

function renderCaseInformation(
    label,
    value
) {

    return `

        <div class="ldd-case-information-item">

            <span>
                ${LDD.escape(
                    label
                )}
            </span>

            <strong>
                ${LDD.escape(
                    value
                )}
            </strong>

        </div>

    `;
}


/* ============================================================
   ATTACK STAGE FORMATTER
   ============================================================ */

function formatCaseStage(
    stage
) {

    return String(
        stage ||
        "UNKNOWN"
    )
        .replaceAll(
            "_",
            " "
        )
        .replace(
            /\b\w/g,
            (
                character
            ) =>
                character.toUpperCase()
        );
}


/* ============================================================
   INITIALIZATION
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        /*
         * Tab buttons.
         */

        document
            .querySelectorAll(
                ".tab"
            )
            .forEach(
                (
                    tab
                ) => {

                    tab.addEventListener(
                        "click",
                        () => {

                            const name =
                                tab.dataset.tab;

                            if (name) {

                                switchTab(
                                    name
                                );

                            }

                        }
                    );

                }
            );


        /*
         * Back button.
         */

        const backButton =
            document.getElementById(
                "back-to-station"
            );


        if (backButton) {

            backButton.addEventListener(
                "click",
                backToStation
            );

        }


        /*
         * Detective controls.
         */

        const detectiveButton =
            document.getElementById(
                "detective-inspect"
            );


        if (
            detectiveButton
        ) {

            detectiveButton.addEventListener(
                "click",
                () => {

                    if (
                        LDD.currentCase
                    ) {

                        openCase(
                            LDD.currentCase
                        );

                    } else {

                        const detectiveMessage =
                            document.getElementById(
                                "detective-message"
                            );

                        if (detectiveMessage) {

                            detectiveMessage.textContent =
                                "Select a case from Room 01 to begin the investigation.";

                        }

                    }

                }
            );

        }


        /*
         * Run investigation button.
         */

        const runButton =
            document.getElementById(
                "run-investigation"
            );


        if (runButton) {

            runButton.addEventListener(
                "click",
                async () => {

                    if (
                        !LDD.currentCase
                    ) {
                        return;
                    }


                    runButton.disabled =
                        true;


                    runButton.textContent =
                        "Loading...";


                    try {

                        await loadInvestigation(
                            LDD.currentCase
                        );


                    } finally {

                        runButton.disabled =
                            false;

                        runButton.textContent =
                            "Run Investigation";

                    }

                }
            );

        }

    }
);


/* ============================================================
   PUBLIC API
   ============================================================ */

LDD.openCase =
    openCase;

LDD.backToStation =
    backToStation;

window.openCase =
    openCase;

window.switchTab =
    switchTab;

window.loadInvestigation =
    loadInvestigation;

window.loadCaseSummary =
    loadCaseSummary;
