/*
 * Linux Digital Detective
 * Findings & Detection Center
 *
 * Investigator-focused renderer for detection findings.
 *
 * All CSS classes use the ldd-findings-* namespace
 * to prevent collisions with the rest of the dashboard.
 */


async function loadFindings(caseId) {
    const container =
        document.getElementById(
            "findings-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            Running detection findings review...
        </div>
    `;

    try {
        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/findings`
            );

        const findings =
            Array.isArray(data)
                ? data
                : Array.isArray(data.findings)
                    ? data.findings
                    : [];

        LDD.state.findings =
            findings;

        renderFindingsData(
            findings
        );

    } catch (error) {
        console.error(
            "Linux Digital Detective: findings request failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                <strong>Detection center unavailable.</strong>
                <br>
                Findings could not be loaded for this investigation.
            </div>
        `;
    }
}


/*
 * Render findings without making another API request.
 */
function renderFindingsData(
    findings = []
) {
    const container =
        document.getElementById(
            "findings-content"
        );

    if (!container) {
        return;
    }

    if (
        !Array.isArray(findings) ||
        findings.length === 0
    ) {
        container.innerHTML = `
            <div class="empty-state">
                <strong>No detections identified.</strong>
                <br>
                The current evidence did not produce any findings.
            </div>
        `;

        return;
    }

    const counts =
        calculateFindingCounts(
            findings
        );

    const highestSeverity =
        getHighestSeverity(
            findings
        );

    container.innerHTML = `
        <section class="ldd-findings-center">

            <header class="ldd-findings-header">

                <div class="ldd-findings-heading">

                    <span class="eyebrow">
                        DETECTION CENTER
                    </span>

                    <h2>
                        Investigation Findings
                    </h2>

                    <p>
                        Detection engines identified
                        ${findings.length}
                        finding(s) requiring investigator review.
                    </p>

                </div>

                <div class="ldd-findings-overview">

                    <div class="ldd-findings-stat">

                        <span>
                            FINDINGS
                        </span>

                        <strong>
                            ${findings.length}
                        </strong>

                    </div>

                    <div class="ldd-findings-stat">

                        <span>
                            CRITICAL
                        </span>

                        <strong>
                            ${counts.CRITICAL}
                        </strong>

                    </div>

                    <div class="ldd-findings-stat">

                        <span>
                            HIGH
                        </span>

                        <strong>
                            ${counts.HIGH}
                        </strong>

                    </div>

                    <div class="ldd-findings-stat">

                        <span>
                            HIGHEST
                        </span>

                        <strong
                            class="${LDD.severityClass(
                                highestSeverity
                            )}"
                        >
                            ${LDD.escape(
                                highestSeverity
                            )}
                        </strong>

                    </div>

                </div>

            </header>

            <div class="ldd-findings-list">

                ${findings
                    .map(
                        (
                            finding,
                            index
                        ) =>
                            renderFindingCard(
                                finding,
                                index
                            )
                    )
                    .join("")}

            </div>

        </section>
    `;

    bindFindingInteractions();
}


/*
 * Calculate severity counts.
 */
function calculateFindingCounts(
    findings
) {
    const counts = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
    };

    findings.forEach(
        (finding) => {
            const severity =
                String(
                    finding.severity ||
                    "INFO"
                ).toUpperCase();

            if (
                Object.prototype.hasOwnProperty.call(
                    counts,
                    severity
                )
            ) {
                counts[severity] += 1;
            }
        }
    );

    return counts;
}


/*
 * Determine highest finding severity.
 */
function getHighestSeverity(
    findings
) {
    const ranking = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1
    };

    let highest =
        "INFO";

    findings.forEach(
        (finding) => {
            const severity =
                String(
                    finding.severity ||
                    "INFO"
                ).toUpperCase();

            if (
                (ranking[severity] || 0) >
                (ranking[highest] || 0)
            ) {
                highest =
                    severity;
            }
        }
    );

    return highest;
}


/*
 * Render a complete finding card.
 */
function renderFindingCard(
    finding,
    index
) {
    const findingId =
        finding.finding_id ||
        finding.id ||
        `FINDING-${String(
            index + 1
        ).padStart(4, "0")}`;

    const severity =
        String(
            finding.severity ||
            "INFO"
        ).toUpperCase();

    const type =
        finding.finding_type ||
        finding.type ||
        finding.category ||
        finding.detection_type ||
        "DETECTION";

    const title =
        finding.title ||
        finding.name ||
        formatFindingTitle(
            type
        );

    const description =
        finding.description ||
        finding.reason ||
        finding.message ||
        "Detection engine identified suspicious activity.";

    const timestamp =
        finding.timestamp ||
        finding.detected_at ||
        finding.created_at ||
        null;

    const sourceIp =
        finding.source_ip ||
        finding.src_ip ||
        finding.source ||
        "-";

    const username =
        finding.username ||
        finding.user ||
        finding.account ||
        "-";

    const eventIds =
        normalizeArray(
            finding.event_ids ||
            finding.related_event_ids ||
            finding.events
        );

    const indicators =
        normalizeArray(
            finding.indicators ||
            finding.indicator ||
            finding.iocs
        );

    const chainIds =
        normalizeArray(
            finding.chain_ids ||
            finding.attack_chain_ids ||
            finding.chains
        );

    const technique =
        finding.mitre_id ||
        finding.technique_id ||
        finding.mitre_technique ||
        "";

    return `
        <article
            class="ldd-findings-card ${LDD.severityClass(
                severity
            )}"
            data-finding-index="${index}"
        >

            <div class="ldd-findings-card-top">

                <div class="ldd-findings-severity-marker">
                    <span></span>
                </div>

                <div class="ldd-findings-card-title">

                    <div class="ldd-findings-type">
                        ${LDD.escape(
                            type
                        )}
                    </div>

                    <h3>
                        ${LDD.escape(
                            title
                        )}
                    </h3>

                    <div class="ldd-findings-id">
                        ${LDD.escape(
                            findingId
                        )}
                    </div>

                </div>

                <span
                    class="badge ${LDD.severityClass(
                        severity
                    )}"
                >
                    ${LDD.escape(
                        severity
                    )}
                </span>

            </div>

            <div class="ldd-findings-description">

                ${LDD.escape(
                    description
                )}

            </div>

            <div class="ldd-findings-meta">

                <div class="ldd-findings-meta-item">

                    <span>
                        USER
                    </span>

                    <strong>
                        ${LDD.escape(
                            username
                        )}
                    </strong>

                </div>

                <div class="ldd-findings-meta-item">

                    <span>
                        SOURCE
                    </span>

                    <strong>
                        ${LDD.escape(
                            sourceIp
                        )}
                    </strong>

                </div>

                <div class="ldd-findings-meta-item">

                    <span>
                        EVENTS
                    </span>

                    <strong>
                        ${eventIds.length}
                    </strong>

                </div>

                <div class="ldd-findings-meta-item">

                    <span>
                        INDICATORS
                    </span>

                    <strong>
                        ${indicators.length}
                    </strong>

                </div>

            </div>

            <div class="ldd-findings-tags">

                ${
                    timestamp
                        ? `
                            <span>
                                DETECTED
                                ${LDD.escape(
                                    LDD.formatDate(
                                        timestamp
                                    )
                                )}
                            </span>
                        `
                        : ""
                }

                ${
                    technique
                        ? `
                            <span>
                                MITRE
                                ${LDD.escape(
                                    technique
                                )}
                            </span>
                        `
                        : ""
                }

                ${
                    chainIds.length
                        ? `
                            <span>
                                ${chainIds.length}
                                ATTACK CHAIN
                                ${
                                    chainIds.length === 1
                                        ? ""
                                        : "S"
                                }
                            </span>
                        `
                        : ""
                }

            </div>

            <button
                type="button"
                class="ldd-findings-details-button"
                data-finding-details="${index}"
                aria-expanded="false"
            >
                Show forensic evidence
            </button>

            <div
                class="ldd-findings-details"
                data-finding-panel="${index}"
                hidden
            >

                ${renderFindingEvidence(
                    finding,
                    eventIds,
                    indicators,
                    chainIds
                )}

            </div>

        </article>
    `;
}


/*
 * Render evidence connected to a finding.
 */
function renderFindingEvidence(
    finding,
    eventIds,
    indicators,
    chainIds
) {
    const sections = [];

    if (eventIds.length) {
        sections.push(`
            <div class="ldd-findings-detail-section">

                <h4>
                    RELATED EVENTS
                </h4>

                <div class="ldd-findings-chip-list">

                    ${eventIds
                        .map(
                            (id) => `
                                <span class="ldd-findings-chip">
                                    ${LDD.escape(
                                        String(id)
                                    )}
                                </span>
                            `
                        )
                        .join("")}

                </div>

            </div>
        `);
    }

    if (indicators.length) {
        sections.push(`
            <div class="ldd-findings-detail-section">

                <h4>
                    INDICATORS
                </h4>

                <div class="ldd-findings-indicators">

                    ${indicators
                        .map(
                            (indicator) => `
                                <code>
                                    ${LDD.escape(
                                        formatFindingValue(
                                            indicator
                                        )
                                    )}
                                </code>
                            `
                        )
                        .join("")}

                </div>

            </div>
        `);
    }

    if (chainIds.length) {
        sections.push(`
            <div class="ldd-findings-detail-section">

                <h4>
                    ATTACK CHAINS
                </h4>

                <div class="ldd-findings-chip-list">

                    ${chainIds
                        .map(
                            (id) => `
                                <span class="ldd-findings-chip">
                                    ${LDD.escape(
                                        String(id)
                                    )}
                                </span>
                            `
                        )
                        .join("")}

                </div>

            </div>
        `);
    }

    const metadata =
        extractFindingMetadata(
            finding
        );

    if (
        Object.keys(metadata).length
    ) {
        sections.push(`
            <div class="ldd-findings-detail-section">

                <h4>
                    DETECTION METADATA
                </h4>

                <div class="ldd-findings-metadata">

                    ${Object.entries(
                        metadata
                    )
                        .map(
                            ([key, value]) => `
                                <div class="ldd-findings-metadata-row">

                                    <span>
                                        ${LDD.escape(
                                            key
                                        )}
                                    </span>

                                    <strong>
                                        ${LDD.escape(
                                            formatFindingValue(
                                                value
                                            )
                                        )}
                                    </strong>

                                </div>
                            `
                        )
                        .join("")}

                </div>

            </div>
        `);
    }

    if (!sections.length) {
        return `
            <div class="ldd-findings-no-evidence">
                No additional forensic metadata was attached
                to this finding.
            </div>
        `;
    }

    return sections.join("");
}


/*
 * Extract useful metadata while avoiding duplication.
 */
function extractFindingMetadata(
    finding
) {
    const excluded =
        new Set([
            "finding_id",
            "id",
            "severity",
            "finding_type",
            "type",
            "category",
            "detection_type",
            "title",
            "name",
            "description",
            "reason",
            "message",
            "timestamp",
            "detected_at",
            "created_at",
            "source_ip",
            "src_ip",
            "source",
            "username",
            "user",
            "account",
            "event_ids",
            "related_event_ids",
            "events",
            "indicators",
            "indicator",
            "iocs",
            "chain_ids",
            "attack_chain_ids",
            "chains",
            "mitre_id",
            "technique_id",
            "mitre_technique"
        ]);

    return Object.fromEntries(
        Object.entries(
            finding || {}
        ).filter(
            ([key, value]) =>
                !excluded.has(key) &&
                value !== null &&
                value !== undefined &&
                value !== ""
        )
    );
}


/*
 * Convert finding title from detection type.
 */
function formatFindingTitle(
    type
) {
    const text =
        String(
            type || "Detection"
        )
            .replaceAll(
                "_",
                " "
            )
            .replaceAll(
                "-",
                " "
            );

    return text
        .toLowerCase()
        .replace(
            /\b\w/g,
            (character) =>
                character.toUpperCase()
        );
}


/*
 * Normalize values into arrays.
 */
function normalizeArray(
    value
) {
    if (
        value === null ||
        value === undefined
    ) {
        return [];
    }

    if (
        Array.isArray(value)
    ) {
        return value;
    }

    return [
        value
    ];
}


/*
 * Format arbitrary finding values.
 */
function formatFindingValue(
    value
) {
    if (
        value === null ||
        value === undefined
    ) {
        return "-";
    }

    if (
        typeof value === "object"
    ) {
        try {
            return JSON.stringify(
                value
            );
        } catch {
            return String(
                value
            );
        }
    }

    return String(
        value
    );
}


/*
 * Bind expandable forensic evidence.
 */
function bindFindingInteractions() {
    document
        .querySelectorAll(
            "[data-finding-details]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const index =
                            button.dataset
                                .findingDetails;

                        const panel =
                            document.querySelector(
                                `[data-finding-panel="${index}"]`
                            );

                        if (!panel) {
                            return;
                        }

                        const expanded =
                            button.getAttribute(
                                "aria-expanded"
                            ) === "true";

                        button.setAttribute(
                            "aria-expanded",
                            String(
                                !expanded
                            )
                        );

                        panel.hidden =
                            expanded;

                        button.textContent =
                            expanded
                                ? "Show forensic evidence"
                                : "Hide forensic evidence";
                    }
                );
            }
        );
}


/*
 * Reload findings when a case is selected.
 */
document.addEventListener(
    "ldd:case-selected",
    (event) => {

        const caseId =
            event.detail?.caseId;

        if (!caseId) {
            return;
        }

        /*
         * app.js may already have loaded the findings.
         * If it has not, load them directly.
         */
        if (
            !Array.isArray(
                LDD.state.findings
            ) ||
            LDD.state.findings.length === 0
        ) {
            loadFindings(
                caseId
            );
        }

    }
);
