/*
 * Linux Digital Detective
 * MITRE ATT&CK Investigation View
 *
 * Renders ATT&CK mappings from the investigation data.
 *
 * Theme-safe:
 * all MITRE-specific classes use the
 * ldd-mitre-* namespace.
 */


async function loadMitre(caseId) {

    const container =
        document.getElementById(
            "mitre-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            Loading MITRE ATT&amp;CK mappings...
        </div>
    `;


    try {

        /*
         * Prefer the investigation object already
         * loaded by app.js.
         */

        const investigation =
            LDD.state.investigationData ||
            null;


        if (investigation) {

            const techniques =
                extractMitreTechniques(
                    investigation
                );

            LDD.state.mitre =
                techniques;

            renderMitreView(
                techniques
            );

            return;
        }


        /*
         * Fallback to the dedicated API endpoint.
         */

        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/mitre`
            );


        const techniques =
            Array.isArray(data)
                ? data
                : Array.isArray(data.mitre)
                    ? data.mitre
                    : Array.isArray(data.techniques)
                        ? data.techniques
                        : [];


        LDD.state.mitre =
            techniques;


        renderMitreView(
            techniques
        );

    } catch (error) {

        console.error(
            "Linux Digital Detective: MITRE request failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">

                <strong>
                    MITRE ATT&amp;CK data unavailable.
                </strong>

                <br>

                The technique mappings could not be loaded.

            </div>
        `;
    }
}


/* ============================================================
   EXTRACT MITRE DATA
   ============================================================ */

function extractMitreTechniques(
    investigation
) {

    if (
        Array.isArray(
            investigation.mitre
        )
    ) {
        return investigation.mitre;
    }


    if (
        Array.isArray(
            investigation.mitre_techniques
        )
    ) {
        return investigation.mitre_techniques;
    }


    if (
        investigation.attack_story &&
        Array.isArray(
            investigation
                .attack_story
                .mitre_techniques
        )
    ) {
        return investigation
            .attack_story
            .mitre_techniques;
    }


    if (
        investigation.story &&
        Array.isArray(
            investigation
                .story
                .mitre_techniques
        )
    ) {
        return investigation
            .story
            .mitre_techniques;
    }


    return [];
}


/* ============================================================
   MAIN VIEW
   ============================================================ */

function renderMitreView(
    techniques = []
) {

    const container =
        document.getElementById(
            "mitre-content"
        );

    if (!container) {
        return;
    }


    const uniqueTechniques =
        deduplicateMitre(
            techniques
        );


    if (
        !uniqueTechniques.length
    ) {

        container.innerHTML = `
            <div class="empty-state">

                <strong>
                    No MITRE ATT&amp;CK techniques detected.
                </strong>

                <br>

                No technique mappings were generated
                from the available findings.

            </div>
        `;

        return;
    }


    const tactics =
        getMitreTactics(
            uniqueTechniques
        );


    const coverage =
        calculateMitreCoverage(
            uniqueTechniques
        );


    container.innerHTML = `

        <section class="ldd-mitre">

            <!-- ============================================
                 HEADER
                 ============================================ -->

            <header class="ldd-mitre-header">

                <div>

                    <span class="eyebrow">
                        MITRE ATT&amp;CK
                    </span>

                    <h2>
                        Adversary Technique Mapping
                    </h2>

                    <p>
                        Detection findings mapped to
                        ATT&amp;CK techniques observed
                        during the investigation.
                    </p>

                </div>


                <div class="ldd-mitre-status">

                    <span>
                        TECHNIQUES DETECTED
                    </span>

                    <strong>
                        ${uniqueTechniques.length}
                    </strong>

                </div>

            </header>


            <!-- ============================================
                 COVERAGE
                 ============================================ -->

            <section class="ldd-mitre-overview">

                <div class="ldd-mitre-overview-card">

                    <span>
                        TECHNIQUES
                    </span>

                    <strong>
                        ${uniqueTechniques.length}
                    </strong>

                </div>


                <div class="ldd-mitre-overview-card">

                    <span>
                        TACTICS
                    </span>

                    <strong>
                        ${tactics.length}
                    </strong>

                </div>


                <div class="ldd-mitre-overview-card">

                    <span>
                        COVERAGE
                    </span>

                    <strong>
                        ${coverage}%
                    </strong>

                </div>

            </section>


            <!-- ============================================
                 TACTIC SUMMARY
                 ============================================ -->

            <section class="ldd-mitre-tactics">

                <div class="ldd-mitre-section-heading">

                    <span>
                        01
                    </span>

                    <div>

                        <strong>
                            ATTACK TACTICS
                        </strong>

                        <p>
                            Tactics represented by the
                            detected techniques.
                        </p>

                    </div>

                </div>


                <div class="ldd-mitre-tactic-list">

                    ${
                        tactics
                            .map(
                                (
                                    tactic
                                ) => `
                                    <span class="ldd-mitre-tactic">
                                        ${LDD.escape(
                                            tactic
                                        )}
                                    </span>
                                `
                            )
                            .join("")
                    }

                </div>

            </section>


            <!-- ============================================
                 TECHNIQUE CARDS
                 ============================================ -->

            <section class="ldd-mitre-techniques">

                <div class="ldd-mitre-section-heading">

                    <span>
                        02
                    </span>

                    <div>

                        <strong>
                            DETECTED TECHNIQUES
                        </strong>

                        <p>
                            ATT&amp;CK mappings generated from
                            forensic detection findings.
                        </p>

                    </div>

                </div>


                <div class="ldd-mitre-list">

                    ${uniqueTechniques
                        .map(
                            (
                                technique,
                                index
                            ) =>
                                renderMitreTechnique(
                                    technique,
                                    index
                                )
                        )
                        .join("")}

                </div>

            </section>


            <!-- ============================================
                 INVESTIGATOR NOTE
                 ============================================ -->

            <section class="ldd-mitre-note">

                <div class="ldd-mitre-section-heading">

                    <span>
                        03
                    </span>

                    <div>

                        <strong>
                            INVESTIGATOR NOTE
                        </strong>

                    </div>

                </div>


                <p>
                    ATT&amp;CK mappings describe the
                    adversary behavior represented by
                    the detected evidence. They should
                    be interpreted together with the
                    underlying events, findings, and
                    attack chains.
                </p>

            </section>

        </section>
    `;
}


/* ============================================================
   TECHNIQUE CARD
   ============================================================ */

function renderMitreTechnique(
    technique,
    index
) {

    const id =
        technique.technique_id ||
        technique.mitre_id ||
        technique.id ||
        "-";


    const name =
        technique.name ||
        technique.technique_name ||
        technique.technique ||
        "Unknown Technique";


    const description =
        technique.description ||
        technique.reason ||
        technique.details ||
        "Technique mapped from investigation evidence.";


    const tactic =
        technique.tactic ||
        technique.tactics ||
        technique.stage ||
        "Investigation";


    const findingIds =
        normalizeArray(
            technique.finding_ids ||
            technique.findings
        );


    const eventIds =
        normalizeArray(
            technique.event_ids ||
            technique.events
        );


    const severity =
        String(
            technique.severity ||
            "INFO"
        ).toUpperCase();


    return `

        <article
            class="ldd-mitre-card"
            data-mitre-index="${index}"
        >

            <div class="ldd-mitre-card-top">

                <div class="ldd-mitre-technique-id">

                    <span>
                        TECHNIQUE
                    </span>

                    <strong>
                        ${LDD.escape(
                            id
                        )}
                    </strong>

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


            <div class="ldd-mitre-card-body">

                <span class="ldd-mitre-tactic-label">
                    ${LDD.escape(
                        formatMitreTactic(
                            tactic
                        )
                    )}
                </span>


                <h3>
                    ${LDD.escape(
                        name
                    )}
                </h3>


                <p>
                    ${LDD.escape(
                        description
                    )}
                </p>

            </div>


            <button
                type="button"
                class="ldd-mitre-details-button"
                data-mitre-details="${index}"
                aria-expanded="false"
            >
                Show evidence mapping
            </button>


            <div
                class="ldd-mitre-details"
                data-mitre-panel="${index}"
                hidden
            >

                ${
                    findingIds.length
                        ? `
                            <div class="ldd-mitre-evidence-block">

                                <span>
                                    FINDINGS
                                </span>

                                <div>

                                    ${findingIds
                                        .map(
                                            (
                                                findingId
                                            ) => `
                                                <code>
                                                    ${LDD.escape(
                                                        findingId
                                                    )}
                                                </code>
                                            `
                                        )
                                        .join("")}

                                </div>

                            </div>
                        `
                        : ""
                }


                ${
                    eventIds.length
                        ? `
                            <div class="ldd-mitre-evidence-block">

                                <span>
                                    EVENTS
                                </span>

                                <div>

                                    ${eventIds
                                        .map(
                                            (
                                                eventId
                                            ) => `
                                                <code>
                                                    ${LDD.escape(
                                                        eventId
                                                    )}
                                                </code>
                                            `
                                        )
                                        .join("")}

                                </div>

                            </div>
                        `
                        : ""
                }


                ${
                    !findingIds.length &&
                    !eventIds.length
                        ? `
                            <p class="ldd-mitre-no-evidence">
                                The mapping does not contain
                                explicit finding or event identifiers.
                            </p>
                        `
                        : ""
                }

            </div>

        </article>

    `;
}


/* ============================================================
   INTERACTIONS
   ============================================================ */

function bindMitreInteractions() {

    document
        .querySelectorAll(
            "[data-mitre-details]"
        )
        .forEach(
            (
                button
            ) => {

                button.addEventListener(
                    "click",
                    () => {

                        const index =
                            button.dataset
                                .mitreDetails;


                        const panel =
                            document.querySelector(
                                `[data-mitre-panel="${index}"]`
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
                                ? "Show evidence mapping"
                                : "Hide evidence mapping";

                    }
                );

            }
        );
}


/* ============================================================
   NORMALIZATION
   ============================================================ */

function normalizeArray(
    value
) {

    if (
        Array.isArray(
            value
        )
    ) {
        return value;
    }


    if (
        value === null ||
        value === undefined
    ) {
        return [];
    }


    return [
        value
    ];
}


function deduplicateMitre(
    techniques
) {

    const seen =
        new Set();


    const result =
        [];


    techniques.forEach(
        (
            technique
        ) => {

            if (
                !technique ||
                typeof technique !==
                    "object"
            ) {
                return;
            }


            const id =
                String(
                    technique.technique_id ||
                    technique.mitre_id ||
                    technique.id ||
                    technique.name ||
                    ""
                )
                    .trim()
                    .toUpperCase();


            if (!id) {
                return;
            }


            if (
                seen.has(
                    id
                )
            ) {
                return;
            }


            seen.add(
                id
            );


            result.push(
                technique
            );

        }
    );


    return result;
}


/* ============================================================
   TACTICS
   ============================================================ */

function getMitreTactics(
    techniques
) {

    const values =
        new Set();


    techniques.forEach(
        (
            technique
        ) => {

            const tactic =
                technique.tactic ||
                technique.tactics ||
                technique.stage;


            if (
                Array.isArray(
                    tactic
                )
            ) {

                tactic.forEach(
                    (
                        item
                    ) => {

                        if (item) {
                            values.add(
                                formatMitreTactic(
                                    item
                                )
                            );
                        }

                    }
                );

            } else if (
                tactic
            ) {

                values.add(
                    formatMitreTactic(
                        tactic
                    )
                );

            }

        }
    );


    if (!values.size) {

        techniques.forEach(
            (
                technique
            ) => {

                const id =
                    String(
                        technique.technique_id ||
                        technique.mitre_id ||
                        technique.id ||
                        ""
                    ).toUpperCase();


                if (
                    id.startsWith(
                        "T1110"
                    )
                ) {
                    values.add(
                        "Credential Access"
                    );
                }


                if (
                    id ===
                    "T1046"
                ) {
                    values.add(
                        "Discovery"
                    );
                }


                if (
                    id ===
                    "T1016"
                ) {
                    values.add(
                        "Discovery"
                    );
                }


                if (
                    id ===
                    "T1049"
                ) {
                    values.add(
                        "Discovery"
                    );
                }


                if (
                    id.startsWith(
                        "T1003"
                    )
                ) {
                    values.add(
                        "Credential Access"
                    );
                }


                if (
                    id ===
                    "T1548.003"
                ) {
                    values.add(
                        "Privilege Escalation"
                    );
                }


                if (
                    id.startsWith(
                        "T1059"
                    )
                ) {
                    values.add(
                        "Execution"
                    );
                }


                if (
                    id ===
                    "T1027"
                ) {
                    values.add(
                        "Defense Evasion"
                    );
                }


                if (
                    id ===
                    "T1105"
                ) {
                    values.add(
                        "Command and Control"
                    );
                }


                if (
                    id.startsWith(
                        "T1098"
                    )
                ) {
                    values.add(
                        "Persistence"
                    );
                }


                if (
                    id.startsWith(
                        "T1053"
                    )
                ) {
                    values.add(
                        "Persistence"
                    );
                }


                if (
                    id.startsWith(
                        "T1543"
                    )
                ) {
                    values.add(
                        "Persistence"
                    );
                }


                if (
                    id.startsWith(
                        "T1546"
                    )
                ) {
                    values.add(
                        "Persistence"
                    );
                }


                if (
                    id ===
                    "T1037"
                ) {
                    values.add(
                        "Persistence"
                    );
                }

            }
        );

    }


    return Array.from(
        values
    );
}


function formatMitreTactic(
    value
) {

    return String(
        value ||
        "Investigation"
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
   COVERAGE
   ============================================================ */

function calculateMitreCoverage(
    techniques
) {

    /*
     * This is an investigation coverage indicator,
     * not a claim of complete ATT&CK coverage.
     *
     * We use a simple bounded metric based on the
     * number of distinct mapped techniques.
     */

    if (!techniques.length) {
        return 0;
    }


    return Math.min(
        100,
        techniques.length * 20
    );
}


/* ============================================================
   CASE SELECTION
   ============================================================ */

document.addEventListener(
    "ldd:case-selected",
    (
        event
    ) => {

        const caseId =
            event.detail?.caseId;


        if (!caseId) {
            return;
        }


        setTimeout(
            () => {

                loadMitre(
                    caseId
                );

            },
            75
        );

    }
);
