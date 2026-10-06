/*
 * Linux Digital Detective
 * Investigation Board
 *
 * Renders the correlated attack chains already loaded
 * by the central dashboard controller.
 *
 * IMPORTANT:
 * This file does not define or replace the dashboard theme.
 * All board-specific classes remain namespaced.
 */


/* ============================================================
   PUBLIC BOARD LOADER
   ============================================================ */

function loadAttackBoard(caseId) {

    const container =
        document.getElementById(
            "attack-board-content"
        );

    if (!container) {
        console.warn(
            "Linux Digital Detective: Attack Board container not found."
        );
        return;
    }

    /*
     * The central app controller loads the complete
     * investigation object first.
     *
     * Therefore the board should consume that state
     * instead of making a second investigation request.
     */

    const investigation =
        LDD.state.investigationData ||
        null;

    if (investigation) {

        renderAttackBoard(
            investigation
        );

        return;
    }


    /*
     * Some versions of app.js store individual pieces
     * of the investigation instead of the complete object.
     *
     * Build a compatible object from those pieces.
     */

    const chains =
        Array.isArray(
            LDD.state.attackChains
        )
            ? LDD.state.attackChains
            : [];

    const findings =
        Array.isArray(
            LDD.state.findings
        )
            ? LDD.state.findings
            : [];

    const events =
        Array.isArray(
            LDD.state.events
        )
            ? LDD.state.events
            : [];


    if (
        chains.length ||
        findings.length ||
        events.length
    ) {

        renderAttackBoard({
            attack_chains: chains,
            findings: findings,
            events: events
        });

        return;
    }


    /*
     * No data is available yet.
     *
     * Do not show a misleading "failed to load"
     * message immediately. The central controller
     * may still be loading the investigation.
     */

    container.innerHTML = `
        <div class="empty-state">
            <strong>Investigation data is being prepared.</strong>
            <br>
            Select the Attack Board again after the case finishes loading.
        </div>
    `;
}


/* ============================================================
   MAIN RENDERER
   ============================================================ */

function renderAttackBoard(
    investigation = {}
) {

    const container =
        document.getElementById(
            "attack-board-content"
        );

    if (!container) {
        return;
    }


    const chains =
        extractAttackChains(
            investigation
        );

    const findings =
        extractFindings(
            investigation
        );

    const events =
        extractEvents(
            investigation
        );


    /*
     * If the investigation contains no explicit chains,
     * create a visual fallback from findings/events.
     */

    const boardChains =
        chains.length
            ? chains
            : buildFallbackChain(
                  findings,
                  events
              );


    if (!boardChains.length) {

        container.innerHTML = `
            <div class="empty-state">

                <strong>
                    No attack chain available.
                </strong>

                <br>

                The investigation completed, but no
                correlated attack sequence was generated.

            </div>
        `;

        return;
    }


    /*
     * Calculate overall board information.
     */

    const totalSteps =
        boardChains.reduce(
            (
                total,
                chain
            ) =>
                total +
                (
                    Array.isArray(
                        chain.steps
                    )
                        ? chain.steps.length
                        : 0
                ),
            0
        );


    const highestSeverity =
        getHighestSeverity(
            findings,
            boardChains
        );


    const confidence =
        calculateBoardConfidence(
            boardChains
        );


    container.innerHTML = `

        <section class="ldd-board">

            <!-- ============================================
                 BOARD HEADER
                 ============================================ -->

            <header class="ldd-board-header">

                <div class="ldd-board-heading">

                    <span class="eyebrow">
                        INVESTIGATION BOARD
                    </span>

                    <h2>
                        Attack Chain Reconstruction
                    </h2>

                    <p>
                        Correlated evidence grouped into
                        chronological attack activity.
                    </p>

                </div>


                <div class="ldd-board-status">

                    <span>
                        INVESTIGATION STATUS
                    </span>

                    <strong class="${LDD.severityClass(
                        highestSeverity
                    )}">
                        ${LDD.escape(
                            highestSeverity
                        )}
                    </strong>

                </div>

            </header>


            <!-- ============================================
                 BOARD METRICS
                 ============================================ -->

            <section class="ldd-board-metrics">

                <div class="ldd-board-metric">

                    <span>
                        ATTACK CHAINS
                    </span>

                    <strong>
                        ${boardChains.length}
                    </strong>

                </div>


                <div class="ldd-board-metric">

                    <span>
                        CHAIN STEPS
                    </span>

                    <strong>
                        ${totalSteps}
                    </strong>

                </div>


                <div class="ldd-board-metric">

                    <span>
                        FINDINGS
                    </span>

                    <strong>
                        ${findings.length}
                    </strong>

                </div>


                <div class="ldd-board-metric">

                    <span>
                        CONFIDENCE
                    </span>

                    <strong>
                        ${confidence}%
                    </strong>

                </div>

            </section>


            <!-- ============================================
                 ATTACK CHAINS
                 ============================================ -->

            <section class="ldd-board-chains">

                <div class="ldd-board-section-title">

                    <span>
                        CORRELATED ACTIVITY
                    </span>

                    <p>
                        Each chain represents a sequence of
                        related investigation findings.
                    </p>

                </div>


                <div class="ldd-board-chain-list">

                    ${boardChains
                        .map(
                            (
                                chain,
                                index
                            ) =>
                                renderBoardChain(
                                    chain,
                                    index
                                )
                        )
                        .join("")}

                </div>

            </section>

        </section>
    `;


    bindBoardInteractions();
}


/* ============================================================
   DATA EXTRACTION
   ============================================================ */

function extractAttackChains(
    investigation
) {

    if (
        Array.isArray(
            investigation.attack_chains
        )
    ) {
        return investigation.attack_chains;
    }


    if (
        investigation.attack_story &&
        Array.isArray(
            investigation.attack_story.attack_chains
        )
    ) {
        return investigation
            .attack_story
            .attack_chains;
    }


    if (
        investigation.story &&
        Array.isArray(
            investigation.story.attack_chains
        )
    ) {
        return investigation
            .story
            .attack_chains;
    }


    return [];
}


function extractFindings(
    investigation
) {

    if (
        Array.isArray(
            investigation.findings
        )
    ) {
        return investigation.findings;
    }


    return Array.isArray(
        LDD.state.findings
    )
        ? LDD.state.findings
        : [];
}


function extractEvents(
    investigation
) {

    if (
        Array.isArray(
            investigation.events
        )
    ) {
        return investigation.events;
    }


    return Array.isArray(
        LDD.state.events
    )
        ? LDD.state.events
        : [];
}


/* ============================================================
   FALLBACK CHAIN
   ============================================================ */

function buildFallbackChain(
    findings,
    events
) {

    if (
        !findings.length &&
        !events.length
    ) {
        return [];
    }


    const steps = [];


    /*
     * Convert findings into chronological steps.
     */

    findings
        .slice()
        .sort(
            (
                first,
                second
            ) =>
                getTimestamp(first) -
                getTimestamp(second)
        )
        .forEach(
            (
                finding
            ) => {

                const stage =
                    inferFindingStage(
                        finding
                    );

                steps.push({

                    stage:
                        stage,

                    title:
                        finding.title ||
                        finding.name ||
                        finding.finding_type ||
                        finding.category ||
                        "Detection Finding",

                    description:
                        finding.description ||
                        finding.message ||
                        "Detection finding associated with the investigation.",

                    timestamp:
                        finding.timestamp ||
                        finding.detected_at ||
                        null,

                    severity:
                        finding.severity ||
                        "INFO",

                    event_ids:
                        finding.event_ids ||
                        [],

                    finding_ids:
                        [
                            finding.finding_id ||
                            finding.id ||
                            "UNKNOWN"
                        ],

                    indicators:
                        finding.indicators ||
                        []

                });
            }
        );


    /*
     * If findings did not produce steps,
     * derive a basic chain from events.
     */

    if (!steps.length) {

        events
            .slice()
            .sort(
                (
                    first,
                    second
                ) =>
                    getTimestamp(first) -
                    getTimestamp(second)
            )
            .forEach(
                (
                    event
                ) => {

                    const eventType =
                        String(
                            event.event_type ||
                            ""
                        ).toUpperCase();


                    if (
                        eventType.includes(
                            "SSH_AUTH_FAILURE"
                        )
                    ) {

                        steps.push({
                            stage:
                                "INITIAL_ACCESS",

                            title:
                                "SSH Authentication Failures",

                            description:
                                "Repeated SSH authentication failures were observed.",

                            timestamp:
                                event.timestamp,

                            severity:
                                event.severity ||
                                "HIGH",

                            event_ids:
                                [
                                    event.event_id
                                ],

                            finding_ids:
                                [],

                            indicators:
                                []
                        });

                        return;
                    }


                    if (
                        eventType.includes(
                            "SSH_AUTH_SUCCESS"
                        )
                    ) {

                        steps.push({
                            stage:
                                "INITIAL_ACCESS",

                            title:
                                "Successful SSH Login",

                            description:
                                "A successful SSH authentication followed the observed failures.",

                            timestamp:
                                event.timestamp,

                            severity:
                                event.severity ||
                                "CRITICAL",

                            event_ids:
                                [
                                    event.event_id
                                ],

                            finding_ids:
                                [],

                            indicators:
                                []
                        });

                        return;
                    }


                    if (
                        eventType.includes(
                            "SUDO_COMMAND"
                        )
                    ) {

                        steps.push({
                            stage:
                                "PRIVILEGE_ESCALATION",

                            title:
                                "Privilege Escalation",

                            description:
                                "A sudo command indicating elevated privileges was observed.",

                            timestamp:
                                event.timestamp,

                            severity:
                                event.severity ||
                                "CRITICAL",

                            event_ids:
                                [
                                    event.event_id
                                ],

                            finding_ids:
                                [],

                            indicators:
                                []
                        });

                    }

                }
            );
    }


    if (!steps.length) {
        return [];
    }


    return [
        {
            chain_id:
                "CHAIN-RECONSTRUCTED",

            confidence:
                60,

            steps:
                steps,

            metadata:
                {
                    stages:
                        steps.map(
                            (
                                step
                            ) =>
                                step.stage
                        )
                }
        }
    ];
}


/* ============================================================
   CHAIN RENDERER
   ============================================================ */

function renderBoardChain(
    chain,
    chainIndex
) {

    const chainId =
        chain.chain_id ||
        chain.id ||
        `CHAIN-${String(
            chainIndex + 1
        ).padStart(
            4,
            "0"
        )}`;


    const confidence =
        Number(
            chain.confidence ||
            0
        );


    const steps =
        Array.isArray(
            chain.steps
        )
            ? chain.steps
            : [];


    const stages =
        steps
            .map(
                (
                    step
                ) =>
                    step.stage ||
                    ""
            )
            .filter(
                Boolean
            );


    return `

        <article
            class="ldd-board-chain"
            data-chain-id="${LDD.escape(
                chainId
            )}"
        >

            <!-- CHAIN HEADER -->

            <header class="ldd-board-chain-header">

                <div>

                    <span>
                        ATTACK CHAIN
                    </span>

                    <strong>
                        ${LDD.escape(
                            chainId
                        )}
                    </strong>

                </div>


                <div class="ldd-board-chain-meta">

                    <span>
                        ${steps.length}
                        STEP${steps.length === 1 ? "" : "S"}
                    </span>

                    <span>
                        ${confidence}% CONFIDENCE
                    </span>

                </div>

            </header>


            <!-- CHAIN PATH -->

            <div class="ldd-board-path">

                ${
                    steps.length
                        ? steps
                            .map(
                                (
                                    step,
                                    index
                                ) =>
                                    renderBoardStep(
                                        step,
                                        index,
                                        steps.length
                                    )
                            )
                            .join("")
                        : `
                            <div class="empty-state">
                                No steps available.
                            </div>
                        `
                }

            </div>


            <!-- STAGE SUMMARY -->

            ${
                stages.length
                    ? `
                        <footer class="ldd-board-chain-footer">

                            <span>
                                STAGES
                            </span>

                            <div>

                                ${stages
                                    .map(
                                        (
                                            stage
                                        ) => `
                                            <span class="ldd-board-stage">
                                                ${LDD.escape(
                                                    stage
                                                )}
                                            </span>
                                        `
                                    )
                                    .join("")}

                            </div>

                        </footer>
                    `
                    : ""
            }

        </article>

    `;
}


/* ============================================================
   CHAIN STEP
   ============================================================ */

function renderBoardStep(
    step,
    index,
    total
) {

    const stage =
        step.stage ||
        "UNKNOWN";


    const title =
        step.title ||
        step.name ||
        stage;


    const description =
        step.description ||
        "";


    const severity =
        String(
            step.severity ||
            "INFO"
        ).toUpperCase();


    const timestamp =
        step.timestamp ||
        step.time ||
        null;


    const eventIds =
        Array.isArray(
            step.event_ids
        )
            ? step.event_ids
            : [];


    const findingIds =
        Array.isArray(
            step.finding_ids
        )
            ? step.finding_ids
            : [];


    return `

        <div
            class="ldd-board-step"
            data-step-index="${index}"
        >

            <div class="ldd-board-step-marker">

                <span>
                    ${String(
                        index + 1
                    ).padStart(
                        2,
                        "0"
                    )}
                </span>

            </div>


            <div class="ldd-board-step-content">

                <div class="ldd-board-step-heading">

                    <div>

                        <span class="ldd-board-step-stage">
                            ${LDD.escape(
                                stage
                            )}
                        </span>

                        <strong>
                            ${LDD.escape(
                                title
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


                ${
                    description
                        ? `
                            <p>
                                ${LDD.escape(
                                    description
                                )}
                            </p>
                        `
                        : ""
                }


                ${
                    timestamp
                        ? `
                            <time>
                                ${LDD.escape(
                                    LDD.formatDate(
                                        timestamp
                                    )
                                )}
                            </time>
                        `
                        : ""
                }


                <div class="ldd-board-evidence">

                    ${
                        eventIds.length
                            ? `
                                <span>
                                    EVENTS
                                </span>

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
                            `
                            : ""
                    }


                    ${
                        findingIds.length
                            ? `
                                <span>
                                    FINDINGS
                                </span>

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
                            `
                            : ""
                    }

                </div>


                ${
                    eventIds.length ||
                    findingIds.length
                        ? `
                            <button
                                type="button"
                                class="ldd-board-inspect"
                                data-board-inspect="${index}"
                            >
                                Inspect Evidence
                            </button>
                        `
                        : ""
                }

            </div>


            ${
                index <
                total - 1
                    ? `
                        <div class="ldd-board-connector">
                            ↓
                        </div>
                    `
                    : ""
            }

        </div>

    `;
}


/* ============================================================
   INTERACTIONS
   ============================================================ */

function bindBoardInteractions() {

    document
        .querySelectorAll(
            "[data-board-inspect]"
        )
        .forEach(
            (
                button
            ) => {

                button.addEventListener(
                    "click",
                    () => {

                        /*
                         * Evidence inspection currently
                         * switches to the Findings tab,
                         * where the complete forensic details
                         * are available.
                         */

                        const findingsTab =
                            document.querySelector(
                                '[data-tab="findings"]'
                            );


                        if (
                            findingsTab
                        ) {

                            findingsTab.click();

                            return;
                        }


                        /*
                         * Compatibility with alternate
                         * tab implementations.
                         */

                        if (
                            typeof switchTab ===
                            "function"
                        ) {

                            switchTab(
                                "findings"
                            );

                        }

                    }
                );

            }
        );
}


/* ============================================================
   HELPERS
   ============================================================ */

function getTimestamp(
    item
) {

    const value =
        item?.timestamp ||
        item?.detected_at ||
        item?.created_at ||
        null;


    if (!value) {
        return 0;
    }


    const timestamp =
        new Date(
            value
        ).getTime();


    return Number.isFinite(
        timestamp
    )
        ? timestamp
        : 0;
}


function getHighestSeverity(
    findings,
    chains
) {

    const levels = {
        INFO: 0,
        LOW: 1,
        MEDIUM: 2,
        HIGH: 3,
        CRITICAL: 4
    };


    let highest =
        "INFO";


    const consider =
        (
            severity
        ) => {

            const normalized =
                String(
                    severity ||
                    "INFO"
                ).toUpperCase();


            if (
                (
                    levels[
                        normalized
                    ] ??
                    0
                ) >
                (
                    levels[
                        highest
                    ] ??
                    0
                )
            ) {

                highest =
                    normalized;

            }

        };


    findings.forEach(
        (
            finding
        ) =>
            consider(
                finding.severity
            )
    );


    chains.forEach(
        (
            chain
        ) => {

            const steps =
                Array.isArray(
                    chain.steps
                )
                    ? chain.steps
                    : [];


            steps.forEach(
                (
                    step
                ) =>
                    consider(
                        step.severity
                    )
            );

        }
    );


    return highest;
}


function calculateBoardConfidence(
    chains
) {

    if (!chains.length) {
        return 0;
    }


    const values =
        chains
            .map(
                (
                    chain
                ) =>
                    Number(
                        chain.confidence ||
                        0
                    )
            )
            .filter(
                (
                    value
                ) =>
                    Number.isFinite(
                        value
                    )
            );


    if (!values.length) {
        return 0;
    }


    const average =
        values.reduce(
            (
                total,
                value
            ) =>
                total +
                value,
            0
        ) /
        values.length;


    return Math.round(
        average
    );
}


function inferFindingStage(
    finding
) {

    const type =
        String(
            finding.finding_type ||
            finding.category ||
            finding.type ||
            ""
        ).toUpperCase();


    const title =
        String(
            finding.title ||
            finding.name ||
            ""
        ).toUpperCase();


    const combined =
        `${type} ${title}`;


    if (
        combined.includes(
            "BRUTE"
        ) ||
        combined.includes(
            "SSH"
        )
    ) {

        return "INITIAL_ACCESS";

    }


    if (
        combined.includes(
            "PRIV"
        ) ||
        combined.includes(
            "SUDO"
        )
    ) {

        return "PRIVILEGE_ESCALATION";

    }


    if (
        combined.includes(
            "CREDENTIAL"
        )
    ) {

        return "CREDENTIAL_ACCESS";

    }


    if (
        combined.includes(
            "PERSIST"
        )
    ) {

        return "PERSISTENCE";

    }


    if (
        combined.includes(
            "NETWORK"
        ) ||
        combined.includes(
            "SCAN"
        )
    ) {

        return "DISCOVERY";

    }


    if (
        combined.includes(
            "COMMAND"
        ) ||
        combined.includes(
            "EXECUTION"
        )
    ) {

        return "EXECUTION";

    }


    return "UNKNOWN";
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


        /*
         * Give app.js a moment to finish loading the
         * central investigation object.
         */

        setTimeout(
            () => {

                loadAttackBoard(
                    caseId
                );

            },
            50
        );

    }
);
