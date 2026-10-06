/*
 * Linux Digital Detective
 * Attack Story
 *
 * Converts correlated investigation data into a
 * human-readable investigator narrative.
 *
 * Theme-safe:
 * all new classes use the ldd-story-* namespace.
 */


async function loadAttackStory(caseId) {

    const container =
        document.getElementById(
            "attack-story-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            Reconstructing attack story...
        </div>
    `;

    try {

        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/attack-story`
            );

        const story =
            data.attack_story ||
            data;

        LDD.state.attackStory =
            story;

        renderAttackStory(
            story
        );

    } catch (error) {

        console.error(
            "Linux Digital Detective: attack story request failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                <strong>Attack story unavailable.</strong>
                <br>
                The investigation narrative could not be reconstructed.
            </div>
        `;
    }
}


/*
 * Render complete attack story.
 */
function renderAttackStory(
    story = {}
) {

    const container =
        document.getElementById(
            "attack-story-content"
        );

    if (!container) {
        return;
    }

    const attackPath =
        Array.isArray(
            story.attack_path
        )
            ? story.attack_path
            : [];

    const narrative =
        Array.isArray(
            story.narrative
        )
            ? story.narrative
            : [];

    const chains =
        Array.isArray(
            story.attack_chains
        )
            ? story.attack_chains
            : LDD.state.attackChains || [];

    const mitre =
        Array.isArray(
            story.mitre_techniques
        )
            ? story.mitre_techniques
            : LDD.state.mitre || [];

    const sourceIps =
        Array.isArray(
            story.source_ips
        )
            ? story.source_ips
            : [];

    const usernames =
        Array.isArray(
            story.usernames
        )
            ? story.usernames
            : [];

    const findingCount =
        Number(
            story.finding_count ||
            LDD.state.findings.length ||
            0
        );

    const confidence =
        Number(
            story.confidence ||
            0
        );

    const risk =
        story.risk_score ||
        LDD.state.riskScore ||
        {};

    const riskScore =
        Number(
            risk.score ||
            0
        );

    const riskSeverity =
        risk.severity ||
        "INFO";


    container.innerHTML = `

        <section class="ldd-story">

            <!-- ============================================
                 STORY HEADER
                 ============================================ -->

            <header class="ldd-story-header">

                <div>

                    <span class="eyebrow">
                        INVESTIGATOR'S NARRATIVE
                    </span>

                    <h2>
                        ${LDD.escape(
                            story.title ||
                            "Attack Story"
                        )}
                    </h2>

                    <p>
                        Evidence has been correlated into
                        a chronological attack narrative.
                    </p>

                </div>


                <div class="ldd-story-verdict">

                    <span>
                        INCIDENT RATING
                    </span>

                    <strong
                        class="${LDD.severityClass(
                            riskSeverity
                        )}"
                    >
                        ${LDD.escape(
                            riskSeverity
                        )}
                    </strong>

                </div>

            </header>


            <!-- ============================================
                 ATTACK PATH
                 ============================================ -->

            <section class="ldd-story-path">

                <div class="ldd-story-section-heading">

                    <span>
                        01
                    </span>

                    <div>

                        <strong>
                            ATTACK PATH
                        </strong>

                        <p>
                            Reconstructed sequence of attacker activity.
                        </p>

                    </div>

                </div>


                <div class="ldd-story-path-track">

                    ${
                        attackPath.length
                            ? attackPath
                                .map(
                                    (
                                        stage,
                                        index
                                    ) =>
                                        renderStoryPathNode(
                                            stage,
                                            index,
                                            attackPath.length
                                        )
                                )
                                .join("")
                            : `
                                <div class="ldd-story-empty">
                                    No attack path was generated.
                                </div>
                            `
                    }

                </div>

            </section>


            <!-- ============================================
                 INVESTIGATION METRICS
                 ============================================ -->

            <section class="ldd-story-metrics">

                ${renderStoryMetric(
                    "RISK SCORE",
                    `${riskScore}/100`
                )}

                ${renderStoryMetric(
                    "CONFIDENCE",
                    `${confidence}%`
                )}

                ${renderStoryMetric(
                    "FINDINGS",
                    findingCount
                )}

                ${renderStoryMetric(
                    "ATTACK CHAINS",
                    chains.length
                )}

                ${renderStoryMetric(
                    "MITRE",
                    mitre.length
                )}

            </section>


            <!-- ============================================
                 INVESTIGATOR NARRATIVE
                 ============================================ -->

            <section class="ldd-story-narrative">

                <div class="ldd-story-section-heading">

                    <span>
                        02
                    </span>

                    <div>

                        <strong>
                            WHAT HAPPENED
                        </strong>

                        <p>
                            Investigator reconstruction of the incident.
                        </p>

                    </div>

                </div>


                <div class="ldd-story-narrative-body">

                    ${
                        narrative.length
                            ? narrative
                                .map(
                                    (
                                        paragraph,
                                        index
                                    ) => `
                                        <div
                                            class="ldd-story-narrative-item"
                                        >

                                            <span>
                                                ${String(
                                                    index + 1
                                                ).padStart(
                                                    2,
                                                    "0"
                                                )}
                                            </span>

                                            <p>
                                                ${LDD.escape(
                                                    paragraph
                                                )}
                                            </p>

                                        </div>
                                    `
                                )
                                .join("")
                            : `
                                <div class="ldd-story-empty">
                                    No narrative was generated.
                                </div>
                            `
                    }

                </div>

            </section>


            <!-- ============================================
                 ACTOR / INDICATORS
                 ============================================ -->

            <section class="ldd-story-indicators">

                <div class="ldd-story-section-heading">

                    <span>
                        03
                    </span>

                    <div>

                        <strong>
                            INVESTIGATION INDICATORS
                        </strong>

                        <p>
                            Entities associated with the detected activity.
                        </p>

                    </div>

                </div>


                <div class="ldd-story-indicator-grid">

                    <div class="ldd-story-indicator-card">

                        <span>
                            SOURCE IP
                        </span>

                        ${
                            sourceIps.length
                                ? sourceIps
                                    .map(
                                        (ip) => `
                                            <code>
                                                ${LDD.escape(
                                                    ip
                                                )}
                                            </code>
                                        `
                                    )
                                    .join("")
                                : `
                                    <strong>
                                        Not identified
                                    </strong>
                                `
                        }

                    </div>


                    <div class="ldd-story-indicator-card">

                        <span>
                            USERNAME
                        </span>

                        ${
                            usernames.length
                                ? usernames
                                    .map(
                                        (username) => `
                                            <code>
                                                ${LDD.escape(
                                                    username
                                                )}
                                            </code>
                                        `
                                    )
                                    .join("")
                                : `
                                    <strong>
                                        Not identified
                                    </strong>
                                `
                        }

                    </div>

                </div>

            </section>


            <!-- ============================================
                 ATTACK CHAINS
                 ============================================ -->

            <section class="ldd-story-chains">

                <div class="ldd-story-section-heading">

                    <span>
                        04
                    </span>

                    <div>

                        <strong>
                            CORRELATED ATTACK CHAINS
                        </strong>

                        <p>
                            Detection findings grouped into related activity.
                        </p>

                    </div>

                </div>


                ${
                    chains.length
                        ? `
                            <div class="ldd-story-chain-list">

                                ${chains
                                    .map(
                                        (
                                            chain
                                        ) =>
                                            renderStoryChain(
                                                chain
                                            )
                                    )
                                    .join("")}

                            </div>
                        `
                        : `
                            <div class="ldd-story-empty">
                                No correlated attack chains were generated.
                            </div>
                        `
                }

            </section>


            <!-- ============================================
                 MITRE ATT&CK
                 ============================================ -->

            <section class="ldd-story-mitre">

                <div class="ldd-story-section-heading">

                    <span>
                        05
                    </span>

                    <div>

                        <strong>
                            ATTACK TECHNIQUES
                        </strong>

                        <p>
                            MITRE ATT&amp;CK techniques associated
                            with the investigation.
                        </p>

                    </div>

                </div>


                ${
                    mitre.length
                        ? `
                            <div class="ldd-story-mitre-list">

                                ${mitre
                                    .map(
                                        (
                                            technique
                                        ) =>
                                            renderStoryMitre(
                                                technique
                                            )
                                    )
                                    .join("")}

                            </div>
                        `
                        : `
                            <div class="ldd-story-empty">
                                No MITRE ATT&amp;CK mappings were generated.
                            </div>
                        `
                }

            </section>


            <!-- ============================================
                 CONCLUSION
                 ============================================ -->

            <section class="ldd-story-conclusion">

                <div class="ldd-story-section-heading">

                    <span>
                        06
                    </span>

                    <div>

                        <strong>
                            INVESTIGATOR CONCLUSION
                        </strong>

                        <p>
                            Final assessment based on the available evidence.
                        </p>

                    </div>

                </div>


                <div class="ldd-story-conclusion-box">

                    <div class="ldd-story-conclusion-status">

                        <span>
                            ${LDD.escape(
                                riskSeverity
                            )}
                        </span>

                    </div>

                    <p>
                        ${LDD.escape(
                            story.conclusion ||
                            buildFallbackConclusion(
                                story,
                                riskScore,
                                riskSeverity
                            )
                        )}
                    </p>

                </div>

            </section>

        </section>
    `;
}


/*
 * Attack path node.
 */
function renderStoryPathNode(
    stage,
    index,
    total
) {

    const normalized =
        String(
            stage || ""
        )
            .toLowerCase()
            .replaceAll(
                "_",
                " "
            );

    const title =
        normalized
            .replace(
                /\b\w/g,
                (character) =>
                    character.toUpperCase()
            );

    return `

        <div class="ldd-story-path-node">

            <div class="ldd-story-path-number">

                ${String(
                    index + 1
                ).padStart(
                    2,
                    "0"
                )}

            </div>

            <div class="ldd-story-path-content">

                <strong>
                    ${LDD.escape(
                        title
                    )}
                </strong>

                <span>
                    Attack stage
                </span>

            </div>

        </div>

        ${
            index <
            total - 1
                ? `
                    <div class="ldd-story-path-arrow">
                        →
                    </div>
                `
                : ""
        }

    `;
}


/*
 * Investigation metric.
 */
function renderStoryMetric(
    label,
    value
) {

    return `

        <div class="ldd-story-metric">

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


/*
 * Attack chain card.
 */
function renderStoryChain(
    chain
) {

    const chainId =
        chain.chain_id ||
        chain.id ||
        "UNKNOWN";

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

    return `

        <article class="ldd-story-chain">

            <div class="ldd-story-chain-header">

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

                <span class="ldd-story-confidence">
                    ${confidence}% CONFIDENCE
                </span>

            </div>


            <div class="ldd-story-chain-steps">

                ${
                    steps.length
                        ? steps
                            .map(
                                (
                                    step,
                                    index
                                ) =>
                                    renderStoryChainStep(
                                        step,
                                        index
                                    )
                            )
                            .join("")
                        : `
                            <div class="ldd-story-empty">
                                No chain steps available.
                            </div>
                        `
                }

            </div>

        </article>

    `;
}


/*
 * Individual attack chain step.
 */
function renderStoryChainStep(
    step,
    index
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
        null;

    return `

        <div class="ldd-story-chain-step">

            <div class="ldd-story-chain-step-number">

                ${String(
                    index + 1
                ).padStart(
                    2,
                    "0"
                )}

            </div>


            <div class="ldd-story-chain-step-main">

                <div class="ldd-story-chain-step-heading">

                    <strong>
                        ${LDD.escape(
                            title
                        )}
                    </strong>

                    <span class="badge ${LDD.severityClass(
                        severity
                    )}">
                        ${LDD.escape(
                            severity
                        )}
                    </span>

                </div>


                <span class="ldd-story-chain-stage">
                    ${LDD.escape(
                        stage
                    )}
                </span>


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

            </div>

        </div>

    `;
}


/*
 * MITRE technique card.
 */
function renderStoryMitre(
    technique
) {

    const id =
        technique.technique_id ||
        technique.id ||
        technique.mitre_id ||
        "-";

    const name =
        technique.name ||
        technique.technique ||
        "Unknown technique";

    const description =
        technique.description ||
        technique.reason ||
        "";

    return `

        <article class="ldd-story-mitre-card">

            <div class="ldd-story-mitre-id">

                ${LDD.escape(
                    id
                )}

            </div>

            <div>

                <strong>
                    ${LDD.escape(
                        name
                    )}
                </strong>

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

            </div>

        </article>

    `;
}


/*
 * Fallback conclusion.
 */
function buildFallbackConclusion(
    story,
    riskScore,
    riskSeverity
) {

    const findings =
        Number(
            story.finding_count ||
            0
        );

    if (
        findings === 0
    ) {

        return (
            "No confirmed detection findings were generated from the available evidence."
        );
    }

    return (
        `The investigation identified ${findings} detection finding(s). ` +
        `The resulting risk assessment is ${riskScore}/100 (${riskSeverity}). ` +
        `The available evidence should be reviewed alongside the correlated attack chains ` +
        `before final incident disposition.`
    );
}


/*
 * Case selection compatibility.
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
         * app.js normally loads the story.
         * This fallback ensures the tab also works
         * when selected independently.
         */
        if (
            !LDD.state.attackStory
        ) {

            loadAttackStory(
                caseId
            );
        }

    }
);
