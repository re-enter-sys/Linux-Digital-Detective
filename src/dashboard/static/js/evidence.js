/*
 * Linux Digital Detective
 * Evidence Room
 *
 * Isolated Evidence Room renderer.
 * All CSS classes use the ldd-evidence-* namespace
 * to prevent collisions with the main dashboard.
 */

async function loadEvidence(caseId) {
    const container =
        document.getElementById(
            "evidence-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            Opening evidence room...
        </div>
    `;

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

        renderEvidenceData(
            evidence
        );

    } catch (error) {
        console.error(
            "Linux Digital Detective: evidence request failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                <strong>Evidence room unavailable.</strong>
                <br>
                The collected evidence could not be loaded.
            </div>
        `;
    }
}


function renderEvidenceData(
    evidence = []
) {
    const container =
        document.getElementById(
            "evidence-content"
        );

    if (!container) {
        return;
    }

    if (
        !Array.isArray(evidence) ||
        evidence.length === 0
    ) {
        container.innerHTML = `
            <div class="empty-state">
                No evidence has been collected for this case.
            </div>
        `;

        return;
    }

    const verified =
        evidence.filter(
            (item) =>
                String(
                    item.integrity ||
                    "VERIFIED"
                ).toUpperCase() ===
                "VERIFIED"
        ).length;

    const totalBytes =
        evidence.reduce(
            (
                total,
                item
            ) => {
                const size =
                    Number(
                        item.size_bytes ||
                        item.size ||
                        0
                    );

                return (
                    total +
                    (
                        Number.isFinite(size)
                            ? size
                            : 0
                    )
                );
            },
            0
        );

    container.innerHTML = `
        <section class="ldd-evidence-room">

            <header class="ldd-evidence-header">

                <div class="ldd-evidence-heading">

                    <span class="eyebrow">
                        EVIDENCE ROOM
                    </span>

                    <h2>
                        Collected Artifacts
                    </h2>

                    <p>
                        Forensic artifacts acquired for
                        ${LDD.escape(
                            LDD.currentCase ||
                            "this investigation"
                        )}.
                    </p>

                </div>

                <div class="ldd-evidence-stats">

                    <div class="ldd-evidence-stat">
                        <span>ARTIFACTS</span>
                        <strong>
                            ${evidence.length}
                        </strong>
                    </div>

                    <div class="ldd-evidence-stat">
                        <span>VERIFIED</span>
                        <strong>
                            ${verified}
                        </strong>
                    </div>

                    <div class="ldd-evidence-stat">
                        <span>TOTAL SIZE</span>
                        <strong>
                            ${formatEvidenceSize(
                                totalBytes
                            )}
                        </strong>
                    </div>

                </div>

            </header>

            <div class="ldd-evidence-list">

                ${evidence
                    .map(
                        (
                            item,
                            index
                        ) =>
                            renderEvidenceArtifact(
                                item,
                                index
                            )
                    )
                    .join("")}

            </div>

        </section>
    `;

    bindEvidenceInteractions();
}


function renderEvidenceArtifact(
    item,
    index
) {
    const filename =
        item.filename ||
        item.name ||
        "Unknown artifact";

    const storedFilename =
        item.stored_filename ||
        "-";

    const integrity =
        String(
            item.integrity ||
            "VERIFIED"
        ).toUpperCase();

    const size =
        formatEvidenceSize(
            Number(
                item.size_bytes ||
                item.size ||
                0
            )
        );

    const sha256 =
        item.sha256 ||
        "-";

    const acquired =
        item.acquired_at
            ? LDD.formatDate(
                  item.acquired_at
              )
            : "-";

    const originalPath =
        item.original_path ||
        item.source_path ||
        "-";

    const evidenceId =
        item.evidence_id ||
        item.id ||
        "-";

    const integrityClass =
        integrity === "VERIFIED"
            ? "success"
            : integrity === "FAILED"
                ? "critical"
                : "medium";

    return `
        <article
            class="ldd-evidence-artifact"
            data-evidence-index="${index}"
        >

            <div class="ldd-evidence-artifact-header">

                <div class="ldd-evidence-file-icon">
                    E
                </div>

                <div class="ldd-evidence-file-info">

                    <h3>
                        ${LDD.escape(
                            filename
                        )}
                    </h3>

                    <span>
                        Forensic artifact
                    </span>

                </div>

                <span
                    class="badge ${integrityClass}"
                >
                    ${LDD.escape(
                        integrity
                    )}
                </span>

            </div>

            <div class="ldd-evidence-integrity">

                <div class="ldd-evidence-integrity-label">
                    SHA-256
                </div>

                <code>
                    ${LDD.escape(
                        sha256
                    )}
                </code>

                <button
                    type="button"
                    class="ldd-evidence-copy"
                    data-copy-sha="${index}"
                >
                    Copy hash
                </button>

            </div>

            <div class="ldd-evidence-grid">

                <div class="ldd-evidence-field">
                    <span>SIZE</span>
                    <strong>
                        ${LDD.escape(size)}
                    </strong>
                </div>

                <div class="ldd-evidence-field">
                    <span>ACQUIRED</span>
                    <strong>
                        ${LDD.escape(acquired)}
                    </strong>
                </div>

                <div class="ldd-evidence-field">
                    <span>EVIDENCE ID</span>
                    <strong>
                        ${LDD.escape(evidenceId)}
                    </strong>
                </div>

                <div class="ldd-evidence-field">
                    <span>STORED AS</span>
                    <strong>
                        ${LDD.escape(storedFilename)}
                    </strong>
                </div>

            </div>

            <button
                type="button"
                class="ldd-evidence-details-button"
                data-evidence-details="${index}"
                aria-expanded="false"
            >
                Show forensic metadata
            </button>

            <div
                class="ldd-evidence-details"
                data-evidence-panel="${index}"
                hidden
            >

                <div class="ldd-evidence-detail-section">

                    <h4>
                        Original Path
                    </h4>

                    <code>
                        ${LDD.escape(
                            originalPath
                        )}
                    </code>

                </div>

                <div class="ldd-evidence-detail-section">

                    <h4>
                        Integrity Assessment
                    </h4>

                    <p>
                        ${
                            integrity === "VERIFIED"
                                ? "SHA-256 integrity verification completed successfully. The recorded hash represents the acquired artifact."
                                : "The artifact integrity requires investigator review."
                        }
                    </p>

                </div>

                ${renderEvidenceMetadata(item)}

            </div>

        </article>
    `;
}


function renderEvidenceMetadata(
    item
) {
    const excluded =
        new Set([
            "filename",
            "name",
            "stored_filename",
            "integrity",
            "sha256",
            "size",
            "size_bytes",
            "acquired_at",
            "original_path",
            "source_path",
            "evidence_id",
            "id"
        ]);

    const entries =
        Object.entries(
            item || {}
        ).filter(
            ([key, value]) =>
                !excluded.has(key) &&
                value !== null &&
                value !== undefined &&
                value !== ""
        );

    if (!entries.length) {
        return "";
    }

    return `
        <div class="ldd-evidence-detail-section">

            <h4>
                Additional Metadata
            </h4>

            <div class="ldd-evidence-metadata">

                ${entries
                    .map(
                        ([key, value]) => `
                            <div class="ldd-evidence-metadata-row">

                                <span>
                                    ${LDD.escape(key)}
                                </span>

                                <strong>
                                    ${LDD.escape(
                                        formatEvidenceValue(
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
    `;
}


function bindEvidenceInteractions() {

    document
        .querySelectorAll(
            "[data-copy-sha]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    async () => {

                        const index =
                            Number(
                                button.dataset.copySha
                            );

                        const item =
                            LDD.state
                                .evidence[
                                index
                            ];

                        if (
                            !item ||
                            !item.sha256
                        ) {
                            return;
                        }

                        try {

                            await navigator
                                .clipboard
                                .writeText(
                                    item.sha256
                                );

                            button.textContent =
                                "Copied";

                            setTimeout(
                                () => {
                                    button.textContent =
                                        "Copy hash";
                                },
                                1600
                            );

                        } catch (error) {

                            console.error(
                                "Unable to copy SHA-256.",
                                error
                            );

                            button.textContent =
                                "Copy failed";
                        }
                    }
                );
            }
        );


    document
        .querySelectorAll(
            "[data-evidence-details]"
        )
        .forEach(
            (button) => {

                button.addEventListener(
                    "click",
                    () => {

                        const index =
                            button.dataset
                                .evidenceDetails;

                        const panel =
                            document.querySelector(
                                `[data-evidence-panel="${index}"]`
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
                            String(!expanded)
                        );

                        panel.hidden =
                            expanded;

                        button.textContent =
                            expanded
                                ? "Show forensic metadata"
                                : "Hide forensic metadata";
                    }
                );
            }
        );
}


function formatEvidenceSize(
    bytes
) {
    const value =
        Number(bytes);

    if (
        !Number.isFinite(value) ||
        value <= 0
    ) {
        return "0 B";
    }

    const units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB"
    ];

    let size =
        value;

    let unitIndex =
        0;

    while (
        size >= 1024 &&
        unitIndex <
            units.length - 1
    ) {
        size /=
            1024;

        unitIndex +=
            1;
    }

    if (unitIndex === 0) {
        return `${Math.round(size)} ${units[unitIndex]}`;
    }

    return `${size.toFixed(2)} ${units[unitIndex]}`;
}


function formatEvidenceValue(
    value
) {
    if (
        typeof value === "object"
    ) {
        try {
            return JSON.stringify(value);
        } catch {
            return String(value);
        }
    }

    return String(value);
}
