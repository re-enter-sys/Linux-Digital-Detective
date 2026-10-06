/*
 * Linux Digital Detective
 * Forensic Timeline Renderer
 *
 * Converts normalized forensic events into an
 * investigator-friendly chronological timeline.
 */

async function loadTimeline(caseId) {
    const container =
        document.getElementById(
            "timeline-content"
        );

    if (!container) {
        return;
    }

    container.innerHTML = `
        <div class="loading">
            Reconstructing forensic timeline...
        </div>
    `;

    try {
        const data =
            await LDD.request(
                `/api/cases/${encodeURIComponent(caseId)}/timeline`
            );

        const events =
            data &&
            Array.isArray(data.events)
                ? data.events
                : Array.isArray(data)
                    ? data
                    : [];

        LDD.state.timeline =
            events;

        renderTimelineData(
            events
        );

    } catch (error) {
        console.error(
            "Linux Digital Detective: timeline request failed.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                <strong>Timeline unavailable.</strong>
                <br>
                The forensic timeline could not be reconstructed.
            </div>
        `;
    }
}


/*
 * Render normalized events.
 *
 * This function is also used by app.js when the
 * investigation data has already been fetched.
 */
function renderTimelineData(
    events = []
) {
    const container =
        document.getElementById(
            "timeline-content"
        );

    if (!container) {
        return;
    }

    if (!Array.isArray(events) || events.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                No normalized forensic events are available.
            </div>
        `;

        return;
    }

    const sortedEvents =
        [...events].sort(
            (a, b) => {
                return (
                    new Date(
                        a.timestamp || 0
                    ) -
                    new Date(
                        b.timestamp || 0
                    )
                );
            }
        );

    container.innerHTML = `
        <div class="forensic-timeline">

            <div class="timeline-header">

                <div>
                    <span class="eyebrow">
                        FORENSIC TIMELINE
                    </span>

                    <h2>
                        Attack Sequence
                    </h2>

                    <p>
                        ${sortedEvents.length}
                        normalized event(s)
                        reconstructed from available evidence.
                    </p>
                </div>

                <div class="timeline-stat">
                    <span>EVENTS</span>
                    <strong>
                        ${sortedEvents.length}
                    </strong>
                </div>

            </div>

            <div class="timeline-track">

                ${sortedEvents
                    .map(
                        (
                            event,
                            index
                        ) =>
                            renderForensicEvent(
                                event,
                                index,
                                sortedEvents
                            )
                    )
                    .join("")}

            </div>

        </div>
    `;

    bindTimelineInteractions();
}


/*
 * Render a single forensic event.
 */
function renderForensicEvent(
    event,
    index,
    events
) {
    const severity =
        String(
            event.severity ||
            "INFO"
        ).toUpperCase();

    const eventType =
        event.event_type ||
        "UNKNOWN_EVENT";

    const timestamp =
        event.timestamp
            ? LDD.formatDate(
                  event.timestamp
              )
            : "-";

    const user =
        event.user ||
        "-";

    const sourceIp =
        event.source_ip ||
        "-";

    const process =
        event.process ||
        "-";

    const pid =
        event.pid !== null &&
        event.pid !== undefined
            ? event.pid
            : "-";

    const command =
        event.command ||
        "";

    const message =
        event.message ||
        event.raw ||
        "No event message available.";

    const raw =
        event.raw ||
        message;

    const metadata =
        event.metadata &&
        typeof event.metadata === "object"
            ? event.metadata
            : {};

    const sequence =
        String(
            index + 1
        ).padStart(
            2,
            "0"
        );

    const previous =
        index > 0
            ? events[index - 1]
            : null;

    const gapSeconds =
        previous &&
        event.timestamp &&
        previous.timestamp
            ? Math.max(
                  0,
                  (
                      new Date(
                          event.timestamp
                      ) -
                      new Date(
                          previous.timestamp
                      )
                  ) / 1000
              )
            : 0;

    const stage =
        determineAttackStage(
            event,
            index
        );

    const metadataHtml =
        renderMetadata(
            metadata
        );

    return `
        <article
            class="forensic-event ${LDD.severityClass(
                severity
            )}"
            data-event-index="${index}"
        >

            <div class="timeline-marker">

                <div class="timeline-sequence">
                    ${sequence}
                </div>

                <div class="timeline-dot"></div>

            </div>

            <div class="timeline-card">

                <div class="timeline-card-header">

                    <div>

                        <div class="timeline-event-type">
                            ${LDD.escape(
                                eventType
                            )}
                        </div>

                        <div class="timeline-stage">
                            ${LDD.escape(
                                stage
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

                <div class="timeline-timestamp">
                    ${LDD.escape(
                        timestamp
                    )}
                </div>

                <div class="timeline-message">
                    ${LDD.escape(
                        message
                    )}
                </div>

                <div class="timeline-details">

                    <div class="timeline-detail">

                        <span>
                            USER
                        </span>

                        <strong>
                            ${LDD.escape(
                                user
                            )}
                        </strong>

                    </div>

                    <div class="timeline-detail">

                        <span>
                            SOURCE
                        </span>

                        <strong>
                            ${LDD.escape(
                                sourceIp
                            )}
                        </strong>

                    </div>

                    <div class="timeline-detail">

                        <span>
                            PROCESS
                        </span>

                        <strong>
                            ${LDD.escape(
                                process
                            )}
                            ${
                                pid !== "-"
                                    ? ` [PID ${LDD.escape(
                                          pid
                                      )}]`
                                    : ""
                            }
                        </strong>

                    </div>

                    <div class="timeline-detail">

                        <span>
                            EVENT ID
                        </span>

                        <strong>
                            ${LDD.escape(
                                event.event_id ||
                                "-"
                            )}
                        </strong>

                    </div>

                </div>

                ${
                    command
                        ? `
                            <div class="timeline-command">

                                <span>
                                    COMMAND
                                </span>

                                <code>
                                    ${LDD.escape(
                                        command
                                    )}
                                </code>

                            </div>
                        `
                        : ""
                }

                <button
                    type="button"
                    class="timeline-expand"
                    data-timeline-toggle="${index}"
                    aria-expanded="false"
                >
                    Show forensic details
                </button>

                <div
                    class="timeline-forensic-details"
                    data-timeline-details="${index}"
                    hidden
                >

                    <div class="forensic-section">

                        <h4>
                            Raw Evidence
                        </h4>

                        <pre>${LDD.escape(
                            raw
                        )}</pre>

                    </div>

                    ${
                        metadataHtml
                            ? `
                                <div class="forensic-section">

                                    <h4>
                                        Parsed Metadata
                                    </h4>

                                    ${metadataHtml}

                                </div>
                            `
                            : ""
                    }

                </div>

            </div>

        </article>

        ${
            gapSeconds > 0
                ? `
                    <div class="timeline-gap">
                        <span>
                            ${formatTimelineGap(
                                gapSeconds
                            )}
                        </span>
                    </div>
                `
                : ""
        }
    `;
}


/*
 * Determine an investigator-friendly
 * attack stage from the normalized event.
 */
function determineAttackStage(
    event,
    index
) {
    const type =
        String(
            event.event_type ||
            ""
        ).toUpperCase();

    const command =
        String(
            event.command ||
            ""
        ).toLowerCase();

    if (
        type.includes(
            "AUTH_FAILURE"
        )
    ) {
        return "INITIAL ACCESS";
    }

    if (
        type.includes(
            "AUTH_SUCCESS"
        )
    ) {
        return "INITIAL ACCESS";
    }

    if (
        type.includes(
            "SESSION_OPEN"
        )
    ) {
        return "EXECUTION";
    }

    if (
        type.includes(
            "SUDO"
        ) ||
        command.includes(
            "sudo"
        )
    ) {
        return "PRIVILEGE ESCALATION";
    }

    if (
        command.includes(
            "/etc/shadow"
        ) ||
        command.includes(
            "/etc/passwd"
        ) ||
        command.includes(
            "authorized_keys"
        )
    ) {
        return "CREDENTIAL ACCESS";
    }

    if (
        command.includes(
            "nmap"
        ) ||
        command.includes(
            "masscan"
        ) ||
        command.includes(
            "netstat"
        ) ||
        command.includes(
            "ss "
        )
    ) {
        return "RECONNAISSANCE";
    }

    if (
        command.includes(
            "curl "
        ) ||
        command.includes(
            "wget "
        )
    ) {
        return "COMMAND & CONTROL";
    }

    if (
        command.includes(
            "cron"
        ) ||
        command.includes(
            "systemctl"
        ) ||
        command.includes(
            "authorized_keys"
        )
    ) {
        return "PERSISTENCE";
    }

    if (
        type.includes(
            "SESSION_CLOSE"
        )
    ) {
        return "CLOSURE";
    }

    if (index === 0) {
        return "INITIAL ACCESS";
    }

    return "OBSERVATION";
}


/*
 * Render event metadata safely.
 */
function renderMetadata(
    metadata
) {
    const entries =
        Object.entries(
            metadata || {}
        );

    if (!entries.length) {
        return "";
    }

    return `
        <div class="forensic-metadata">

            ${entries
                .map(
                    ([key, value]) => `
                        <div class="metadata-row">

                            <span>
                                ${LDD.escape(
                                    key
                                )}
                            </span>

                            <strong>
                                ${LDD.escape(
                                    formatMetadataValue(
                                        value
                                    )
                                )}
                            </strong>

                        </div>
                    `
                )
                .join("")}

        </div>
    `;
}


/*
 * Convert metadata values into readable strings.
 */
function formatMetadataValue(
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
 * Human-readable gap between events.
 */
function formatTimelineGap(
    seconds
) {
    if (seconds < 60) {
        return `+${Math.round(
            seconds
        )} sec`;
    }

    if (seconds < 3600) {
        return `+${Math.round(
            seconds / 60
        )} min`;
    }

    return `+${(
        seconds / 3600
    ).toFixed(1)} hr`;
}


/*
 * Expand/collapse forensic details.
 */
function bindTimelineInteractions() {
    document
        .querySelectorAll(
            "[data-timeline-toggle]"
        )
        .forEach(
            (button) => {
                button.addEventListener(
                    "click",
                    () => {
                        const index =
                            button.dataset
                                .timelineToggle;

                        const details =
                            document.querySelector(
                                `[data-timeline-details="${index}"]`
                            );

                        if (!details) {
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

                        details.hidden =
                            expanded;

                        button.textContent =
                            expanded
                                ? "Show forensic details"
                                : "Hide forensic details";
                    }
                );
            }
        );
}


/*
 * Compatibility helper for the existing dashboard.
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
         * app.js is the primary investigation loader.
         * This listener intentionally does not trigger
         * another request when loadInvestigation exists.
         */
        if (
            typeof loadInvestigation !==
            "function"
        ) {
            loadTimeline(
                caseId
            );
        }
    }
);
