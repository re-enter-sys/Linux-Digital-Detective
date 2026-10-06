async function loadCases() {
    const container =
        document.getElementById("cases");

    if (!container) {
        console.error(
            "Linux Digital Detective: #cases container not found."
        );
        return;
    }

    container.innerHTML =
        '<div class="loading">Loading cases...</div>';

    try {
        const data =
            await LDD.request("/api/cases");

        const cases =
            Array.isArray(data)
                ? data
                : Array.isArray(data.cases)
                    ? data.cases
                    : [];

        LDD.state.cases = cases;

        renderCaseCells(cases);
        updateCaseStatistics(cases);

        console.log(
            `Linux Digital Detective: loaded ${cases.length} case(s).`
        );
    } catch (error) {
        console.error(
            "Linux Digital Detective: failed to load cases.",
            error
        );

        container.innerHTML = `
            <div class="empty-state">
                Unable to load cases.
            </div>
        `;

        updateCaseStatistics([]);
    }
}


function renderCaseCells(cases) {
    const container =
        document.getElementById("cases");

    if (!container) {
        return;
    }

    const cells = [];

    const maximumCells =
        Math.max(6, cases.length);

    for (
        let index = 0;
        index < maximumCells;
        index += 1
    ) {
        const investigationCase =
            cases[index];

        if (!investigationCase) {
            cells.push(`
                <div class="case-cell">
                    <div class="cell-bars"></div>

                    <div class="cell-number">
                        CELL ${String(index + 1).padStart(2, "0")}
                    </div>

                    <div class="cell-empty">
                        Empty Cell
                    </div>
                </div>
            `);

            continue;
        }

        const caseId =
            investigationCase.case_id ||
            investigationCase.id ||
            `CASE-${String(index + 1).padStart(4, "0")}`;

        const title =
            investigationCase.title ||
            "Untitled investigation";

        const status =
            investigationCase.status ||
            "NEW";

        const severity =
            investigationCase.severity ||
            "INFO";

        cells.push(`
            <div
                class="case-cell"
                data-case-id="${LDD.escape(caseId)}"
                role="button"
                tabindex="0"
            >
                <div class="cell-bars"></div>

                <div class="cell-number">
                    CELL ${String(index + 1).padStart(2, "0")}
                </div>

                <div class="cell-case-id">
                    ${LDD.escape(caseId)}
                </div>

                <div class="cell-title">
                    ${LDD.escape(title)}
                </div>

                <div class="cell-status ${LDD.severityClass(status)}">
                    ${LDD.escape(status)}
                </div>

                <div class="cell-severity ${LDD.severityClass(severity)}">
                    ${LDD.escape(severity)}
                </div>
            </div>
        `);
    }

    container.innerHTML =
        cells.join("");

    container
        .querySelectorAll("[data-case-id]")
        .forEach((cell) => {
            const caseId =
                cell.dataset.caseId;

            cell.addEventListener(
                "click",
                () => {
                    LDD.openCase(caseId);
                }
            );

            cell.addEventListener(
                "keydown",
                (event) => {
                    if (
                        event.key === "Enter" ||
                        event.key === " "
                    ) {
                        event.preventDefault();
                        LDD.openCase(caseId);
                    }
                }
            );
        });
}


function updateCaseStatistics(cases) {
    const caseCount =
        document.getElementById("case-count");

    const findingCount =
        document.getElementById("finding-count");

    const evidenceCount =
        document.getElementById("evidence-count");

    const mitreCount =
        document.getElementById("mitre-count");

    if (caseCount) {
        caseCount.textContent =
            cases.length;
    }

    /*
     * The remaining statistics are investigation-wide
     * values and are populated by the investigation
     * dashboard once a case is selected.
     *
     * Keep them at zero here rather than displaying
     * stale values from a previous case.
     */

    if (findingCount) {
        findingCount.textContent = "0";
    }

    if (evidenceCount) {
        evidenceCount.textContent = "0";
    }

    if (mitreCount) {
        mitreCount.textContent = "0";
    }
}


async function refreshCases() {
    await loadCases();

    if (
        typeof Detective !== "undefined" &&
        typeof Detective.speak === "function"
    ) {
        if (LDD.state.cases.length > 0) {
            Detective.speak(
                `${LDD.state.cases.length} case(s) are registered in the station.`
            );
        }
    }
}


document.addEventListener(
    "DOMContentLoaded",
    () => {
        loadCases();

        const refreshButton =
            document.getElementById(
                "refresh-cases"
            );

        if (refreshButton) {
            refreshButton.addEventListener(
                "click",
                refreshCases
            );
        }
    }
);
