async function loadDashboard() {
    const detectiveMessage =
        document.getElementById(
            "detective-message"
        );

    try {
        await loadCases();

        if (
            detectiveMessage &&
            LDD.state.cases.length > 0
        ) {
            const active =
                LDD.state.cases.find(
                    (item) =>
                        String(item.status)
                            .toUpperCase() !==
                        "CLOSED"
                );

            if (active) {
                detectiveMessage.textContent =
                    `${active.case_id || "CASE"} requires investigation.`;
            } else {
                detectiveMessage.textContent =
                    "All available cases are closed.";
            }
        } else if (detectiveMessage) {
            detectiveMessage.textContent =
                "Find the first suspicious event.";
        }
    } catch (error) {
        console.error(
            "Linux Digital Detective: dashboard initialization failed.",
            error
        );

        if (detectiveMessage) {
            detectiveMessage.textContent =
                "Investigation system is waiting for case data.";
        }
    }
}


async function refreshDashboard() {
    await loadDashboard();
}


document.addEventListener(
    "DOMContentLoaded",
    () => {
        loadDashboard();
    }
);
