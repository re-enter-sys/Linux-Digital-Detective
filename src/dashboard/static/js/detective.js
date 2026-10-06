const Detective = {
    messages: [
        "Evidence never lies. People sometimes do.",
        "Start with the timeline.",
        "Find the first suspicious event.",
        "Follow the attacker, not just the alert.",
        "WHO → WHAT → WHEN → FROM WHERE → HOW.",
        "Correlation turns events into an attack story.",
        "Preserve evidence before interpreting it."
    ],

    speak(message = null) {
        const target =
            document.getElementById(
                "detective-message"
            );

        if (!target) {
            return;
        }

        const selected =
            message ||
            this.messages[
                Math.floor(
                    Math.random() *
                    this.messages.length
                )
            ];

        target.textContent =
            selected;
    },

    inspectCase() {
        if (LDD.state.cases.length === 0) {
            this.speak(
                "There are no cases to inspect."
            );
            return;
        }

        const active =
            LDD.state.cases.find(
                (item) =>
                    String(item.status)
                        .toUpperCase() !==
                    "CLOSED"
            );

        if (!active) {
            this.speak(
                "Every case in the station archive is closed."
            );
            return;
        }

        this.speak(
            `Case ${active.case_id} is waiting in Cell 01.`
        );

        LDD.openCase(
            active.case_id
        );
    }
};

document.addEventListener(
    "DOMContentLoaded",
    () => {
        const detective =
            document.getElementById(
                "detective-card"
            );

        if (detective) {
            detective.addEventListener(
                "click",
                () => {
                    Detective.speak();
                }
            );
        }
    }
);
