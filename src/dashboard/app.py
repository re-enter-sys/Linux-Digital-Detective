from pathlib import Path

from flask import Flask, render_template

from src.dashboard.routes import dashboard_api


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def create_app() -> Flask:
    """
    Create the Linux Digital Detective dashboard application.
    """

    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["PROJECT_ROOT"] = PROJECT_ROOT
    app.config["CASES_DIR"] = PROJECT_ROOT / "data" / "cases"

    @app.route("/")
    def index():
        return render_template("index.html")

    app.register_blueprint(dashboard_api)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
