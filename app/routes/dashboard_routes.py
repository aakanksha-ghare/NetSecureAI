
from flask import Blueprint, render_template

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.get("/")
def dashboard():
    """Render the NetSecureAI dashboard."""
    return render_template("dashboard.html")
