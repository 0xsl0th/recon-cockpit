"""Data-only session proposal validation, with no controller or execution API."""

from .models import ValidationError, load_json


def _plan(raw):
    plan = load_json(raw)
    if (set(plan) != {"schema_version", "action", "done"} or plan["schema_version"] != "1"
            or type(plan["done"]) is not bool
            or (plan["action"] is None and not plan["done"])
            or (plan["action"] is not None and type(plan["action"]) is not dict)):
        raise ValidationError("invalid_session_proposal")
    return plan
