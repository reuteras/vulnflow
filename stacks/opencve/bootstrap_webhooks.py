# Runs INSIDE the OpenCVE webserver container via `manage.py shell` on stdin;
# `python -m vulnflow opencve-webhook-input` prints the first line, defining the inputs, so
# the webhook token never appears on a command line:
#   VF = {"org": "<OPENCVE_ORG>", "projects": ["sysadm", ...], "name": "vulnflow",
#         "url": "http://vulnflow-receiver:8380/opencve", "headers": {"X-Vulnflow-Token": ...}}
# Checked against OpenCVE v3.1.0 (web/projects/models.py, web/projects/views.py,
# scheduler/dags/includes/tasks/automations/).
#
# Why the ORM and not the API: v3.1.0's API runs webhook URLs through an SSRF guard that
# rejects every private address, and has no allow-list (that only exists on master), so a
# receiver on OpenCVE's own docker network can't be configured through it. The Airflow
# sender does no such check. Only this fixed URL, set by the operator, goes in this way.
#
# In v3.1.0 a notification is only sent by an Automation with a send_notification action,
# so per project this ensures:
#   - Notification <name>: type webhook, configuration {"extras": {"url", "headers"}}
#     (the shape the UI's form saves), enabled;
#   - Automation <name>: trigger "alert", all v3.1.0 triggers, an empty AND condition
#     (matches every change), one action sending the notification, enabled.
# Idempotent; existing ones are updated in place (url/token kept in sync).
# Prints one line per project: WEBHOOK <project> created|updated, or MISSING <project>.
# ruff: noqa: F821  (VF is defined by the prepended line)
from django.db import transaction
from organizations.models import Organization
from projects.models import Automation, Notification, Project

# scheduler/dags/includes/tasks/automations/triggers.py, v3.1.0
TRIGGERS = [
    "cve_enters_project",
    "cvss_increased",
    "cvss_decreased",
    "epss_increased",
    "epss_decreased",
    "kev_added",
    "new_vendor",
    "new_product",
    "new_reference",
    "new_weakness",
    "description_changed",
    "title_changed",
]

name = VF.get("name") or "vulnflow"
org = Organization.objects.get(name=VF["org"])

with transaction.atomic():
    for project_name in VF["projects"]:
        project = Project.objects.filter(organization=org, name=project_name).first()
        if project is None:
            print(f"MISSING {project_name}")
            continue

        notification, created = Notification.objects.get_or_create(
            project=project, name=name, defaults={"type": "webhook"}
        )
        notification.type = "webhook"
        notification.is_enabled = True
        notification.configuration = {"extras": {"url": VF["url"], "headers": VF["headers"]}}
        notification.save()

        automation, _ = Automation.objects.get_or_create(project=project, name=name)
        automation.is_enabled = True
        automation.trigger_type = Automation.TRIGGER_ALERT
        automation.frequency = None
        automation.schedule_timezone = None
        automation.schedule_time = None
        automation.schedule_weekday = None
        automation.configuration = {
            "triggers": TRIGGERS,
            "conditions": {"operator": "AND", "children": []},
            "actions": [{"type": "send_notification", "value": str(notification.id)}],
        }
        automation.save()
        print(f"WEBHOOK {project_name} {'created' if created else 'updated'}")
