# Runs INSIDE the OpenCVE webserver container via `manage.py shell` on stdin;
# poc.sh opencve-bootstrap prepends one line defining the inputs, so secrets never
# appear on a command line:
#   VF = {"org": "<OPENCVE_ORG>", "user": "vulnflow", "token": "<current OPENCVE_TOKEN>",
#         "admin": {"username": ..., "email": ..., "password": ...}}
# Checked against OpenCVE v3.1.0 models.
#
# Idempotent. Ensures:
#   - the human admin (superuser, email pre-verified like upstream's install.sh does), created
#     only if that username doesn't exist yet; an existing user is never modified;
#   - a non-login service user and the organization, with both users as owners;
#   - a read-write organization API token for the service user.
# Prints exactly one of
#   OPENCVE_TOKEN_OK=1          the current token still works
#   OPENCVE_TOKEN=opc_org.x.y   a new token (older 'vulnflow' tokens are revoked)
# and ADMIN_CREATED=1 when it created the admin.
# ruff: noqa: F821  (VF is defined by the prepended line)
from allauth.account.models import EmailAddress
from django.db import transaction
from django.utils import timezone
from organizations.models import Membership, Organization, OrganizationAPIToken
from users.models import User

TOKEN_NAME = "vulnflow"  # noqa: S105 - the token's display name, not a secret
org_name = VF["org"]
username = VF.get("user") or "vulnflow"
existing = VF.get("token") or ""
admin = VF.get("admin") or {}
WRITE = OrganizationAPIToken.AccessMode.WRITE


def token_valid(org, raw):
    parts = raw.split(".")
    if len(parts) != 3 or parts[0] != OrganizationAPIToken.TOKEN_PREFIX:
        return False
    tok = OrganizationAPIToken.objects.filter(
        token_id=parts[1], organization=org, is_active=True
    ).first()
    return bool(tok and tok.access_mode == WRITE and tok.verify_token(parts[2]))


def ensure_owner(user, org):
    membership, _ = Membership.objects.get_or_create(
        user=user, organization=org, defaults={"role": Membership.OWNER, "date_joined": timezone.now()}
    )
    if membership.role != Membership.OWNER or membership.date_joined is None:
        membership.role = Membership.OWNER
        membership.date_joined = membership.date_joined or timezone.now()
        membership.save()


with transaction.atomic():
    org, _ = Organization.objects.get_or_create(name=org_name)

    if admin.get("username") and admin.get("password"):
        human = User.objects.filter(username=admin["username"]).first()
        if human is None:
            human = User.objects.create_superuser(admin["username"], admin["email"], admin["password"])
            # ACCOUNT_EMAIL_VERIFICATION is "mandatory"; install.sh's create-superuser
            # marks the address verified the same way (account_emailaddress row).
            EmailAddress.objects.get_or_create(
                user=human, email=admin["email"], defaults={"verified": True, "primary": True}
            )
            print("ADMIN_CREATED=1")
        ensure_owner(human, org)

    user, created = User.objects.get_or_create(
        username=username, defaults={"email": f"{username}@localhost.invalid"}
    )
    if created:
        user.set_unusable_password()  # service account: API token only, no UI login
        user.save()
    ensure_owner(user, org)

    if existing and token_valid(org, existing):
        print("OPENCVE_TOKEN_OK=1")
    else:
        for old in OrganizationAPIToken.objects.filter(
            organization=org, name=TOKEN_NAME, is_active=True
        ):
            old.revoke(revoked_by=user)
        raw = OrganizationAPIToken.create_token(
            organization=org,
            name=TOKEN_NAME,
            description="vulnflow glue (created by poc.sh opencve-bootstrap)",
            created_by=user,
            access_mode=WRITE,
        )
        print(f"OPENCVE_TOKEN={raw}")
