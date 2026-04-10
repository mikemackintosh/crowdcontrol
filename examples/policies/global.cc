# global.cc — generic platform policies (NOT tied to any specific tool)
#
# These rules demonstrate the major CrowdControl features against a
# domain-agnostic resource shape:
#
#     {
#       "user":      { "name": "...", "groups": [...] },
#       "resource":  { "type": "...", "name": "...", "acl": "...", ... },
#       "request":   { "action": "...", "approved": bool, "approvers": [...] },
#       "plan":      { "changes": [...] }
#     }

forbid "no-public-storage" {
  description "Storage buckets must not be publicly readable"
  owner       "platform-security"
  link        "https://wiki.example.com/sec/public-buckets"

  resource.type == "storage_bucket"
  resource.acl in ["public-read", "public-read-write"]
  message "bucket {resource.name} would expose data publicly"
}

forbid "production-needs-approval" {
  description "Production changes require at least one approver"
  resource.environment == "production"
  request.approved == false
  unless user.groups contains "platform-oncall"
  message "production changes require approval (or oncall override)"
}

forbid "no-prod-deletes-by-interns" {
  description "Interns may not delete production resources"
  resource.environment == "production"
  request.action == "delete"
  user.groups contains "interns"
  message "{user.name} is an intern and cannot delete production resources"
}

warn "large-blast-radius" {
  description "Changes touching many resources should be split up"
  count(plan.changes) > 10
  message "this change touches {count(plan.changes)} resources — consider splitting"
}

warn "draft-mode" {
  description "Draft requests should not be merged"
  request.draft == true
  message "request is still in draft"
}

permit "platform-team-override" {
  description "Platform team may bypass other forbid rules for emergencies"
  user.groups contains "platform-oncall"
  request.labels contains "emergency"
  message "approved as emergency platform override"
}
