# quickstart.cc — the smallest meaningful CrowdControl policy
#
# Run with: cc evaluate --policy ./examples --input ./examples/demo/input.json

forbid "no-public-buckets" {
  description "Storage buckets must not be publicly readable"
  resource.type == "storage_bucket"
  resource.acl == "public-read"
  message "bucket {resource.name} would be public-read"
}

warn "large-changeset" {
  description "Changesets touching more than 5 resources need extra review"
  count(plan.changes) > 5
  message "this change touches {count(plan.changes)} resources"
}
