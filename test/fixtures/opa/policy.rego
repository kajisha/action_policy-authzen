package authzen

import rego.v1

default allow := false

allow if {
    input.subject.type == "user"
    input.subject.id in {"alice", "bob"}
    input.resource.type == "document"
    input.resource.id in {"one", "two"}
    input.action.name in {"read", "view"}
}

subjects contains subject if {
    subject := {"type": "user", "id": {"alice", "bob"}[_]}
    input.subject.type == subject.type
    allow with input.subject as subject
}

resources contains resource if {
    resource := {"type": "document", "id": {"one", "two"}[_]}
    input.resource.type == resource.type
    allow with input.resource as resource
}

actions contains action if {
    action := {"name": {"read", "view"}[_]}
    allow with input.action as action
}
