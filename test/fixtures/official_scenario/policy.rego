package authzen

import rego.v1

default allow := false

subjects_fixture := [
    {"type": "user", "id": "alice"},
    {"type": "user", "id": "bob", "properties": {"role": "admin"}},
]

resources_fixture := [
    {"type": "record", "id": "record-1", "properties": {"status": "active"}},
    {"type": "record", "id": "record-2", "properties": {"status": "archived"}},
]

actions_fixture := [
    {"name": "read"},
    {"name": "write"},
]

decision_rule_1 if {
    input.subject.type == "user"
    input.subject.id == "alice"
    input.action.name == "read"
    input.resource.type == "record"
    input.resource.id == "record-1"
}

decision_rule_2 if {
    input.subject.type == "user"
    input.subject.id == "alice"
    input.action.name == "write"
    input.resource.type == "record"
    input.resource.id == "record-1"
}

decision_rule_3 if {
    input.subject.type == "user"
    input.subject.id == "bob"
    input.action.name == "read"
    input.resource.type == "record"
    input.resource.id == "record-1"
}

decision_rule_5 if {
    input.subject.type == "user"
    input.subject.id == "alice"
    input.action.name == "write"
    input.resource.type == "record"
    input.resource.properties.status == "archived"
}

decision_rule_6 if {
    input.subject.type == "user"
    input.subject.properties.role == "admin"
    input.action.name == "write"
    input.resource.type == "record"
    input.resource.properties.status == "archived"
}

decision_rule_7 if {
    input.subject.type == "user"
    input.subject.id == "alice"
    input.action.name == "delete"
    input.action.properties.soft == true
    input.resource.type == "record"
    input.resource.id == "record-1"
}

allow if decision_rule_1

allow if {
    decision_rule_2
    not decision_rule_5
}

allow if decision_rule_3

allow if {
    input.subject.type == "user"
    input.subject.id == "alice"
    input.action.name == "write"
    input.resource.type == "record"
    input.resource.properties.status == "active"
}

allow if decision_rule_6

allow if decision_rule_7

subjects contains subject if {
    subject := subjects_fixture[_]
    input.subject.type == subject.type
    allow with input.subject as subject
}

resources contains resource if {
    resource := resources_fixture[_]
    input.resource.type == resource.type
    allow with input.resource as resource
}

actions contains action if {
    action := actions_fixture[_]
    allow with input.action as action
}
