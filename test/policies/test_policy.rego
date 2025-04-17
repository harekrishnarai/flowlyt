package flowlyt

# Test policy to enforce specific runner types
deny[violation] {
    job := input.workflow.jobs[job_name]
    not job["runs-on"] == "ubuntu-latest"
    
    violation := {
        "id": "TEST_POLICY_RUNNER_TYPE",
        "name": "Non-Standard Runner",
        "description": "Job uses a non-standard runner. Only ubuntu-latest is allowed.",
        "severity": "MEDIUM",
        "job": job_name,
        "evidence": sprintf("runs-on: %v", [job["runs-on"]]),
        "remediation": "Use 'ubuntu-latest' runner for consistency"
    }
}

# Test policy to enforce minimum Node.js version
deny[violation] {
    job := input.workflow.jobs[job_name]
    step := job.steps[_]
    step.uses
    startswith(step.uses, "actions/setup-node")
    
    step.with.node-version
    version := to_number(step.with.node-version)
    version < 16
    
    violation := {
        "id": "TEST_POLICY_NODE_VERSION",
        "name": "Outdated Node.js Version",
        "description": "Node.js version is too old. Minimum version should be 16.",
        "severity": "HIGH",
        "job": job_name,
        "step": step.name,
        "evidence": sprintf("node-version: %v", [step.with.node-version]),
        "remediation": "Update to Node.js 16 or newer"
    }
}