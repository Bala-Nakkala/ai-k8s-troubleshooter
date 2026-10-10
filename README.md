# AI-Assisted Kubernetes Troubleshooter

## 1. Project Overview

This project uses Python and Gemini AI to help troubleshoot Kubernetes application issues.

The tool collects selected Kubernetes Pod details and relevant error logs, filters sensitive information, and sends a diagnostic summary to Gemini AI.

Gemini analyzes the information and suggests possible causes and troubleshooting steps.

**The tool helps engineers investigate issues. It does not automatically fix the Kubernetes cluster.**

## 2. Why Do We Use This Project?

In a Kubernetes environment, engineers regularly troubleshoot issues such as:

* Pods restarting frequently.
* Applications failing to start.
* `CrashLoopBackOff`.
* `ImagePullBackOff`.
* `OOMKilled`.
* Application errors and connection failures.
* Kubernetes Events and probe failures.

Normally, engineers inspect these issues manually using `kubectl` commands and application logs.

This project uses AI to help interpret the collected information and suggest possible root causes.

## 3. Tools Used

| Tool                       | Purpose                                                       |
| -------------------------- | ------------------------------------------------------------- |
| Kubernetes                 | Runs containerized applications.                              |
| kubectl                    | Inspects Pods, Events, and cluster resources.                 |
| Python                     | Collects diagnostics and communicates with Gemini.            |
| Kubernetes Python Client   | Accesses Kubernetes API information.                          |
| Gemini AI API              | Analyzes diagnostic information and suggests possible causes. |
| Python Virtual Environment | Isolates project dependencies.                                |
| Git and GitHub             | Stores and versions the project code.                         |

## 4. How Does It Work?

```text
Kubernetes Cluster
        |
        v
Python Troubleshooting Script
        |
        v
Collect Pod Status and Selected Logs
        |
        v
Filter Unnecessary Information
        |
        v
Redact Sensitive Information
        |
        v
Send Sanitized Diagnostics to Gemini AI
        |
        v
Receive Possible Causes and Suggestions
        |
        v
Display and Save the Troubleshooting Report
```

### Workflow

1. The script connects to the Kubernetes cluster.
2. It collects selected Pod status, restart information, Events, and relevant log lines.
3. It filters unnecessary information.
4. It attempts to redact sensitive information.
5. It sends the prepared diagnostic information to Gemini AI.
6. Gemini suggests possible causes and troubleshooting steps.
7. The script displays the response and saves a local report.
8. The engineer verifies the suggestions using Kubernetes commands and other evidence.

## 5. Why Do We Use Gemini AI?

Gemini can help engineers:

* Understand error messages.
* Identify possible causes of Pod failures.
* Suggest useful diagnostic commands.
* Summarize complex error information.
* Reduce the time spent on initial troubleshooting.

**Important:** Gemini provides suggestions, not guaranteed root causes. Engineers must verify the findings.

## 6. Why Should We Not Send Raw Logs?

Raw application logs may contain sensitive information, including:

* Passwords.
* API keys and access tokens.
* Database credentials.
* Private keys.
* Customer information.
* Email addresses and phone numbers.
* Authentication headers.
* Internal infrastructure details.

For example, a raw log might contain:

```text
ERROR: Database connection failed
username=app_user
password=ExamplePassword123
Authorization: Bearer example-secret-token
```

This is only an illustrative example.

If we send raw logs to an external AI service, sensitive information may be disclosed to that service. Depending on the service and account terms, submitted data may be processed or retained. This can create security, privacy, compliance, and incident-response risks.

Even if Gemini does not repeat a secret in its answer, the secret has already been transmitted.

**Therefore, we should minimize the data collected and sanitize it before sending it to an external AI service.**

## 7. How Do We Protect Sensitive Information?

We can introduce several controls in the Python code.

### A. Collect Only Required Information

Do not collect everything from the Kubernetes cluster.

Collect only the information needed for troubleshooting, such as:

* Pod phase.
* Container state.
* Restart count.
* Termination reason.
* Selected Kubernetes Events.
* Relevant error messages.

Avoid collecting Kubernetes Secret objects, container environment-variable dumps, or entire configuration files.

### B. Select Relevant Log Lines

Instead of sending all application logs, select relevant error messages.

For example:

```text
ERROR: Database connection refused
ERROR: Application startup failed
```

This reduces unnecessary data, but an error line can still contain sensitive information.

### C. Redact Sensitive Values

Before sending data to Gemini, the Python script can replace detected sensitive values.

Example:

**Before redaction:**

```text
password=ExamplePassword123
Authorization: Bearer example-secret-token
```

**After redaction:**

```text
password=[REDACTED]
Authorization: Bearer [REDACTED]
```

Common ways to implement this include:

* Regular expressions.
* Secret-pattern detection.
* Allowlisting approved diagnostic fields.
* Removing or masking personal information.

### D. Check the Final Prompt

The application should prepare the final prompt only after filtering and redaction.

During development, test this process using synthetic logs and verify that sensitive test values do not appear in the outgoing prompt.

### E. Do Not Store API Keys in Source Code

Read the Gemini API key from an environment variable:

```python
import os

api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError("GEMINI_API_KEY is not configured")
```

Never commit the real API key to GitHub.

## 8. Is Redaction Enough?

No. Regular expressions cannot identify every possible secret.

Sensitive information may be:

* Written in an unexpected format.
* Encoded or split across multiple lines.
* Embedded in JSON or stack traces.
* Included in application-specific messages.

Therefore, the safer approach is:

1. Minimize the data collected.
2. Collect only approved diagnostic fields.
3. Filter unnecessary log lines.
4. Redact common sensitive patterns.
5. Validate the final prompt.
6. Send only the minimum required information.

**Redaction reduces risk, but it does not guarantee that every secret will be removed.**

## 9. Gemini API Data Considerations

Data handling depends on the specific Google service, account, and applicable terms.

For example, Google's published terms distinguish between unpaid Gemini API services and paid services. Unpaid services may use submitted prompts and responses to improve Google products, and human reviewers may process them. Paid services generally have different data-use terms, including restrictions on using prompts and responses to improve Google's products, subject to the applicable terms and exceptions.

Before using real production data, review the current official documentation:

* [Gemini API Terms of Service](https://ai.google.dev/gemini-api/terms)
* [Gemini API Usage Policies](https://ai.google.dev/gemini-api/docs/usage-policies)

For a learning project, use synthetic or sanitized logs. Never assume that production data is safe to send without organizational approval.

## 10. Example Troubleshooting Use Cases

| Kubernetes Issue            | Information to Investigate                               |
| --------------------------- | -------------------------------------------------------- |
| CrashLoopBackOff            | Container state, previous logs, restart count, Events    |
| ImagePullBackOff            | Image name, tag, and Pod Events                          |
| OOMKilled                   | Termination reason, memory limits, resource metrics      |
| Probe failures              | Probe configuration, application health endpoint, Events |
| Pending Pod                 | Scheduling Events, resource requests, node conditions    |
| HTTP 503                    | Service endpoints, Pod readiness, Ingress configuration  |
| Database connection failure | Sanitized error message and dependency health            |

Gemini can suggest possible causes and useful commands based on the available information.

It cannot reliably diagnose every issue from Pod logs alone. Some problems require metrics, network information, deployment history, or dependency logs.

## 11. Production Improvements

Before adapting this proof of concept for production, consider:

* Least-privilege Kubernetes RBAC.
* Strict data allowlisting.
* Reliable secret scanning and redaction.
* Approved AI service and data-handling terms.
* Secure report storage and retention.
* API timeouts and bounded retries.
* Request limits and cost controls.
* Audit logging without recording secrets.
* Human approval before remediation.
* Testing for sensitive-data leakage and incorrect AI suggestions.

The AI should not independently execute destructive Kubernetes commands.

## 12. Key Takeaways

* Kubernetes provides operational information.
* Python collects and prepares the diagnostic data.
* Gemini AI helps interpret the information.
* Raw logs can contain passwords, tokens, customer data, and other sensitive details.
* Filtering and redaction reduce the amount of sensitive information sent.
* Redaction is not perfect, so data minimization is essential.
* Gemini suggestions must be verified by an engineer.
* This project is a learning proof of concept, not a production-ready troubleshooting platform.

**Project:** AI-Assisted Kubernetes Troubleshooter
**Technologies:** Kubernetes, Python, Gemini AI API
**Purpose:** AI-assisted diagnosis of Kubernetes application issues
