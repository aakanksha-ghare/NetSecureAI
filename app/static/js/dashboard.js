
const auditForm = document.getElementById("audit-form");
const auditButton = document.getElementById("audit-button");
const auditMessage = document.getElementById("audit-message");
const resultsSection = document.getElementById("results-section");
const findingsList = document.getElementById("findings-list");

const downloadButton = document.getElementById("download-report-button");
const reportMessage = document.getElementById("report-message");
const verificationConfig = document.getElementById("verification-config");
const verifyButton = document.getElementById("verify-evidence-button");
const verificationMessage = document.getElementById("verification-message");

let latestAudit = null;

function addTextElement(parent, tag, text, className = "") {
    const element = document.createElement(tag);
    element.textContent = text ?? "Not available";

    if (className) {
        element.className = className;
    }

    parent.appendChild(element);
    return element;
}

function addFindingDetail(card, label, value) {
    const paragraph = document.createElement("p");
    const labelElement = document.createElement("strong");

    labelElement.textContent = `${label}: `;
    paragraph.appendChild(labelElement);

    const valueElement = document.createElement("span");
    valueElement.textContent =
        value === null || value === undefined || value === ""
            ? "Not available"
            : Array.isArray(value)
                ? value.join(", ") || "None"
                : String(value);

    paragraph.appendChild(valueElement);
    card.appendChild(paragraph);
}

function renderFindings(findings) {
    findingsList.replaceChildren();

    if (!findings.length) {
        addTextElement(
            findingsList,
            "p",
            "No findings were returned by the audit."
        );
        return;
    }

    for (const finding of findings) {
        const card = document.createElement("article");
        const status = String(finding.status || "UNKNOWN").toLowerCase();

        card.className = `finding status-${status}`;

        addTextElement(
            card,
            "h3",
            `${finding.rule_id || "Rule"} — ${finding.title || "Untitled finding"}`
        );

        addTextElement(
            card,
            "p",
            `Status: ${finding.status || "UNKNOWN"} · Severity: ${finding.severity || "Not available"}`,
            "finding-status"
        );

        addFindingDetail(card, "Description", finding.description);
        addFindingDetail(card, "Evidence", finding.evidence);
        addFindingDetail(card, "Source lines", finding.source_lines);
        addFindingDetail(card, "Remediation", finding.remediation);

        const risk = finding.risk_assessment;

        if (risk) {
            addFindingDetail(
                card,
                "Assessed risk",
                `${risk.level || "Not assessed"}; score: ${risk.score ?? "N/A"}; rationale: ${risk.rationale || "Not provided"}`
            );
        } else {
            addFindingDetail(card, "Assessed risk", "Not assessed");
        }

        const mappings = finding.framework_mappings || [];

        if (mappings.length) {
            const mappingList = document.createElement("ul");

            for (const mapping of mappings) {
                const item = document.createElement("li");
                item.textContent =
                    `${mapping.framework || "Framework"} — ` +
                    `${mapping.control_id || "Control"}: ` +
                    `${mapping.control_title || "Untitled control"}`;
                mappingList.appendChild(item);
            }

            card.appendChild(mappingList);
        }

        findingsList.appendChild(card);
    }
}

function displayResults(data, vendor, config) {
    const findings = data.findings || [];

    const counts = {
        PASS: 0,
        FAIL: 0,
        UNKNOWN: 0,
    };

    for (const finding of findings) {
        if (Object.hasOwn(counts, finding.status)) {
            counts[finding.status] += 1;
        }
    }

    document.getElementById("total-count").textContent = findings.length;
    document.getElementById("pass-count").textContent = counts.PASS;
    document.getElementById("fail-count").textContent = counts.FAIL;
    document.getElementById("unknown-count").textContent = counts.UNKNOWN;

    document.getElementById("device-details").textContent =
        `${data.vendor || "Unknown vendor"} · ${data.device_type || "Device type unavailable"}`;

    const hash = data.configuration_hash || {};

    document.getElementById("configuration-hash").textContent =
        hash.digest
            ? `${hash.algorithm || "SHA-256"}: ${hash.digest}`
            : "Configuration hash unavailable.";

    const record = data.evidence_record || {};

    document.getElementById("evidence-record").textContent =
        record.record_id
            ? `Evidence record ID: ${record.record_id}`
            : "Evidence record unavailable.";

    verificationConfig.value = config;
    verificationMessage.textContent = "";
    verificationMessage.className = "message";
    reportMessage.textContent = "";
    reportMessage.className = "message";

    renderFindings(findings);
    resultsSection.hidden = false;

    latestAudit = {
        vendor,
        config,
        recordId: record.record_id,
    };

    verifyButton.disabled = !latestAudit.recordId;
    downloadButton.disabled = false;
}

auditForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const vendor = document.getElementById("vendor").value;
    const config = document.getElementById("config").value;

    if (!config.trim()) {
        auditMessage.textContent =
            "Enter a configuration before running the audit.";
        auditMessage.className = "message error";
        return;
    }

    auditButton.disabled = true;
    auditButton.textContent = "Auditing...";
    auditMessage.textContent = "Submitting configuration for analysis...";
    auditMessage.className = "message";
    resultsSection.hidden = true;
    latestAudit = null;

    try {
        const response = await fetch(
            `/api/audit/${encodeURIComponent(vendor)}`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body: JSON.stringify({ config }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `Audit failed (${response.status}).`);
        }

        displayResults(data, vendor, config);

        auditMessage.textContent = "Audit completed successfully.";
        auditMessage.className = "message success";
    } catch (error) {
        auditMessage.textContent =
            error.message || "An unexpected error occurred during the audit.";
        auditMessage.className = "message error";
    } finally {
        auditButton.disabled = false;
        auditButton.textContent = "Run security audit";
    }
});

downloadButton.addEventListener("click", async () => {
    if (!latestAudit) {
        reportMessage.textContent = "Run an audit before downloading a report.";
        reportMessage.className = "message error";
        return;
    }

    downloadButton.disabled = true;
    reportMessage.textContent = "Generating PDF report...";
    reportMessage.className = "message";

    try {
        const response = await fetch(
            `/api/audit/${encodeURIComponent(latestAudit.vendor)}/report`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/pdf, application/json",
                },
                body: JSON.stringify({ config: latestAudit.config }),
            }
        );

        if (!response.ok) {
            const data = await response.json().catch(() => ({}));
            throw new Error(data.error || `PDF generation failed (${response.status}).`);
        }

        const blob = await response.blob();

        if (blob.type !== "application/pdf") {
            throw new Error("The server did not return a PDF file.");
        }

        const objectUrl = URL.createObjectURL(blob);
        const link = document.createElement("a");

        link.href = objectUrl;
        link.download = `netsecureai-${latestAudit.vendor}-audit-report.pdf`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(objectUrl);

        reportMessage.textContent = "PDF report downloaded.";
        reportMessage.className = "message success";
    } catch (error) {
        reportMessage.textContent =
            error.message || "Could not download the PDF report.";
        reportMessage.className = "message error";
    } finally {
        downloadButton.disabled = false;
    }
});

verifyButton.addEventListener("click", async () => {
    if (!latestAudit?.recordId) {
        verificationMessage.textContent =
            "Run an audit before verifying configuration integrity.";
        verificationMessage.className = "message error";
        return;
    }

    verifyButton.disabled = true;
    verificationMessage.textContent = "Verifying SHA-256 fingerprint...";
    verificationMessage.className = "message";

    try {
        const response = await fetch(
            `/api/evidence/${encodeURIComponent(latestAudit.recordId)}/verify`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body: JSON.stringify({
                    configuration: verificationConfig.value,
                }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.error || `Verification failed (${response.status}).`
            );
        }

        verificationMessage.textContent = data.verified
            ? "VERIFIED — the supplied configuration matches the recorded SHA-256 fingerprint."
            : "MISMATCH — the supplied configuration does not match the recorded fingerprint.";

        verificationMessage.className = data.verified
            ? "message success"
            : "message error";
    } catch (error) {
        verificationMessage.textContent =
            error.message || "Could not verify configuration integrity.";
        verificationMessage.className = "message error";
    } finally {
        verifyButton.disabled = false;
    }
});

auditForm.addEventListener("reset", () => {
    resultsSection.hidden = true;
    findingsList.replaceChildren();
    auditMessage.textContent = "";
    auditMessage.className = "message";
    reportMessage.textContent = "";
    reportMessage.className = "message";
    verificationMessage.textContent = "";
    verificationMessage.className = "message";
    latestAudit = null;
    downloadButton.disabled = true;
    verifyButton.disabled = true;
});
