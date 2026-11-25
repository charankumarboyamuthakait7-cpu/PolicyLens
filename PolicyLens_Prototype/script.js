
const roleMenus = {
    Admin: [
        ["Dashboard", "▦"],
        ["Documents", "▯"],
        ["Upload", "⇧"],
        ["AI Assistant", "◷"],
        ["Compare clauses", "⟷"],
        ["Question history", "◷"],
        ["Compliance findings", "⚑"],
        ["Users", "♙"],
        ["Departments", "▤"],
        ["Permissions", "♙"],
        ["Compliance rules", "◇"],
        ["Audit history", "◷"]
    ],

    Analyst: [
        ["Dashboard", "▦"],
        ["Documents", "▯"],
        ["Upload", "⇧"],
        ["AI Assistant", "◷"],
        ["Compare clauses", "⟷"],
        ["Question history", "◷"],
        ["Compliance findings", "⚑"]
    ],

    Reviewer: [
        ["Dashboard", "▦"],
        ["Assigned findings", "⚑"],
        ["Review history", "◷"]
    ]
};

let currentRole = "Admin";
let currentPage = "Dashboard";

const sampleDocuments = [
    ["DOC-001", "Employee Agreement.pdf", "Human Resources", "Approved"],
    ["DOC-002", "Data Privacy Policy.pdf", "IT Department", "Approved"],
    ["DOC-003", "Vendor Service Agreement.pdf", "Procurement", "Pending"]
];

const sampleFindings = [
    ["FND-101", "Missing termination clause", "High", "Pending"],
    ["FND-102", "Data retention period", "Medium", "Under Review"],
    ["FND-103", "Unclear payment obligations", "High", "Pending"]
];


/* Enter demo application */

function enterDemo() {
    
    currentRole = document.getElementById("roleSelect").value;

    document.getElementById("loginScreen").classList.add("hidden");
    document.getElementById("appScreen").classList.remove("hidden");

    document.getElementById("userContext").textContent =
        (currentRole === "Admin"
            ? "System Administrator"
            : "Demo " + currentRole)
        + " · " + currentRole;

    buildNavigation();
    showPage("Dashboard");
}


/* Build role-based sidebar */

function buildNavigation() {
    const nav = document.getElementById("navigation");
    nav.innerHTML = "";

    roleMenus[currentRole].forEach(([label, icon]) => {
        const button = document.createElement("button");

        button.className = "nav-item";

        button.innerHTML = `
            <span class="nav-icon" aria-hidden="true">${icon}</span>
            <span>${label}</span>
        `;

        button.addEventListener("click", () => showPage(label));
        nav.appendChild(button);
    });
}


/* Navigate between pages */

function showPage(page) {
    currentPage = page;

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.textContent.trim() === page
        );
    });

    const content = document.getElementById("pageContent");

    const pages = {
        "Dashboard": dashboardPage,
        "Documents": documentLibraryPage,
        "Document Library": documentLibraryPage,
        "Upload": uploadPage,
        "Document Upload": uploadPage,
        "AI Assistant": assistantPage,
        "Compare clauses": comparisonPage,
        "Document Comparison": comparisonPage,
        "Question history": questionHistoryPage,
        "Compliance findings": findingsPage,
        "Compliance Findings": findingsPage,
        "Assigned findings": findingsPage,
        "Assigned Findings": findingsPage,
        "Review history": historyPage,
        "Review History": historyPage,
        "Users": usersPage,
        "User Management": usersPage,
        "Departments": departmentsPage,
        "Permissions": permissionsPage,
        "Compliance rules": complianceRulesPage,
        "Audit history": auditPage,
        "Audit Logs": auditPage
    };

    content.innerHTML = (pages[page] || dashboardPage)();

    if (page === "Dashboard") {
        document.querySelectorAll(".nav-item").forEach(button => {
            button.classList.toggle(
                "active",
                button.textContent.trim() === "Dashboard"
            );
        });
    }
}


/* Dashboard */

function dashboardPage() {
    if (currentRole === "Admin") {
        return `
            <section class="dashboard-hero">
                <h1>Administration overview</h1>
                <p>
                    You manage users, departments, documents and access
                    for the whole organization.
                </p>
            </section>

            <div class="quick-actions">
                <button class="quick-primary"
                    onclick="showPage('Upload')">
                    Upload document
                </button>

                <button onclick="showPage('Documents')">
                    Browse documents
                </button>

                <button onclick="showPage('AI Assistant')">
                    Ask PolicyLens
                </button>

                <button onclick="showPage('Compliance findings')">
                    Compliance findings
                </button>
            </div>

            <section class="stats-grid">
                ${statCard("Accessible documents", "13")}
                ${statCard("Agreements", "7")}
                ${statCard("Policies", "6")}
                ${statCard("Awaiting indexing", "0")}
                ${statCard("Failed processing", "0")}
                ${statCard("Open compliance findings", "1")}
                ${statCard("Users (active)", "10 / 11")}
                ${statCard("Departments", "6")}
                ${statCard("Audit events", "213")}
            </section>
        `;
    }

    const stats = currentRole === "Analyst"
        ? [
            ["My documents", "18"],
            ["Processed", "15"],
            ["Findings", "8"],
            ["Comparisons", "4"]
        ]
        : [
            ["Assigned findings", "6"],
            ["Pending review", "3"],
            ["Reviewed", "12"],
            ["Comments", "9"]
        ];

    return `
        <section class="dashboard-hero">
            <h1>${currentRole} overview</h1>
            <p>
                ${currentRole === "Analyst"
                    ? "Review documents, ask PolicyLens and identify compliance findings."
                    : "Review assigned compliance findings and track review activity."
                }
            </p>
        </section>

        <div class="quick-actions">
            ${currentRole === "Analyst"
                ? `
                    <button class="quick-primary"
                        onclick="showPage('Upload')">
                        Upload document
                    </button>
                    <button onclick="showPage('Documents')">
                        Browse documents
                    </button>
                    <button onclick="showPage('AI Assistant')">
                        Ask PolicyLens
                    </button>
                `
                : `
                    <button class="quick-primary"
                        onclick="showPage('Assigned findings')">
                        View assigned findings
                    </button>
                    <button onclick="showPage('Review history')">
                        Review history
                    </button>
                `
            }
        </div>

        <section class="stats-grid">
            ${stats.map(item =>
                statCard(item[0], item[1])
            ).join("")}
        </section>
    `;
}


/* Reusable statistic card */

function statCard(label, value) {
    return `
        <div class="stat-card">
            <p>${label}</p>
            <h2>${value}</h2>
        </div>
    `;
}


/* Reusable page heading */

function pageHeading(title, description) {
    return `
        <div class="page-heading">
            <h1>${title}</h1>
            <p>${description}</p>
        </div>
    `;
}


/* Document library */

function documentLibraryPage() {
    const rows = sampleDocuments.map(doc => `
        <tr>
            <td>${doc[0]}</td>
            <td>${doc[1]}</td>
            <td>${doc[2]}</td>
            <td>
                <span class="status ${doc[3] === "Pending" ? "pending" : ""}">
                    ${doc[3]}
                </span>
            </td>
            <td>
                <button class="small-btn"
                    onclick="notify('Sample document preview opened.')">
                    View
                </button>
            </td>
        </tr>
    `).join("");

    return `
        ${pageHeading(
            "Documents",
            "Browse organizational contracts and policies available in this demo."
        )}

        <div class="info-box">
            This library contains fictional sample documents.
            No real company documents are connected.
        </div>

        <div class="panel">
            <div class="panel-header">
                <h3>Available documents</h3>
                <button class="secondary-btn"
                    onclick="notify('Sample document list refreshed.')">
                    Refresh
                </button>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Document ID</th>
                            <th>Document name</th>
                            <th>Department</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        </div>
    `;
}


/* Document upload */

function uploadPage() {
    return `
        ${pageHeading(
            "Upload",
            "Add a contract or policy to the demo workspace."
        )}

        <div class="info-box">
            The upload workflow is simulated.
            The selected file is not sent to a server or stored.
        </div>

        <div class="panel">
            <h3>Upload a document</h3>

            <div class="form-group">
                <label>Document name</label>
                <input id="docName" type="text"
                    placeholder="Enter document name">
            </div>

            <div class="form-group">
                <label>Department</label>
                <select id="docDepartment">
                    <option>Human Resources</option>
                    <option>Information Technology</option>
                    <option>Finance</option>
                    <option>Legal</option>
                    <option>Procurement</option>
                </select>
            </div>

            <div class="form-group">
                <label>Select PDF</label>
                <input type="file" accept=".pdf" id="demoFile">
            </div>

            <button class="primary-btn" onclick="simulateUpload()">
                Simulate upload
            </button>
        </div>
    `;
}


/* AI assistant */

function assistantPage() {
    return `
        ${pageHeading(
            "AI Assistant",
            "Ask questions about an example contract or policy."
        )}

        <div class="info-box">
            This is a visual simulation.
            It does not connect to the live PolicyLens AI model,
            vector database or real documents.
        </div>

        <div class="panel">
            <h3>Ask PolicyLens</h3>

            <div class="form-group">
                <label>Select document</label>
                <select id="assistantDocument">
                    <option>Employee Agreement.pdf</option>
                    <option>Data Privacy Policy.pdf</option>
                    <option>Vendor Service Agreement.pdf</option>
                </select>
            </div>

            <div class="chat-box" id="chatBox">
                <div class="chat-message">
                    <strong>PolicyLens Assistant</strong>
                    <br>
                    Hello! Ask a question to see an illustrative response.
                </div>
            </div>

            <div class="form-group">
                <label>Your question</label>
                <textarea id="assistantQuestion"
                    placeholder="Ask a question about the selected document..."></textarea>
            </div>

            <button class="primary-btn" onclick="simulateQuestion()">
                Ask question
            </button>
        </div>
    `;
}


/* Document comparison */

function comparisonPage() {
    return `
        ${pageHeading(
            "Compare clauses",
            "Compare clauses from two example documents."
        )}

        <div class="info-box">
            The comparison is simulated and does not analyse
            actual PDF contents.
        </div>

        <div class="panel">
            <h3>Select documents to compare</h3>

            <div class="form-group">
                <label>First document</label>
                <select id="compareOne">
                    <option>Employee Agreement.pdf</option>
                    <option>Data Privacy Policy.pdf</option>
                </select>
            </div>

            <div class="form-group">
                <label>Second document</label>
                <select id="compareTwo">
                    <option>Vendor Service Agreement.pdf</option>
                    <option>Data Privacy Policy.pdf</option>
                </select>
            </div>

            <button class="primary-btn" onclick="simulateComparison()">
                Compare documents
            </button>

            <div id="comparisonResult"></div>
        </div>
    `;
}


/* Compliance findings */

function findingsPage() {
    const rows = sampleFindings.map(item => `
        <tr>
            <td>${item[0]}</td>
            <td>${item[1]}</td>
            <td>${item[2]}</td>
            <td>
                <span class="status ${item[3] === "Pending" ? "pending" : "review"}">
                    ${item[3]}
                </span>
            </td>
            <td>
                <button class="small-btn"
                    onclick="notify('Sample finding details opened.')">
                    View
                </button>
            </td>
        </tr>
    `).join("");

    return `
        ${pageHeading(
            currentPage,
            "Review example compliance findings and their current status."
        )}

        <div class="panel">
            <div class="panel-header">
                <h3>Sample findings</h3>

                ${currentRole === "Analyst"
                    ? '<button class="primary-btn" onclick="showFindingForm()">Create finding</button>'
                    : ''
                }
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Finding ID</th>
                            <th>Description</th>
                            <th>Severity</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>

            <div id="findingForm"></div>
        </div>
    `;
}


/* Finding creation form */

function showFindingForm() {
    document.getElementById("findingForm").innerHTML = `
        <div class="panel">
            <h3>Create sample finding</h3>

            <div class="form-group">
                <label>Finding description</label>
                <textarea id="findingDescription"
                    placeholder="Describe the compliance finding"></textarea>
            </div>

            <div class="form-group">
                <label>Severity</label>
                <select id="findingSeverity">
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                </select>
            </div>

            <button class="primary-btn" onclick="simulateFinding()">
                Submit demo finding
            </button>
        </div>
    `;
}


/* Question history */

function questionHistoryPage() {
    return `
        ${pageHeading(
            "Question history",
            "Example questions previously asked in the PolicyLens assistant."
        )}

        <div class="panel">
            <h3>Recent questions</h3>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Question</th>
                            <th>Document</th>
                            <th>Date</th>
                            <th>Sources</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>What is the termination notice period?</td>
                            <td>Employee Agreement.pdf</td>
                            <td>25 Nov 2026</td>
                            <td>Page 4</td>
                        </tr>
                        <tr>
                            <td>How long is personal data retained?</td>
                            <td>Data Privacy Policy.pdf</td>
                            <td>24 Nov 2026</td>
                            <td>Page 7</td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* Reviewer history */

function historyPage() {
    return `
        ${pageHeading(
            "Review history",
            "View example review activities completed by the reviewer."
        )}

        <div class="panel">
            <h3>Completed review activities</h3>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Finding ID</th>
                            <th>Activity</th>
                            <th>Reviewer</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>FND-090</td>
                            <td>Reviewed finding</td>
                            <td>Demo Reviewer</td>
                            <td><span class="status">Completed</span></td>
                        </tr>
                        <tr>
                            <td>FND-092</td>
                            <td>Comment added</td>
                            <td>Demo Reviewer</td>
                            <td><span class="status review">Reviewed</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* User management */

function usersPage() {
    return `
        ${pageHeading(
            "Users",
            "Manage example users and their assigned roles."
        )}

        <div class="panel">
            <div class="panel-header">
                <h3>Users</h3>
                <button class="primary-btn"
                    onclick="notify('Demo: Add user form opened.')">
                    Add user
                </button>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Role</th>
                            <th>Department</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Demo Admin</td>
                            <td>Admin</td>
                            <td>Administration</td>
                            <td><span class="status">Active</span></td>
                            <td><button class="small-btn"
                                onclick="notify('Sample user details opened.')">View</button></td>
                        </tr>
                        <tr>
                            <td>Demo Analyst</td>
                            <td>Analyst</td>
                            <td>Legal</td>
                            <td><span class="status">Active</span></td>
                            <td><button class="small-btn"
                                onclick="notify('Sample user details opened.')">View</button></td>
                        </tr>
                        <tr>
                            <td>Demo Reviewer</td>
                            <td>Reviewer</td>
                            <td>Compliance</td>
                            <td><span class="status">Active</span></td>
                            <td><button class="small-btn"
                                onclick="notify('Sample user details opened.')">View</button></td>
                        </tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* Departments */

function departmentsPage() {
    return `
        ${pageHeading(
            "Departments",
            "View the departments configured in this sample organization."
        )}

        <div class="panel">
            <div class="panel-header">
                <h3>Organization departments</h3>
                <button class="primary-btn"
                    onclick="notify('Demo: Add department form opened.')">
                    Add department
                </button>
            </div>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Department</th>
                            <th>Department code</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Human Resources</td><td>HR</td><td><span class="status">Active</span></td></tr>
                        <tr><td>Information Technology</td><td>IT</td><td><span class="status">Active</span></td></tr>
                        <tr><td>Finance</td><td>FIN</td><td><span class="status">Active</span></td></tr>
                        <tr><td>Legal</td><td>LEG</td><td><span class="status">Active</span></td></tr>
                        <tr><td>Procurement</td><td>PRO</td><td><span class="status">Active</span></td></tr>
                        <tr><td>Compliance</td><td>COM</td><td><span class="status">Active</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* Permissions */

function permissionsPage() {
    return `
        ${pageHeading(
            "Permissions",
            "Review the illustrative access levels assigned to each role."
        )}

        <div class="panel">
            <h3>Role permission overview</h3>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Role</th>
                            <th>View</th>
                            <th>Ask</th>
                            <th>Edit</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Admin</td><td>All authorized documents</td><td>Yes</td><td>Yes</td></tr>
                        <tr><td>Analyst</td><td>Authorized documents</td><td>Yes</td><td>Limited</td></tr>
                        <tr><td>Reviewer</td><td>Assigned documents</td><td>As permitted</td><td>No</td></tr>
                    </tbody>
                </table>
            </div>

            <p class="muted">
                This table is illustrative and does not change actual application permissions.
            </p>
        </div>
    `;
}


/* Compliance rules */

function complianceRulesPage() {
    return `
        ${pageHeading(
            "Compliance rules",
            "Explore sample rules used to identify potential contract and policy issues."
        )}

        <div class="panel">
            <h3>Configured sample rules</h3>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Rule ID</th>
                            <th>Rule name</th>
                            <th>Category</th>
                            <th>Severity</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>RULE-001</td><td>Termination clause required</td><td>Contract terms</td><td>High</td><td><span class="status">Enabled</span></td></tr>
                        <tr><td>RULE-002</td><td>Data retention period</td><td>Data privacy</td><td>Medium</td><td><span class="status">Enabled</span></td></tr>
                        <tr><td>RULE-003</td><td>Payment obligations defined</td><td>Financial</td><td>High</td><td><span class="status">Enabled</span></td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* Audit history */

function auditPage() {
    return `
        ${pageHeading(
            "Audit history",
            "Review example activity records from the demo environment."
        )}

        <div class="panel">
            <h3>Sample audit events</h3>

            <div class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Activity</th>
                            <th>Module</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Demo Admin</td><td>User management viewed</td><td>Administration</td><td>25 Nov 2026</td></tr>
                        <tr><td>Demo Analyst</td><td>Document upload simulated</td><td>Documents</td><td>25 Nov 2026</td></tr>
                        <tr><td>Demo Reviewer</td><td>Review page opened</td><td>Compliance</td><td>24 Nov 2026</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    `;
}


/* Upload simulation */

function simulateUpload() {
    const name = document.getElementById("docName").value.trim();
    const file = document.getElementById("demoFile").files[0];

    if (!name || !file) {
        notify("Please enter a document name and select a sample PDF.");
        return;
    }

    notify("Demo upload completed. No file was saved.");
}


/* AI question simulation */

function simulateQuestion() {
    const question = document.getElementById("assistantQuestion").value.trim();
    const chatBox = document.getElementById("chatBox");

    if (!question) {
        notify("Please enter a question.");
        return;
    }

    const message = document.createElement("div");
    message.className = "chat-message";

    const response = document.createElement("div");

    response.innerHTML = `
        <strong>Sample response</strong>
        <br>
        This is a simulated response for demonstration purposes.
        The live PolicyLens assistant can retrieve information
        from authorized documents and provide source citations.
        <br><br>
        <strong>Sample source:</strong>
        Employee Agreement.pdf, Page 4
    `;

    message.appendChild(response);
    chatBox.appendChild(message);

    document.getElementById("assistantQuestion").value = "";

    notify("Sample AI response displayed.");
}


/* Document comparison simulation */

function simulateComparison() {
    const first = document.getElementById("compareOne").value;
    const second = document.getElementById("compareTwo").value;

    if (first === second) {
        notify("Please select two different documents.");
        return;
    }

    document.getElementById("comparisonResult").innerHTML = `
        <div class="info-box" style="margin-top:20px;">
            <strong>Sample comparison completed</strong>
            <br>
            Document 1: ${first}
            <br>
            Document 2: ${second}
            <br><br>
            This is an illustrative comparison.
            No actual document analysis was performed.
        </div>
    `;
}


/* Finding simulation */

function simulateFinding() {
    const description =
        document.getElementById("findingDescription").value.trim();

    if (!description) {
        notify("Please enter a finding description.");
        return;
    }

    notify("Demo finding submitted. No record was saved.");
}


/* Notification message */

function notify(message) {
    const toast = document.getElementById("toast");

    toast.textContent = message;
    toast.style.display = "block";

    clearTimeout(window.demoToastTimer);

    window.demoToastTimer = setTimeout(() => {
        toast.style.display = "none";
    }, 3000);
}


/* Exit demo */

function logout() {
    document.getElementById("appScreen").classList.add("hidden");
    document.getElementById("loginScreen").classList.remove("hidden");
    document.getElementById("roleSelect").value = "Admin";
}
document.addEventListener("DOMContentLoaded", function () {

    const exploreButton = document.getElementById("exploreDemoBtn");
    const logoutButton = document.getElementById("logoutBtn");

    if (exploreButton) {
        exploreButton.addEventListener("click", enterDemo);
    }

    if (logoutButton) {
        logoutButton.addEventListener("click", logout);
    }

});