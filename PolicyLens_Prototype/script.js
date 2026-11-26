
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

let sampleDocuments = [
    ["DOC-001", "Employee Agreement.pdf", "Human Resources", "Approved"],
    ["DOC-002", "Data Privacy Policy.pdf", "IT Department", "Approved"],
    ["DOC-003", "Vendor Service Agreement.pdf", "Procurement", "Pending"]
];

let sampleFindings = [
    ["FND-101", "Missing termination clause", "High", "Pending"],
    ["FND-102", "Data retention period", "Medium", "Under Review"],
    ["FND-103", "Unclear payment obligations", "High", "Pending"]
];

let sampleUsers = [
    ["Demo Admin", "admin@policylens.demo", "Admin", "Administration", "Active"],
    ["Demo Analyst", "analyst@policylens.demo", "Analyst", "Legal", "Active"],
    ["Demo Reviewer", "reviewer@policylens.demo", "Reviewer", "Compliance", "Active"]
];

let sampleDepartments = [
    ["Human Resources", "HR"],
    ["Information Technology", "IT"],
    ["Finance", "FIN"],
    ["Legal", "LEG"],
    ["Procurement", "PRO"],
    ["Compliance", "COM"]
];


/* Helper: safely display user-entered text */

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (character) {
        const entities = {
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;"
        };

        return entities[character];
    });
}


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

        button.addEventListener("click", function () {
            showPage(label);
        });

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
                <button class="quick-primary" data-page="Upload">
                    Upload document
                </button>

                <button data-page="Documents">
                    Browse documents
                </button>

                <button data-page="AI Assistant">
                    Ask PolicyLens
                </button>

                <button data-page="Compliance findings">
                    Compliance findings
                </button>
            </div>

            <section class="stats-grid">
                ${statCard("Accessible documents", String(sampleDocuments.length + 10))}
                ${statCard("Agreements", "7")}
                ${statCard("Policies", "6")}
                ${statCard("Awaiting indexing", "0")}
                ${statCard("Failed processing", "0")}
                ${statCard("Open compliance findings", String(sampleFindings.length))}
                ${statCard("Users (active)", String(sampleUsers.length))}
                ${statCard("Departments", String(sampleDepartments.length))}
                ${statCard("Audit events", "213")}
            </section>
        `;
    }

    const stats = currentRole === "Analyst"
        ? [
            ["My documents", "18"],
            ["Processed", "15"],
            ["Findings", String(sampleFindings.length)],
            ["Comparisons", "4"]
        ]
        : [
            ["Assigned findings", String(sampleFindings.length)],
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
                    <button class="quick-primary" data-page="Upload">
                        Upload document
                    </button>
                    <button data-page="Documents">
                        Browse documents
                    </button>
                    <button data-page="AI Assistant">
                        Ask PolicyLens
                    </button>
                `
                : `
                    <button class="quick-primary" data-page="Assigned findings">
                        View assigned findings
                    </button>
                    <button data-page="Review history">
                        Review history
                    </button>
                `
            }
        </div>

        <section class="stats-grid">
            ${stats.map(item => statCard(item[0], item[1])).join("")}
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
    const rows = sampleDocuments.map((doc, index) => `
        <tr>
            <td>${escapeHtml(doc[0])}</td>
            <td>${escapeHtml(doc[1])}</td>
            <td>${escapeHtml(doc[2])}</td>
            <td>
                <span class="status ${doc[3] === "Pending" ? "pending" : ""}">
                    ${escapeHtml(doc[3])}
                </span>
            </td>
            <td>
                <button class="small-btn"
                    data-action="view-document"
                    data-index="${index}">
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
                <button class="secondary-btn" data-action="refresh-documents">
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

            <div id="documentDetails"></div>
        </div>
    `;
}


/* Document upload */

function uploadPage() {
    const departmentOptions = sampleDepartments.map(department =>
        `<option>${escapeHtml(department[0])}</option>`
    ).join("");

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
                    ${departmentOptions}
                </select>
            </div>

            <div class="form-group">
                <label>Select PDF</label>
                <input type="file" accept=".pdf,application/pdf" id="demoFile">
            </div>

            <button class="primary-btn" data-action="simulate-upload">
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

            <button class="primary-btn" data-action="simulate-question">
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

            <button class="primary-btn" data-action="simulate-comparison">
                Compare documents
            </button>

            <div id="comparisonResult"></div>
        </div>
    `;
}


/* Compliance findings */

function findingsPage() {
    const rows = sampleFindings.map((item, index) => `
        <tr>
            <td>${escapeHtml(item[0])}</td>
            <td>${escapeHtml(item[1])}</td>
            <td>${escapeHtml(item[2])}</td>
            <td>
                <span class="status ${item[3] === "Pending" ? "pending" : "review"}">
                    ${escapeHtml(item[3])}
                </span>
            </td>
            <td>
                <button class="small-btn"
                    data-action="view-finding"
                    data-index="${index}">
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
                    ? '<button class="primary-btn" data-action="show-finding-form">Create finding</button>'
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

            <div id="findingDetails"></div>
            <div id="findingForm"></div>
        </div>
    `;
}


/* Finding creation form */

function showFindingForm() {
    const form = document.getElementById("findingForm");

    if (!form) return;

    form.innerHTML = `
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

            <button class="primary-btn" data-action="simulate-finding">
                Submit demo finding
            </button>

            <button class="secondary-btn" data-action="cancel-finding">
                Cancel
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
    const rows = sampleUsers.map((user, index) => `
        <tr>
            <td>${escapeHtml(user[0])}</td>
            <td>${escapeHtml(user[2])}</td>
            <td>${escapeHtml(user[3])}</td>
            <td><span class="status">${escapeHtml(user[4])}</span></td>
            <td>
                <button class="small-btn"
                    data-action="view-user"
                    data-index="${index}">
                    View
                </button>
            </td>
        </tr>
    `).join("");

    return `
        ${pageHeading(
            "Users",
            "Manage example users and their assigned roles."
        )}

        <div class="panel">
            <div class="panel-header">
                <h3>Users</h3>
                <button class="primary-btn" data-action="show-user-form">
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
                    <tbody>${rows}</tbody>
                </table>
            </div>

            <div id="userDetails"></div>
            <div id="userForm"></div>
        </div>
    `;
}


/* Add user form */

function showUserForm() {
    const form = document.getElementById("userForm");

    if (!form) return;

    const departments = sampleDepartments.map(department =>
        `<option>${escapeHtml(department[0])}</option>`
    ).join("");

    form.innerHTML = `
        <div class="panel">
            <h3>Add demo user</h3>

            <div class="form-group">
                <label>Full name</label>
                <input type="text" id="newUserName"
                    placeholder="Enter full name">
            </div>

            <div class="form-group">
                <label>Email address</label>
                <input type="email" id="newUserEmail"
                    placeholder="Enter email address">
            </div>

            <div class="form-group">
                <label>Role</label>
                <select id="newUserRole">
                    <option>Admin</option>
                    <option>Analyst</option>
                    <option>Reviewer</option>
                </select>
            </div>

            <div class="form-group">
                <label>Department</label>
                <select id="newUserDepartment">
                    ${departments}
                </select>
            </div>

            <button class="primary-btn" data-action="save-user">
                Save demo user
            </button>

            <button class="secondary-btn" data-action="cancel-user">
                Cancel
            </button>
        </div>
    `;
}


/* Departments */

function departmentsPage() {
    const rows = sampleDepartments.map(department => `
        <tr>
            <td>${escapeHtml(department[0])}</td>
            <td>${escapeHtml(department[1])}</td>
            <td><span class="status">Active</span></td>
        </tr>
    `).join("");

    return `
        ${pageHeading(
            "Departments",
            "View the departments configured in this sample organization."
        )}

        <div class="panel">
            <div class="panel-header">
                <h3>Organization departments</h3>
                <button class="primary-btn" data-action="show-department-form">
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
                    <tbody>${rows}</tbody>
                </table>
            </div>

            <div id="departmentForm"></div>
        </div>
    `;
}


/* Add department form */

function showDepartmentForm() {
    const form = document.getElementById("departmentForm");

    if (!form) return;

    form.innerHTML = `
        <div class="panel">
            <h3>Add demo department</h3>

            <div class="form-group">
                <label>Department name</label>
                <input type="text" id="newDepartmentName"
                    placeholder="Enter department name">
            </div>

            <div class="form-group">
                <label>Department code</label>
                <input type="text" id="newDepartmentCode"
                    placeholder="Example: HR">
            </div>

            <button class="primary-btn" data-action="save-department">
                Save demo department
            </button>

            <button class="secondary-btn" data-action="cancel-department">
                Cancel
            </button>
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
    const department = document.getElementById("docDepartment").value;
    const file = document.getElementById("demoFile").files[0];

    if (!name || !file) {
        notify("Please enter a document name and select a sample PDF.");
        return;
    }

    if (!file.name.toLowerCase().endsWith(".pdf")) {
        notify("Please select a PDF file.");
        return;
    }

    const newId = "DOC-" + String(sampleDocuments.length + 1).padStart(3, "0");

    sampleDocuments.push([
        newId,
        name.toLowerCase().endsWith(".pdf") ? name : name + ".pdf",
        department,
        "Uploaded (Demo)"
    ]);

    notify("Demo upload completed. No file was saved.");

    showPage("Documents");
}


/* AI question simulation */

function simulateQuestion() {
    const question = document.getElementById("assistantQuestion").value.trim();
    const selectedDocument = document.getElementById("assistantDocument").value;
    const chatBox = document.getElementById("chatBox");

    if (!question) {
        notify("Please enter a question.");
        return;
    }

    const message = document.createElement("div");
    message.className = "chat-message";

    const questionText = document.createElement("p");
    questionText.textContent = question;

    const response = document.createElement("div");

    response.innerHTML = `
        <strong>Sample response</strong>
        <br>
        This is a simulated response for demonstration purposes.
        The live PolicyLens assistant can retrieve information
        from authorized documents and provide source citations.
        <br><br>
        <strong>Sample source:</strong>
        ${escapeHtml(selectedDocument)}, Page 4
    `;

    message.appendChild(questionText);
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
        <div class="info-box">
            <strong>Sample comparison completed</strong>
            <br>
            Document 1: ${escapeHtml(first)}
            <br>
            Document 2: ${escapeHtml(second)}
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

    const severity =
        document.getElementById("findingSeverity").value;

    if (!description) {
        notify("Please enter a finding description.");
        return;
    }

    const newId = "FND-" + String(101 + sampleFindings.length).padStart(3, "0");

    sampleFindings.push([
        newId,
        description,
        severity,
        "Pending"
    ]);

    notify("Demo finding submitted successfully.");

    showPage("Compliance findings");
}


/* Save demo user */

function saveUser() {
    const name = document.getElementById("newUserName").value.trim();
    const email = document.getElementById("newUserEmail").value.trim();
    const role = document.getElementById("newUserRole").value;
    const department = document.getElementById("newUserDepartment").value;

    if (!name || !email) {
        notify("Please enter the user's name and email address.");
        return;
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {
        notify("Please enter a valid email address.");
        return;
    }

    const emailExists = sampleUsers.some(user =>
        user[1].toLowerCase() === email.toLowerCase()
    );

    if (emailExists) {
        notify("This demo email address already exists.");
        return;
    }

    sampleUsers.push([name, email, role, department, "Active"]);

    notify("Demo user added successfully.");

    showPage("Users");
}


/* Save demo department */

function saveDepartment() {
    const name = document.getElementById("newDepartmentName").value.trim();
    const code = document.getElementById("newDepartmentCode").value.trim();

    if (!name || !code) {
        notify("Please enter the department name and code.");
        return;
    }

    const exists = sampleDepartments.some(department =>
        department[0].toLowerCase() === name.toLowerCase() ||
        department[1].toLowerCase() === code.toLowerCase()
    );

    if (exists) {
        notify("This department name or code already exists.");
        return;
    }

    sampleDepartments.push([name, code.toUpperCase()]);

    notify("Demo department added successfully.");

    showPage("Departments");
}


/* View sample document details */

function viewDocument(index) {
    const doc = sampleDocuments[index];

    if (!doc) return;

    const details = document.getElementById("documentDetails");

    details.innerHTML = `
        <div class="info-box">
            <strong>Document details</strong>
            <br>
            Document ID: ${escapeHtml(doc[0])}
            <br>
            Document name: ${escapeHtml(doc[1])}
            <br>
            Department: ${escapeHtml(doc[2])}
            <br>
            Status: ${escapeHtml(doc[3])}
            <br><br>
            This is a sample document. No real PDF is connected.
        </div>
    `;
}


/* View sample finding details */

function viewFinding(index) {
    const finding = sampleFindings[index];

    if (!finding) return;

    const details = document.getElementById("findingDetails");

    details.innerHTML = `
        <div class="info-box">
            <strong>Finding details</strong>
            <br>
            Finding ID: ${escapeHtml(finding[0])}
            <br>
            Description: ${escapeHtml(finding[1])}
            <br>
            Severity: ${escapeHtml(finding[2])}
            <br>
            Status: ${escapeHtml(finding[3])}
        </div>
    `;
}


/* View sample user details */

function viewUser(index) {
    const user = sampleUsers[index];

    if (!user) return;

    const details = document.getElementById("userDetails");

    details.innerHTML = `
        <div class="info-box">
            <strong>User details</strong>
            <br>
            Name: ${escapeHtml(user[0])}
            <br>
            Email: ${escapeHtml(user[1])}
            <br>
            Role: ${escapeHtml(user[2])}
            <br>
            Department: ${escapeHtml(user[3])}
            <br>
            Status: ${escapeHtml(user[4])}
        </div>
    `;
}


/* Notification message */

function notify(message) {
    const toast = document.getElementById("toast");

    if (!toast) return;

    toast.textContent = message;
    toast.style.display = "block";

    clearTimeout(window.demoToastTimer);

    window.demoToastTimer = setTimeout(() => {
        toast.style.display = "none";
    }, 3000);
}


/* Central click handler for dynamically created buttons */

document.addEventListener("click", function (event) {
    const pageButton = event.target.closest("[data-page]");

    if (pageButton) {
        showPage(pageButton.dataset.page);
        return;
    }

    const actionButton = event.target.closest("[data-action]");

    if (!actionButton) return;

    const action = actionButton.dataset.action;

    const actions = {
        "simulate-upload": simulateUpload,
        "simulate-question": simulateQuestion,
        "simulate-comparison": simulateComparison,
        "show-finding-form": showFindingForm,
        "simulate-finding": simulateFinding,
        "cancel-finding": () => {
            document.getElementById("findingForm").innerHTML = "";
        },
        "show-user-form": showUserForm,
        "save-user": saveUser,
        "cancel-user": () => {
            document.getElementById("userForm").innerHTML = "";
        },
        "show-department-form": showDepartmentForm,
        "save-department": saveDepartment,
        "cancel-department": () => {
            document.getElementById("departmentForm").innerHTML = "";
        },
        "refresh-documents": () => {
            showPage("Documents");
            notify("Sample document list refreshed.");
        },
        "view-document": () => viewDocument(Number(actionButton.dataset.index)),
        "view-finding": () => viewFinding(Number(actionButton.dataset.index)),
        "view-user": () => viewUser(Number(actionButton.dataset.index))
    };

    if (actions[action]) {
        actions[action]();
    }
});


/* Exit demo */

function logout() {
    document.getElementById("appScreen").classList.add("hidden");
    document.getElementById("loginScreen").classList.remove("hidden");
    document.getElementById("roleSelect").value = "Admin";
}


/* Initial button events */

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
