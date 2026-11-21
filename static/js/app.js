/* PolicyLens front-end behaviour.
 *
 * No inline scripts are used (the Content-Security-Policy forbids them). Everything is
 * attached through data-* attributes:
 *   data-validate            Bootstrap validation on submit
 *   data-confirm="text"      ask before submitting a form
 *   data-busy-text="text"    show a busy state while a form submits
 *   data-toggle-password=id  show / hide a password field
 * Text from documents and answers is ALWAYS written with textContent, never innerHTML,
 * so document content can never inject markup (XSS protection).
 */
(function () {
  "use strict";

  var csrf = document.body.getAttribute("data-csrf") || "";

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  /* ---------- generic form helpers ---------- */
  document.querySelectorAll("form[data-validate]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var big = form.querySelector("input[type=file][data-max-bytes]");
      if (big && big.files.length && big.files[0].size > Number(big.getAttribute("data-max-bytes"))) {
        big.setCustomValidity("File is too large.");
      } else if (big) {
        big.setCustomValidity("");
      }
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add("was-validated");
    });
  });

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) event.preventDefault();
    });
  });

  document.querySelectorAll("form[data-busy-text]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (event.defaultPrevented) return;
      form.classList.add("is-busy");
      form.querySelectorAll("button[type=submit]").forEach(function (b) {
        window.setTimeout(function () { b.disabled = true; }, 0);
      });
    });
  });

  document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
    button.addEventListener("click", function () {
      var input = document.getElementById(button.getAttribute("data-toggle-password"));
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
    });
  });

  /* ---------- permissions page: user or department grantee ---------- */
  var grantType = document.getElementById("g_type");
  if (grantType) {
    var sync = function () {
      var isUser = grantType.value === "user";
      document.getElementById("g_user").classList.toggle("d-none", !isUser);
      document.getElementById("g_dept").classList.toggle("d-none", isUser);
      document.getElementById("lblUser").textContent = isUser ? "User" : "Department";
    };
    grantType.addEventListener("change", sync);
    sync();
  }

  /* ---------- document page: jump the PDF preview to a cited page (#page=N) ---------- */
  var frame = document.getElementById("pdfFrame");
  if (frame) {
    var match = /page=(\d+)/.exec(window.location.hash);
    if (match) frame.src = frame.getAttribute("data-base") + "#page=" + match[1];
  }

  /* ---------- JSON helper (sends the CSRF token) ---------- */
  function postJson(url, payload) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(payload)
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok && !data.error) data.error = "Request failed (" + response.status + "). Please try again.";
        return data;
      });
    });
  }

  function sourceCard(source) {
    var card = el("div", "ex mb-2");
    var head = el("b");
    head.appendChild(el("span", "pl b", "S" + source.n));
    head.appendChild(document.createTextNode(" "));
    var link = el("a", null, source.title + " · page " + source.page);
    link.href = source.url;
    link.target = "_blank";
    link.rel = "noopener";
    head.appendChild(link);
    card.appendChild(head);
    card.appendChild(el("br"));
    card.appendChild(el("mark", null, source.excerpt));
    card.id = "src-" + source.n;
    return card;
  }

  /* Write answer text; [S1] markers become small links to the evidence card. */
  function writeCited(container, text) {
    var parts = text.split(/(\[S\d+\])/g);
    parts.forEach(function (part) {
      var m = /^\[S(\d+)\]$/.exec(part);
      if (m) {
        var a = el("a", "cite", m[1]);
        a.href = "#src-" + m[1];
        a.title = "Show source " + m[1];
        container.appendChild(a);
      } else if (part) {
        container.appendChild(document.createTextNode(part));
      }
    });
  }

  /* ---------- AI assistant ---------- */
  var assistant = document.getElementById("assistant");
  if (assistant) {
    var chat = document.getElementById("chat");
    var form = document.getElementById("askForm");
    var input = document.getElementById("question");
    var button = document.getElementById("askBtn");
    var evidence = document.getElementById("evidence");
    var deptFilter = document.getElementById("deptFilter");

    var checks = function () { return Array.prototype.slice.call(document.querySelectorAll(".doc-check")); };

    deptFilter.addEventListener("change", function () {
      document.querySelectorAll("#docScope [data-dept]").forEach(function (row) {
        var hide = deptFilter.value && row.getAttribute("data-dept") !== deptFilter.value;
        row.classList.toggle("d-none", !!hide);
        if (hide) row.querySelector("input").checked = false;
      });
    });
    document.getElementById("toggleAll").addEventListener("click", function (event) {
      event.preventDefault();
      var visible = checks().filter(function (c) { return !c.closest("[data-dept]").classList.contains("d-none"); });
      var all = visible.every(function (c) { return c.checked; });
      visible.forEach(function (c) { c.checked = !all; });
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var question = input.value.trim();
      if (!question) return;
      var empty = document.getElementById("chatEmpty");
      if (empty) empty.remove();

      chat.appendChild(el("div", "me", question));
      var row = el("div", "ai");
      row.appendChild(el("span", "av", "AI"));
      var body = el("div", "txt", "Searching your documents…");
      row.appendChild(body);
      chat.appendChild(row);
      chat.scrollTop = chat.scrollHeight;
      input.value = "";
      button.disabled = true;
      form.classList.add("is-busy");

      var selected = checks().filter(function (c) { return c.checked; }).map(function (c) { return Number(c.value); });
      postJson(assistant.getAttribute("data-ask-url"), {
        question: question,
        document_ids: selected,
        department_id: deptFilter.value || null
      }).then(function (data) {
        body.textContent = "";
        if (data.error && !data.answer) {
          body.appendChild(el("span", "pl r", "Error"));
          body.appendChild(el("div", null, data.error));
        } else {
          if (data.label) body.appendChild(el("span", "pl " + (data.insufficient ? "a" : "g"), data.label));
          var text = el("div");
          text.style.marginTop = "6px";
          writeCited(text, data.answer);
          body.appendChild(text);
          var note = el("div", "ex");
          note.style.marginTop = "10px";
          note.textContent = "Searched " + data.searched_documents + " document(s). " + data.notice;
          body.appendChild(note);
        }
        evidence.textContent = "";
        if (data.sources && data.sources.length) {
          data.sources.forEach(function (s) { evidence.appendChild(sourceCard(s)); });
        } else {
          evidence.appendChild(el("span", "mu", "No sources: the documents did not support an answer."));
        }
      }).catch(function () {
        body.textContent = "The request failed. Check your connection and try again.";
      }).then(function () {
        button.disabled = false;
        form.classList.remove("is-busy");
        chat.scrollTop = chat.scrollHeight;
        input.focus();
      });
    });
  }

  /* ---------- clause comparison ---------- */
  var compare = document.getElementById("compare");
  if (compare) {
    var cform = document.getElementById("compareForm");
    var cbtn = document.getElementById("cmpBtn");
    var cerr = document.getElementById("cmpError");
    var cres = document.getElementById("cmpResult");
    var count = document.getElementById("selCount");
    var cchecks = function () { return Array.prototype.slice.call(document.querySelectorAll(".cmp-check")); };
    var refresh = function () {
      var picked = cchecks().filter(function (c) { return c.checked; }).length;
      count.textContent = picked + " selected";
      cchecks().forEach(function (c) { if (!c.checked) c.disabled = picked >= 5; });
    };
    cchecks().forEach(function (c) { c.addEventListener("change", refresh); });
    refresh();

    cform.addEventListener("submit", function (event) {
      event.preventDefault();
      var ids = cchecks().filter(function (c) { return c.checked; }).map(function (c) { return Number(c.value); });
      cerr.classList.add("d-none");
      cres.classList.add("d-none");
      if (ids.length < 2) {
        cerr.textContent = "Select at least two documents.";
        cerr.classList.remove("d-none");
        return;
      }
      cbtn.disabled = true;
      cform.classList.add("is-busy");
      postJson(compare.getAttribute("data-run-url"), {
        document_ids: ids,
        topic: document.getElementById("topic").value
      }).then(function (data) {
        if (data.error) {
          cerr.textContent = data.error;
          cerr.classList.remove("d-none");
          return;
        }
        var columns = document.getElementById("cmpColumns");
        columns.textContent = "";
        data.columns.forEach(function (col) {
          var card = el("section", "cd pd");
          card.style.flex = "1 1 260px";
          var head = el("div", "d-flex justify-content-between gap-2");
          head.appendChild(el("strong", null, col.title));
          head.appendChild(el("span", "pl " + (col.found ? "g" : "r"), col.found ? "Present" : "Missing"));
          card.appendChild(head);
          var bodyBox = el("div");
          bodyBox.style.marginTop = "12px";
          if (col.found) {
            col.sources.forEach(function (s) { bodyBox.appendChild(sourceCard(s)); });
          } else {
            var none = el("div", "ex", col.message);
            none.style.border = "1.5px dashed var(--bd)";
            bodyBox.appendChild(none);
          }
          card.appendChild(bodyBox);
          columns.appendChild(card);
        });
        var summary = document.getElementById("cmpSummary");
        summary.textContent = "";
        if (data.summary) {
          writeCited(summary, data.summary);
        } else {
          summary.textContent = data.summary_note || "No comparison summary is available.";
        }
        document.getElementById("cmpNotice").textContent = data.notice;
        cres.classList.remove("d-none");
      }).catch(function () {
        cerr.textContent = "The request failed. Check your connection and try again.";
        cerr.classList.remove("d-none");
      }).then(function () {
        cbtn.disabled = false;
        cform.classList.remove("is-busy");
      });
    });
  }
})();
