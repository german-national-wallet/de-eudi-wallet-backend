"use strict";

const LEAKED_KEYS_URL = "androidLeakedKeys";

const message = document.getElementById("message");

async function removeEntry(serial) {
    if (!confirm(`Remove leaked key ${serial}?`)) return;
    try {
        await request(`${LEAKED_KEYS_URL}/${encodeURIComponent(serial)}`, {method: "DELETE"});
        showMessage(message, `Removed ${serial}`, false);
        await refresh();
    } catch (e) {
        showMessage(message, e.message, true);
    }
}

async function refresh() {
    const response = await request(LEAKED_KEYS_URL, {headers: {Accept: "application/json"}});
    const {entries} = await response.json();
    const rows = entries.map((entry) => {
        const tr = document.createElement("tr");
        tr.append(
            cell(entry.serial, "serial"),
            cell(entry.status),
            cell(entry.reason),
            cell(entry.comment),
            cell(entry.added_by),
            cell(entry.created_at),
        );
        const button = document.createElement("button");
        button.textContent = "Remove";
        button.addEventListener("click", () => removeEntry(entry.serial));
        const action = document.createElement("td");
        action.append(button);
        tr.append(action);
        return tr;
    });
    document.getElementById("entries").replaceChildren(...rows);
}

async function add(event) {
    event.preventDefault();
    const comment = document.getElementById("comment").value.trim() || null;
    const status = document.getElementById("status").value;
    const reason = document.getElementById("reason").value;
    const serials = document.getElementById("serials").value
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    try {
        await request(LEAKED_KEYS_URL, {
            method: "POST",
            headers: {"Content-Type": "application/json", Accept: "application/json"},
            body: JSON.stringify({entries: serials.map((serial) => ({serial, status, reason, comment}))}),
        });
        event.target.reset();
        showMessage(message, `Added ${serials.length} key(s)`, false);
        await refresh();
    } catch (e) {
        showMessage(message, e.message, true);
    }
}

document.getElementById("add-form").addEventListener("submit", add);
refresh().catch((e) => showMessage(message, e.message, true));
