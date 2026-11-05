"use strict";

const REVOKE_DEVICE_CLASSES_URL = "revokeDeviceClasses";

const message = document.getElementById("message");
const revokeButton = document.getElementById("revoke");

let unfixableAccounts = 0;

function render(result) {
    document.getElementById("summary").textContent =
        `${result.accounts_checked} accounts checked, ${result.accounts_skipped} skipped; ` +
        `${result.accounts_affected_fixable} on fixable and ${result.accounts_affected_unfixable} on unfixable classes.`;
    const rows = result.affected_device_classes.map((deviceClass) => {
        const tr = document.createElement("tr");
        tr.append(
            cell(deviceClass.device_type),
            cell(deviceClass.vulnerability_id),
            cell(deviceClass.classification),
            cell(deviceClass.accounts_affected),
        );
        return tr;
    });
    document.getElementById("device-classes").replaceChildren(...rows);
}

async function scan(dryRun) {
    const response = await request(`${REVOKE_DEVICE_CLASSES_URL}?dryRun=${dryRun}`, {
        method: "POST",
        headers: {Accept: "application/json"},
    });
    const result = await response.json();
    render(result);
    return result;
}

async function dryRun() {
    showMessage(message, "Running dry run…", false);
    unfixableAccounts = (await scan(true)).accounts_affected_unfixable;
    revokeButton.disabled = unfixableAccounts === 0;
    showMessage(message, "", false);
}

async function revoke() {
    if (!confirm(`Revoke ${unfixableAccounts} account(s) on unfixable device classes?`)) return;
    revokeButton.disabled = true;
    try {
        const result = await scan(false);
        showMessage(message, `Published ${result.revocations_published} revocation(s)`, false);
    } catch (e) {
        revokeButton.disabled = false;
        showMessage(message, e.message, true);
    }
}

revokeButton.addEventListener("click", revoke);
dryRun().catch((e) => showMessage(message, e.message, true));
