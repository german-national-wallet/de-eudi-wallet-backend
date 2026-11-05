"use strict";

function showMessage(element, text, isError) {
    element.textContent = text;
    element.classList.toggle("error", isError);
}

async function request(url, options) {
    let response;
    try {
        response = await fetch(url, {...options, credentials: "same-origin", redirect: "error"});
    } catch (e) {
        throw new Error("Request failed, reload the page to log in again");
    }
    if (response.status === 401 || response.status === 403) {
        throw new Error("Not logged in or not authorized, reload the page to log in again");
    }
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(`${body.description ?? response.statusText} (${body.code ?? response.status})`);
    }
    return response;
}

function cell(text, className) {
    const td = document.createElement("td");
    td.textContent = text ?? "";
    if (className) td.className = className;
    return td;
}
