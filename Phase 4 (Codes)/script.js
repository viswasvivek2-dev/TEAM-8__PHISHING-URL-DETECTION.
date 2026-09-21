/* ==========================================
   VARIABLES
========================================== */

let totalInputs = 0;

let history = [];


/* ==========================================
   ELEMENTS
========================================== */

const urlInput =
    document.getElementById("urlInput");

const receiveButton =
    document.getElementById("receiveButton");

const totalInputsElement =
    document.getElementById("totalInputs");

const lastInputElement =
    document.getElementById("lastInput");

const historyTable =
    document.getElementById("historyTable");

const clearHistory =
    document.getElementById("clearHistory");

const breadcrumbPage =
    document.getElementById("breadcrumbPage");

const menuItems =
    document.querySelectorAll(".menu-item");

const scannerPage =
    document.getElementById("scannerPage");

const historyPage =
    document.getElementById("historyPage");

const howPage =
    document.getElementById("howPage");


/* ==========================================
   PAGE SWITCHING
========================================== */

menuItems.forEach(function(item) {

    item.addEventListener("click", function(event) {

        event.preventDefault();


        /* Remove active from all */

        menuItems.forEach(function(menu) {

            menu.classList.remove("active");

        });


        /* Add active to clicked item */

        item.classList.add("active");


        /* Get requested page */

        const page =
            item.getAttribute("data-page");


        /* Hide all pages */

        scannerPage.classList.remove(
            "active-page"
        );

        historyPage.classList.remove(
            "active-page"
        );

        howPage.classList.remove(
            "active-page"
        );


        /* Show selected page */

        if (page === "scanner") {

            scannerPage.classList.add(
                "active-page"
            );

            breadcrumbPage.textContent =
                "Scanner";

        }


        else if (page === "history") {

            historyPage.classList.add(
                "active-page"
            );

            breadcrumbPage.textContent =
                "History";

            displayHistory();

        }


        else if (page === "how") {

            howPage.classList.add(
                "active-page"
            );

            breadcrumbPage.textContent =
                "How it works";

        }

    });

});


/* ==========================================
   RECEIVE URL
========================================== */

receiveButton.addEventListener(
    "click",
    function() {

        const url =
            urlInput.value.trim();


        /* Empty URL */

        if (url === "") {

            alert(
                "Please enter a website URL."
            );

            urlInput.focus();

            return;

        }


        /* Increase total */

        totalInputs++;

        totalInputsElement.textContent =
            totalInputs;


        /* Display latest URL */

        lastInputElement.textContent =
            url;


        /* Create history object */

        const historyItem = {

            url: url,

            time: getCurrentTime()

        };


        /* Add to history */

        history.unshift(historyItem);


        /* Save history */

        saveHistory();


        /* Clear input */

        urlInput.value = "";


        /* Button feedback */

        receiveButton.textContent =
            "Received ✓";


        setTimeout(
            function() {

                receiveButton.textContent =
                    "Receive URL →";

            },
            1500
        );

    }
);


/* ==========================================
   ENTER KEY
========================================== */

urlInput.addEventListener(
    "keydown",
    function(event) {

        if (event.key === "Enter") {

            receiveButton.click();

        }

    }
);


/* ==========================================
   DISPLAY HISTORY
========================================== */

function displayHistory() {

    historyTable.innerHTML = "";


    /* No history */

    if (history.length === 0) {

        const row =
            document.createElement("tr");


        row.innerHTML = `

            <td
                colspan="4"
                class="empty-history"
            >

                No URLs have been submitted yet.

            </td>

        `;


        historyTable.appendChild(row);

        return;

    }


    /* Display each item */

    history.forEach(
        function(item, index) {

            const row =
                document.createElement("tr");


            row.innerHTML = `

                <td>
                    ${index + 1}
                </td>

                <td class="url-history">
                    ${escapeHTML(item.url)}
                </td>

                <td>

                    <span class="status-received">
                        Received
                    </span>

                </td>

                <td>
                    ${item.time}
                </td>

            `;


            historyTable.appendChild(row);

        }
    );

}


/* ==========================================
   CLEAR HISTORY
========================================== */

clearHistory.addEventListener(
    "click",
    function() {

        if (history.length === 0) {

            return;

        }


        const confirmClear =
            confirm(
                "Are you sure you want to clear the history?"
            );


        if (confirmClear) {

            history = [];

            saveHistory();

            displayHistory();

        }

    }
);


/* ==========================================
   CURRENT TIME
========================================== */

function getCurrentTime() {

    const now =
        new Date();


    return now.toLocaleTimeString(
        [],
        {
            hour: "2-digit",
            minute: "2-digit"
        }
    );

}


/* ==========================================
   SAVE HISTORY
========================================== */

function saveHistory() {

    localStorage.setItem(
        "phishshieldHistory",
        JSON.stringify(history)
    );

}


/* ==========================================
   LOAD HISTORY
========================================== */

function loadHistory() {

    const saved =
        localStorage.getItem(
            "phishshieldHistory"
        );


    if (saved) {

        history =
            JSON.parse(saved);

        totalInputs =
            history.length;

        totalInputsElement.textContent =
            totalInputs;


        if (history.length > 0) {

            lastInputElement.textContent =
                history[0].url;

        }

    }

}


/* ==========================================
   ESCAPE HTML
========================================== */

function escapeHTML(text) {

    const div =
        document.createElement("div");

    div.textContent =
        text;

    return div.innerHTML;

}


/* ==========================================
   START APPLICATION
========================================== */

loadHistory();

displayHistory();