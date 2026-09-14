(function () {
    "use strict";

    var input = document.getElementById("dom-input");

    function renderFragment() {
        var value;
        try {
            value = decodeURIComponent(window.location.hash.substring(1));
        } catch (error) {
            document.getElementById("vulnerable-output").textContent = "Invalid URL fragment encoding.";
            document.getElementById("encoded-output").textContent = "";
            return;
        }

        input.value = value;
        document.getElementById("encoded-output").textContent = value;
        // Intentional CWE-79: attacker-controlled URL data reaches an HTML sink.
        document.getElementById("vulnerable-output").innerHTML = value;
    }

    document.getElementById("dom-form").addEventListener("submit", function (event) {
        event.preventDefault();
        var fragment = "#" + encodeURIComponent(input.value);
        if (window.location.hash === fragment) {
            renderFragment();
        } else {
            window.location.hash = fragment;
        }
    });

    window.addEventListener("hashchange", renderFragment);
    renderFragment();
}());
