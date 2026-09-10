(function () {
  var LENGTH = 5;
  var PERSIAN = "۰۱۲۳۴۵۶۷۸۹";
  var seconds = 119;

  var row = document.getElementById("otp-row");
  var hidden = document.getElementById("otpCode");
  var form = document.getElementById("otp-form");
  var timerEl = document.getElementById("otp-timer");
  var timerText = document.getElementById("otp-timer-text");
  var resendForm = document.getElementById("resend-form");

  if (!row || !hidden || !form) return;

  var inputs = Array.prototype.slice.call(row.querySelectorAll(".otp-input"));

  function toPersian(value) {
    return String(value).replace(/\d/g, function (d) {
      return PERSIAN[Number(d)];
    });
  }

  function toLatinDigit(char) {
    var persianIndex = PERSIAN.indexOf(char);
    if (persianIndex >= 0) return String(persianIndex);
    return char;
  }

  function getDigits() {
    return inputs.map(function (input) {
      return toLatinDigit(input.dataset.latin || "").replace(/\D/g, "").slice(-1) || "";
    });
  }

  function syncHidden() {
    hidden.value = getDigits().join("");
  }

  function setActive(index) {
    inputs.forEach(function (input, i) {
      input.classList.toggle("is-active", i === index);
    });
  }

  function focusAt(index) {
    var next = Math.max(0, Math.min(LENGTH - 1, index));
    setActive(next);
    inputs[next].focus();
  }

  function updateDigit(index, raw) {
    var latin = toLatinDigit(raw).replace(/\D/g, "").slice(-1);
    inputs[index].dataset.latin = latin;
    inputs[index].value = latin ? toPersian(latin) : "";
    syncHidden();
    if (latin && index < LENGTH - 1) {
      focusAt(index + 1);
    }
  }

  function handlePaste(index, text) {
    var chars = text
      .split("")
      .map(toLatinDigit)
      .filter(function (char) {
        return /\d/.test(char);
      })
      .slice(0, LENGTH - index);

    if (!chars.length) return;

    chars.forEach(function (char, offset) {
      var i = index + offset;
      inputs[i].dataset.latin = char;
      inputs[i].value = toPersian(char);
    });
    syncHidden();
    focusAt(Math.min(index + chars.length, LENGTH - 1));
  }

  function renderTimer() {
    if (!timerEl || !timerText || !resendForm) return;
    if (seconds > 0) {
      timerText.style.display = "";
      resendForm.style.display = "none";
      var mm = String(Math.floor(seconds / 60)).padStart(2, "0");
      var ss = String(seconds % 60).padStart(2, "0");
      timerEl.textContent = toPersian(mm + ":" + ss);
    } else {
      timerText.style.display = "none";
      resendForm.style.display = "";
    }
  }

  inputs.forEach(function (input, index) {
    input.addEventListener("focus", function () {
      setActive(index);
    });

    input.addEventListener("input", function (event) {
      updateDigit(index, event.target.value);
    });

    input.addEventListener("keydown", function (event) {
      if (event.key === "Backspace") {
        event.preventDefault();
        if (inputs[index].dataset.latin) {
          inputs[index].dataset.latin = "";
          inputs[index].value = "";
          syncHidden();
        } else {
          var prev = Math.max(0, index - 1);
          inputs[prev].dataset.latin = "";
          inputs[prev].value = "";
          syncHidden();
          focusAt(prev);
        }
      }
      if (event.key === "ArrowLeft") {
        event.preventDefault();
        focusAt(index - 1);
      }
      if (event.key === "ArrowRight") {
        event.preventDefault();
        focusAt(index + 1);
      }
    });

    input.addEventListener("paste", function (event) {
      event.preventDefault();
      handlePaste(index, (event.clipboardData || window.clipboardData).getData("text"));
    });
  });

  form.addEventListener("submit", function (event) {
    syncHidden();
    if (hidden.value.length !== LENGTH) {
      event.preventDefault();
    }
  });

  renderTimer();
  window.setInterval(function () {
    if (seconds <= 0) return;
    seconds -= 1;
    renderTimer();
  }, 1000);

  focusAt(0);
})();
