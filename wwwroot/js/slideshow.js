(function () {
  var INTERVAL = 5000;
  var root = document.querySelector("[data-slideshow]");
  if (!root) return;

  var slides = root.querySelectorAll(".login-slideshow-slide");
  var dots = root.querySelectorAll(".login-slideshow-dot");
  if (slides.length < 2) return;

  var index = 0;
  var timer;

  function goTo(next) {
    slides[index].classList.remove("is-active");
    if (dots[index]) {
      dots[index].classList.remove("is-active");
      dots[index].removeAttribute("aria-current");
    }

    index = (next + slides.length) % slides.length;

    slides[index].classList.add("is-active");
    if (dots[index]) {
      dots[index].classList.add("is-active");
      dots[index].setAttribute("aria-current", "true");
    }
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }

  function start() {
    stop();
    timer = setInterval(function () {
      goTo(index + 1);
    }, INTERVAL);
  }

  for (var i = 0; i < dots.length; i++) {
    (function (dotIndex) {
      dots[dotIndex].addEventListener("click", function () {
        goTo(dotIndex);
        start();
      });
    })(i);
  }

  start();
})();
