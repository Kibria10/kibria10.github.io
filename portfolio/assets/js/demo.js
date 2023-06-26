document.addEventListener('DOMContentLoaded', function () {
  particleground(document.getElementById('particles'), {
    dotColor: makeDynamicColors(),
    lineColor: makeDynamicColors(),
  });

  function makeDynamicColors() {
    var colors = [
      '#660099',
      '#cccccc',
      '#ffff00',
      '#ff99cc',
      '#66ccff',
      '#ccffff',
      '#ffffff',
      '#993333'];
    return colors[Math.floor(Math.random() * colors.length)];
  }

  var intro = document.getElementById('intro');
  intro.style.marginTop = - intro.offsetHeight / 2 + 'px';
}, false);


