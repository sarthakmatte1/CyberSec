// Wait for DOM - safest approach
  document.addEventListener('DOMContentLoaded', function() {

    var boxes     = Array.from(document.querySelectorAll('.otp-digit'));
    var hidden    = document.getElementById('otp-hidden');
    var submitBtn = document.getElementById('submit-btn');
    var form      = document.getElementById('otp-form');

    // Sync all box values into hidden input and toggle button
    function sync() {
      var val = '';
      for (var i = 0; i < boxes.length; i++) {
        val += boxes[i].value || '';
      }
      hidden.value = val;
      for (var j = 0; j < boxes.length; j++) {
        if (boxes[j].value) {
          boxes[j].classList.add('filled');
        } else {
          boxes[j].classList.remove('filled');
        }
      }
    }

    // Focus first empty box, or last box if all filled
    function focusNext(fromIdx) {
      for (var i = fromIdx; i < boxes.length; i++) {
        if (!boxes[i].value) { boxes[i].focus(); return; }
      }
      boxes[boxes.length - 1].focus();
    }

    boxes.forEach(function(box, idx) {

      // INPUT event - fires after value changes (handles mobile, autofill, voice)
      box.addEventListener('input', function() {
        // Strip non-digits, keep only last character
        var clean = box.value.replace(/\D/g, '');
        if (clean.length > 1) {
          // Paste detected via input event - spread digits
          var digits = clean.slice(0, 6 - idx);
          for (var i = 0; i < digits.length; i++) {
            if (boxes[idx + i]) boxes[idx + i].value = digits[i];
          }
          sync();
          focusNext(idx + digits.length);
          return;
        }
        box.value = clean;
        sync();
        if (clean && idx < 5) boxes[idx + 1].focus();
      });

      // KEYDOWN - handle backspace and arrows only
      box.addEventListener('keydown', function(e) {
        if (e.key === 'Backspace') {
          if (box.value) {
            box.value = '';
            sync();
          } else if (idx > 0) {
            boxes[idx - 1].value = '';
            boxes[idx - 1].focus();
            sync();
          }
          e.preventDefault();
          return;
        }
        if (e.key === 'ArrowLeft'  && idx > 0) { boxes[idx-1].focus(); e.preventDefault(); return; }
        if (e.key === 'ArrowRight' && idx < 5) { boxes[idx+1].focus(); e.preventDefault(); return; }
        if (e.key === 'Delete') { box.value = ''; sync(); e.preventDefault(); return; }
        // Enter submits if all filled
        if (e.key === 'Enter') { form.requestSubmit ? form.requestSubmit() : form.submit(); return; }
      });

      // PASTE - intercept clipboard paste on any box
      box.addEventListener('paste', function(e) {
        e.preventDefault();
        var text = (e.clipboardData || window.clipboardData).getData('text');
        var digits = text.replace(/\D/g, '').slice(0, 6);
        if (!digits) return;
        // Fill from box 0 always (most natural behavior)
        for (var i = 0; i < 6; i++) {
          boxes[i].value = digits[i] || '';
        }
        sync();
        focusNext(digits.length);
      });

      // Click: select content for easy re-entry
      box.addEventListener('focus', function() { box.select(); });
    });

    // Form submit guard - ensure hidden field is always populated
    form.addEventListener('submit', function(e) {
      sync();
      var val = '';
      for (var i = 0; i < boxes.length; i++) val += boxes[i].value || '';
      hidden.value = val;
      console.log('Submitting OTP:', val); 
      if (val.length < 6) {
        e.preventDefault();
        focusNext(0);
        return;
      }
      submitBtn.textContent = 'Verifying...';
    });

    // Focus first box on load
    boxes[0].focus();

    // ── Countdown timer (5 min = 300s) ──────────────────────
    var seconds = 300;
    var timerEl = document.getElementById('timer');
    var countEl = document.getElementById('timer-count');

    function pad(n) { return n < 10 ? '0' + n : '' + n; }

    var tick = setInterval(function() {
      seconds--;
      var m = Math.floor(seconds / 60);
      var s = seconds % 60;
      countEl.textContent = pad(m) + ':' + pad(s);
      if (seconds <= 60) timerEl.classList.add('expiring');
      if (seconds <= 0) {
        clearInterval(tick);
        countEl.textContent = '00:00';
        submitBtn.textContent = 'OTP Expired — go back to login';
        submitBtn.style.opacity = '0.5';
        submitBtn.style.pointerEvents = 'none';
        for (var i = 0; i < boxes.length; i++) {
          boxes[i].disabled = true;
          boxes[i].style.opacity = '0.4';
        }
      }
    }, 1000);

  }); // end DOMContentLoaded