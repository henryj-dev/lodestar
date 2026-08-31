import type { RequestHandler } from "@sveltejs/kit";

const JS = `(function(){
  // ── Theme ─────────────────────────────────────────────────────────────
  var THEME_KEY='ctrls-theme';
  var saved=localStorage.getItem(THEME_KEY)||'dark';
  document.documentElement.setAttribute('data-theme',saved);
  function initTheme(){
    var btn=document.getElementById('ctrls-theme-toggle');
    var label=document.getElementById('ctrls-theme-label');
    if(!btn||!label)return;
    label.textContent=document.documentElement.getAttribute('data-theme')||'dark';
    btn.addEventListener('click',function(){
      var cur=document.documentElement.getAttribute('data-theme')||'dark';
      var next=cur==='dark'?'light':'dark';
      document.documentElement.setAttribute('data-theme',next);
      localStorage.setItem(THEME_KEY,next);
      label.textContent=next;
    });
  }

  // ── Flash (server-filled IDP_FLASH_MSG) ───────────────────────────────
  // 패스키 에러(passkey-client showError) 와 동일하게 4초 후 자동 숨김.
  function autoHideFlash(flashEl){
    if(!flashEl)return;
    clearTimeout(flashEl._t);
    flashEl._t=setTimeout(function(){flashEl.classList.remove('show');},4000);
  }
  function initFlash(){
    var flashMsgEl=document.getElementById('flash-msg');
    var flashEl=document.getElementById('flash');
    if(!flashMsgEl||!flashEl)return false;
    var txt=(flashMsgEl.textContent||'').trim();
    if(txt){
      flashEl.classList.add('show');
      autoHideFlash(flashEl);
      return true;
    }
    return false;
  }

  // ── Helpers ───────────────────────────────────────────────────────────
  function setField(id,errMsg,okMsg){
    var field=document.getElementById(id);
    if(!field)return;
    field.classList.remove('error','ok');
    var errSpan=field.querySelector('[data-err]');
    var hintSpan=field.querySelector('[data-hint]');
    if(errSpan)errSpan.textContent='';
    if(hintSpan)hintSpan.textContent='';
    if(errMsg){field.classList.add('error');if(errSpan)errSpan.textContent=errMsg;}
    else if(okMsg){field.classList.add('ok');if(hintSpan)hintSpan.textContent=okMsg;}
  }
  function toggleRule(id,ok){var el=document.getElementById(id);if(el)el.classList.toggle('ok',ok);}
  function strength(pw){
    var s=0;
    if(pw.length>=8)s++;if(pw.length>=12)s++;
    if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++;
    if(/\\d/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;
    return Math.min(4,s);
  }
  var STRENGTH_LABELS=['너무 약함','약함','보통','강함','매우 강함'];
  var STRENGTH_COLORS=['#e56b6b','#e89a4e','#e8c34e','#64c88c','#64c88c'];
  function updateStrength(pw,boxId,labelId){
    var box=document.getElementById(boxId);
    var label=document.getElementById(labelId);
    if(!box)return;
    if(!pw){box.hidden=true;return;}
    box.hidden=false;
    var s=strength(pw);
    if(label){label.textContent=STRENGTH_LABELS[s];label.style.color=STRENGTH_COLORS[s];}
    box.querySelectorAll('.bar').forEach(function(b,i){
      b.style.background=i<=s?STRENGTH_COLORS[s]:'var(--border)';
    });
  }

  // ── Login ─────────────────────────────────────────────────────────────
  function initLogin(){
    // 서버가 채운 flash 메시지가 있으면 그걸 우선 표시(에러 스타일 유지).
    var hadServerFlash=initFlash();
    var meta=document.getElementById('skin-meta');
    var flash=document.getElementById('flash');
    var flashMsg=document.getElementById('flash-msg');
    if(meta&&!hadServerFlash){
      if(meta.dataset.registered==='1'&&flash&&flashMsg){
        flash.classList.add('ok','show');
        var tag=flash.querySelector('.tag');if(tag)tag.textContent='[ok]';
        flashMsg.textContent='회원가입이 완료되었습니다. 로그인해주세요.';
        autoHideFlash(flash);
      }else if(meta.dataset.pwReset==='1'&&flash&&flashMsg){
        flash.classList.add('ok','show');
        var tag2=flash.querySelector('.tag');if(tag2)tag2.textContent='[ok]';
        flashMsg.textContent='비밀번호가 재설정되었습니다. 새 비밀번호로 로그인해주세요.';
        autoHideFlash(flash);
      }
    }
    var u=document.querySelector('input[name="username"]');
    var p=document.querySelector('input[name="password"]');
    var btn=document.getElementById('submit');
    if(!u||!p||!btn)return;
    function upd(){btn.disabled=!(u.value.trim()&&p.value);}
    u.addEventListener('input',upd);p.addEventListener('input',upd);
    upd();
    // passkey button — trigger WebAuthn flow if global client is loaded
    var pkBtn=document.getElementById('passkey');
    if(pkBtn){
      pkBtn.addEventListener('click',function(){
        var w=window;
        if(typeof w.idpPasskeyLogin==='function'){
          w.idpPasskeyLogin();
        }else if(flash&&flashMsg){
          flashMsg.textContent='패스키 클라이언트를 불러올 수 없습니다.';
          flash.classList.remove('ok');flash.classList.add('show');
        }
      });
    }
  }

  // ── Signup ────────────────────────────────────────────────────────────
  function initSignup(){
    initFlash();
    var USERNAME_RE=/^[a-zA-Z0-9_]{4,20}$/;
    var EMAIL_RE=/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
    var u=document.getElementById('username');
    var e=document.getElementById('email');
    var p=document.getElementById('password');
    var c=document.getElementById('confirm');
    var btn=document.getElementById('submit');

    function applyUsername(okRes){
      var field=document.getElementById('f-username');
      if(!field)return;
      var errSpan=field.querySelector('[data-err]');
      var def=field.querySelector('[data-default]');
      field.classList.remove('error','ok');
      if(errSpan)errSpan.textContent='';
      if(def){def.textContent='// [a-zA-Z0-9_]{4,20}';def.style.color='';}
      if(!u||!u.value)return;
      if(!okRes.ok){
        field.classList.add('error');
        if(errSpan)errSpan.textContent=okRes.msg;
      }else if(def){
        def.textContent='// '+okRes.msg;
        def.style.color='var(--success)';
      }
    }

    function upd(){
      var pw=p?p.value:'';
      var uv=u?u.value:'';
      var ev=e?e.value:'';
      var cv=c?c.value:'';
      var okU=USERNAME_RE.test(uv);
      var okE=EMAIL_RE.test(ev);
      var okP=pw.length>=8&&pw.length<=64;
      var okC=cv.length>0&&cv===pw;
      applyUsername(okU?{ok:true,msg:'available'}:{ok:false,msg:uv.length<4?'4자 이상 입력해주세요':(uv.length>20?'20자 이하로 입력해주세요':'영문, 숫자, 밑줄(_)만 사용 가능합니다')});
      if(ev)setField('f-email',okE?null:'올바른 이메일 형식이 아닙니다',null);
      else setField('f-email',null,null);
      if(pw)setField('f-password',okP?null:(pw.length<8?'8자 이상 입력해주세요':'64자 이하로 입력해주세요'),null);
      else setField('f-password',null,null);
      if(cv){
        if(cv===pw)setField('f-confirm',null,'match');
        else setField('f-confirm','비밀번호가 일치하지 않습니다',null);
      }else setField('f-confirm',null,null);
      updateStrength(pw,'strength','strengthLabel');
      if(btn)btn.disabled=!(okU&&okE&&okP&&okC);
    }
    [u,e,p,c].forEach(function(el){if(el)el.addEventListener('input',upd);});
    document.querySelectorAll('.toggle-visibility').forEach(function(tvBtn){
      tvBtn.addEventListener('click',function(){
        var inp=document.getElementById(tvBtn.dataset.for);
        if(inp)inp.type=inp.type==='password'?'text':'password';
      });
    });
  }

  // ── Find-id ───────────────────────────────────────────────────────────
  function initFindId(){
    initFlash();
    var EMAIL_RE=/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
    var meta=document.getElementById('skin-meta');
    var sent=meta&&meta.dataset.findIdSent==='1';
    var masked=(meta&&meta.dataset.maskedUsername)||'';
    if(sent){
      var form=document.getElementById('form');
      if(form)form.hidden=true;
      var resultEl=document.getElementById('result');
      if(resultEl){
        if(masked){
          resultEl.className='result show hit';
          resultEl.innerHTML='<div class="result-tag">[200 OK] RESULT</div><div class="result-value">'+masked+'</div><div class="result-hint"><span class="slash">// </span>전체 아이디는 입력하신 이메일로 발송되었습니다.</div>';
        }else{
          resultEl.className='result show miss';
          resultEl.innerHTML='<div class="result-tag">[404 NOT_FOUND]</div>해당 이메일로 가입된 계정이 없습니다.';
        }
      }
    }else{
      var inp=document.getElementById('email');
      var field=document.getElementById('f-email');
      var btn=document.getElementById('submit');
      if(inp&&btn){
        inp.addEventListener('input',function(){
          var ok=EMAIL_RE.test(inp.value);
          btn.disabled=!ok;
          if(field){
            field.classList.toggle('error',inp.value.length>0&&!ok);
            var errSpan=field.querySelector('[data-err]');
            if(errSpan)errSpan.textContent=(inp.value&&!ok)?'올바른 이메일 형식이 아닙니다':'';
          }
        });
      }
    }
  }

  // ── Find-password ─────────────────────────────────────────────────────
  function initFindPassword(){
    initFlash();
    var USERNAME_RE=/^[a-zA-Z0-9_]{4,20}$/;
    var EMAIL_RE=/^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
    var meta=document.getElementById('skin-meta');
    var sent=meta&&meta.dataset.findPasswordSent==='1';
    var submittedEmail=(meta&&meta.dataset.submittedEmail)||'';
    if(sent){
      var formWrap=document.getElementById('form-wrap');
      if(formWrap)formWrap.hidden=true;
      var sentEl=document.getElementById('sent');
      if(sentEl)sentEl.hidden=false;
      var sentEmailEl=document.getElementById('sent-email');
      if(sentEmailEl&&submittedEmail)sentEmailEl.textContent=submittedEmail;
      var footer=document.getElementById('footer');
      if(footer)footer.classList.add('hide');
    }else{
      var u=document.getElementById('username');
      var e=document.getElementById('email');
      var btn=document.getElementById('submit');
      function upd(){
        var okU=u&&USERNAME_RE.test(u.value);
        var okE=e&&EMAIL_RE.test(e.value);
        if(btn)btn.disabled=!(okU&&okE);
        if(u&&u.value){
          var fU=document.getElementById('f-username');
          if(fU){fU.classList.toggle('error',!okU);var s=fU.querySelector('[data-err]');if(s)s.textContent=!okU?'영문·숫자·밑줄(_) 4~20자로 입력해주세요':'';}
        }
        if(e&&e.value){
          var fE=document.getElementById('f-email');
          if(fE){fE.classList.toggle('error',!okE);var s2=fE.querySelector('[data-err]');if(s2)s2.textContent=!okE?'올바른 이메일 형식이 아닙니다':'';}
        }
      }
      if(u)u.addEventListener('input',upd);
      if(e)e.addEventListener('input',upd);
    }
  }

  // ── MFA ───────────────────────────────────────────────────────────────
  function initMfa(){
    initFlash();
    var inputs=Array.prototype.slice.call(document.querySelectorAll('.otp input'));
    var otpVal=document.getElementById('otp-value');
    var submitBtn=document.getElementById('submit');
    var errEl=document.getElementById('err');
    function code(){return inputs.map(function(i){return i.value;}).join('');}
    function upd(){
      var c=code();
      if(otpVal)otpVal.value=c;
      if(submitBtn)submitBtn.disabled=c.length!==6;
      if(errEl)errEl.classList.remove('show');
    }
    inputs.forEach(function(inp,i){
      inp.addEventListener('input',function(){
        if(inp.value&&!/^\\d$/.test(inp.value)){inp.value='';upd();return;}
        if(inp.value&&i<5)inputs[i+1].focus();
        upd();
      });
      inp.addEventListener('keydown',function(ev){
        if(ev.key==='Backspace'){if(!inp.value&&i>0){inputs[i-1].focus();inputs[i-1].value='';upd();}}
        else if(ev.key==='ArrowLeft'&&i>0)inputs[i-1].focus();
        else if(ev.key==='ArrowRight'&&i<5)inputs[i+1].focus();
      });
      inp.addEventListener('paste',function(ev){
        var txt=(ev.clipboardData.getData('text')||'').replace(/\\D/g,'').slice(0,6);
        if(!txt)return;
        ev.preventDefault();
        inputs.forEach(function(x,j){x.value=txt[j]||'';});
        inputs[Math.min(txt.length,5)].focus();
        upd();
      });
      inp.addEventListener('focus',function(){inp.select();});
    });
    if(inputs.length>0){inputs[0].focus();upd();}
  }

  // ── Reset-password ────────────────────────────────────────────────────
  function initResetPassword(){
    initFlash();
    var params=new URLSearchParams(location.search);
    var token=params.get('token')||'';
    var tokenPreview=document.getElementById('token-preview');
    if(tokenPreview&&token){
      tokenPreview.textContent=token.length>16?token.slice(0,6)+'\\u2026'+token.slice(-4):token;
    }
    if(token){
      try{
        params.delete('token');
        var qs=params.toString();
        var newUrl=location.pathname+(qs?('?'+qs):'')+location.hash;
        history.replaceState(null,'',newUrl);
      }catch(_){}
    }
    document.querySelectorAll('.toggle-visibility').forEach(function(tvBtn){
      tvBtn.addEventListener('click',function(){
        var inp=document.getElementById(tvBtn.dataset.for);
        if(inp)inp.type=inp.type==='password'?'text':'password';
      });
    });
    var p=document.getElementById('password');
    var c=document.getElementById('confirm');
    var btn=document.getElementById('submit');
    function upd(){
      var pw=p?p.value:'';
      var conf=c?c.value:'';
      var okP=pw.length>=8&&pw.length<=64;
      var okC=conf.length>0&&conf===pw;
      toggleRule('r-len',pw.length>=8&&pw.length<=64);
      toggleRule('r-mix',/[A-Za-z]/.test(pw)&&/\\d/.test(pw));
      toggleRule('r-special',/[^A-Za-z0-9]/.test(pw));
      updateStrength(pw,'strength','strengthLabel');
      if(p&&p.value)setField('f-password',okP?null:(pw.length<8?'8자 이상 입력해주세요':'64자 이하로 입력해주세요'),null);
      else setField('f-password',null,null);
      if(c&&c.value){
        if(c.value===pw)setField('f-confirm',null,'match');
        else setField('f-confirm','비밀번호가 일치하지 않습니다',null);
      }else setField('f-confirm',null,null);
      if(btn)btn.disabled=!(okP&&okC);
    }
    if(p)p.addEventListener('input',upd);
    if(c)c.addEventListener('input',upd);
  }

  // ── Logout ────────────────────────────────────────────────────────────
  // 로그아웃 스킨은 화면을 보여주는 것이 목적이 아니라 POST 를 일으키는 것이 목적이다.
  // 기본 UI 와 같게 폼을 자동 제출하고, 폼이 없으면 아무것도 하지 않는다.
  function initLogout(){
    initFlash();
    var form=document.getElementById('form')||document.querySelector('form');
    if(!form)return;
    if(typeof form.requestSubmit==='function')form.requestSubmit();
    else form.submit();
  }

  // ── Dispatch ──────────────────────────────────────────────────────────
  function run(){
    initTheme();
    var shell=document.querySelector('.auth-shell');
    var skinType=shell?(shell.dataset.skinType||''):'';
    if(skinType==='login')initLogin();
    else if(skinType==='signup')initSignup();
    else if(skinType==='find_id')initFindId();
    else if(skinType==='find_password')initFindPassword();
    else if(skinType==='mfa')initMfa();
    else if(skinType==='reset_password')initResetPassword();
    else if(skinType==='logout')initLogout();
    else initFlash();
  }

  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',run);}
  else{run();}
})();`;

export const GET: RequestHandler = () =>
    new Response(JS, {
        headers: {
            "Content-Type": "application/javascript; charset=utf-8",
            "Cache-Control": "public, max-age=3600",
        },
    });
