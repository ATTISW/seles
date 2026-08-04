(() => {
  const esc = value => String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const date = value => new Date(Number(value) * 1000).toLocaleString('ru-RU');
  const api = async (url, options={}) => {
    const response = await fetch(url, {headers:{'Content-Type':'application/json',...(options.headers||{})},...options});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Ошибка запроса');
    return data;
  };
  const style=document.createElement('style');
  style.textContent=`
    #msGate{position:fixed;inset:0;z-index:10000;background:radial-gradient(circle at 85% 10%,rgba(200,117,82,.18),transparent 30rem),#f3f0e8;display:grid;place-items:center;padding:20px}
    .ms-auth{width:min(430px,100%);background:#fffdf8;border:1px solid #dcd9cf;border-radius:26px;padding:34px;box-shadow:0 24px 70px rgba(23,50,74,.15)}
    .ms-auth h1{font-size:34px;margin:12px 0 8px}.ms-auth p{color:#456071;line-height:1.5}.ms-form{display:grid;gap:12px;margin-top:24px}
    .ms-input,.ms-textarea,.ms-select{width:100%;border:1px solid #dcd9cf;border-radius:12px;padding:12px 14px;background:#fff;color:#17324a;user-select:text}.ms-textarea{min-height:100px;resize:vertical}
    .ms-primary,.ms-secondary,.ms-danger{border:0;border-radius:12px;padding:11px 15px;font-weight:800;cursor:pointer}.ms-primary{background:#17324a;color:#fff}.ms-secondary{background:#e4ece6;color:#17324a}.ms-danger{background:#f5e5dc;color:#a3534c}
    .ms-error{min-height:20px;color:#a3534c;font-size:13px}.ms-note{font-size:12px;color:#456071}
    #msAccount{display:flex;gap:8px;align-items:center}.ms-user{font-size:12px;font-weight:800;padding:8px 11px;background:#e4ece6;border-radius:999px}
    #msPanel{position:fixed;inset:0;z-index:9000;background:rgba(23,50,74,.42);display:none;align-items:stretch;justify-content:flex-end}
    #msPanel.open{display:flex}.ms-drawer{width:min(720px,100%);background:#f3f0e8;padding:24px;overflow:auto;box-shadow:-20px 0 60px rgba(23,50,74,.16)}
    .ms-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.ms-head h2{margin:0}.ms-tabs{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}.ms-tab{border:1px solid #dcd9cf;background:#fffdf8;padding:9px 12px;border-radius:999px;cursor:pointer;font-weight:750}.ms-tab.active{background:#17324a;color:#fff}
    .ms-section{display:none}.ms-section.active{display:block}.ms-card{background:#fffdf8;border:1px solid #dcd9cf;border-radius:16px;padding:16px;margin:10px 0}.ms-card p{white-space:pre-wrap;line-height:1.5}.ms-meta{color:#456071;font-size:12px}.ms-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.ms-form-card{display:grid;gap:10px;margin-bottom:18px}.ms-code{font:800 22px ui-monospace,monospace;letter-spacing:.08em;background:#e4ece6;padding:14px;border-radius:12px;user-select:text}.ms-badge{padding:4px 8px;border-radius:999px;background:#e5edf1;font-size:11px;font-weight:800}.ms-badge.blocked{background:#f5e5dc;color:#a3534c}
    @media(max-width:650px){.ms-auth{padding:24px}.topbar{padding:0 12px}.mode-switch{display:none}.ms-drawer{padding:16px}}
  `;document.head.appendChild(style);

  document.body.insertAdjacentHTML('beforeend',`
    <div id="msGate"><section class="ms-auth"><div class="eyebrow">Закрытый доступ</div><h1>MS NAVIGATOR</h1><p>Введите свой логин и пароль. Для первого входа придумайте логин и используйте одноразовый пароль, полученный у администратора.</p><form id="msLogin" class="ms-form"><input class="ms-input" name="login" autocomplete="username" placeholder="Логин" required minlength="3"><input class="ms-input" name="password" type="password" autocomplete="current-password" placeholder="Пароль" required minlength="8"><button class="ms-primary">Войти</button><div id="msLoginError" class="ms-error"></div></form><div class="ms-note">Кнопки регистрации нет. Один пароль активации создает только одну учетную запись.</div></section></div>
    <div id="msPanel"><aside class="ms-drawer"><div class="ms-head"><h2>Личный кабинет</h2><button id="msClose" class="ms-secondary">Закрыть</button></div><div id="msTabs" class="ms-tabs"></div><section id="msComments" class="ms-section"></section><section id="msHomework" class="ms-section"></section><section id="msAdmin" class="ms-section"></section><section id="msSecurity" class="ms-section"></section></aside></div>
  `);
  const gate=document.querySelector('#msGate'), panel=document.querySelector('#msPanel'); let user=null;
  const say=e=>alert(e.message||e);

  async function boot(){
    const data=await api('/api/me'); user=data.user;
    if(!user){gate.style.display='grid';return}
    gate.style.display='none'; mountAccount(); buildTabs();
  }
  function mountAccount(){
    let host=document.querySelector('.top-actions');
    let box=document.querySelector('#msAccount'); if(box)box.remove();
    host.insertAdjacentHTML('beforeend',`<div id="msAccount"><button id="msCabinet" class="ms-secondary">Кабинет</button><span class="ms-user">${esc(user.login)} · ${user.role==='admin'?'админ':'пользователь'}</span><button id="msLogout" class="ms-danger">Выйти</button></div>`);
    document.querySelector('#msCabinet').onclick=()=>{panel.classList.add('open');openTab('comments')};
    document.querySelector('#msLogout').onclick=async()=>{await api('/api/logout',{method:'POST',body:'{}'});location.reload()};
  }
  function buildTabs(){
    const tabs=[['comments','Комментарии'],['homework',user.role==='admin'?'Домашние задания':'Сдать домашнее задание'],...(user.role==='admin'?[['admin','Администрирование']]:[]),['security','Пароль']];
    document.querySelector('#msTabs').innerHTML=tabs.map(([id,label])=>`<button class="ms-tab" data-tab="${id}">${label}</button>`).join('');
    document.querySelectorAll('.ms-tab').forEach(b=>b.onclick=()=>openTab(b.dataset.tab));
  }
  async function openTab(name){
    document.querySelectorAll('.ms-tab,.ms-section').forEach(x=>x.classList.remove('active'));
    document.querySelector(`[data-tab="${name}"]`)?.classList.add('active');document.querySelector(`#ms${name[0].toUpperCase()+name.slice(1)}`)?.classList.add('active');
    try{if(name==='comments')await comments();if(name==='homework')await homework();if(name==='admin')await admin();if(name==='security')security()}catch(e){say(e)}
  }
  async function comments(){
    const data=await api('/api/comments'); const root=document.querySelector('#msComments');
    root.innerHTML=`<form id="msCommentForm" class="ms-card ms-form-card"><h3>Новый комментарий</h3><textarea class="ms-textarea" name="body" maxlength="3000" required placeholder="Ваш комментарий"></textarea><button class="ms-primary">Опубликовать</button></form>`+data.items.map(x=>`<article class="ms-card"><div class="ms-meta">${esc(x.login)} · ${date(x.created_at)}</div><p>${esc(x.body)}</p></article>`).join('');
    root.querySelector('form').onsubmit=async e=>{e.preventDefault();try{await api('/api/comments',{method:'POST',body:JSON.stringify({body:e.target.body.value})});comments()}catch(x){say(x)}};
  }
  async function fileData(file){if(!file)return null;if(file.size>5*1024*1024)throw Error('Файл больше 5 МБ');return new Promise((ok,no)=>{const r=new FileReader();r.onload=()=>ok({name:file.name,type:file.type,data:String(r.result).split(',')[1]});r.onerror=no;r.readAsDataURL(file)})}
  const status={submitted:'На проверке',accepted:'Принято',revision:'На доработку'};
  async function homework(){
    const data=await api('/api/homework');const root=document.querySelector('#msHomework');
    const form=user.role==='admin'?'':`<form id="msHwForm" class="ms-card ms-form-card"><h3>Сдать домашнее задание</h3><input class="ms-input" name="title" maxlength="150" required placeholder="Название задания"><textarea class="ms-textarea" name="body" maxlength="10000" placeholder="Текст или пояснение"></textarea><label class="ms-note">Файл до 5 МБ <input name="file" type="file"></label><button class="ms-primary">Отправить</button></form>`;
    root.innerHTML=form+data.items.map(x=>`<article class="ms-card"><div class="ms-row"><strong>${esc(x.title)}</strong><span class="ms-badge">${status[x.status]||esc(x.status)}</span></div><div class="ms-meta">${esc(x.login)} · ${date(x.created_at)}</div><p>${esc(x.body)}</p>${x.filename?`<a href="/api/homework/file/${x.id}">Скачать: ${esc(x.filename)}</a>`:''}${x.admin_note?`<p><strong>Комментарий администратора:</strong> ${esc(x.admin_note)}</p>`:''}${user.role==='admin'?`<div class="ms-form-card"><select class="ms-select" data-status="${x.id}"><option value="submitted">На проверке</option><option value="accepted">Принято</option><option value="revision">На доработку</option></select><textarea class="ms-textarea" data-note="${x.id}" placeholder="Комментарий администратора">${esc(x.admin_note)}</textarea><button class="ms-primary" data-review="${x.id}">Сохранить проверку</button></div>`:''}</article>`).join('');
    if(user.role!=='admin')root.querySelector('form').onsubmit=async e=>{e.preventDefault();try{const attachment=await fileData(e.target.file.files[0]);await api('/api/homework',{method:'POST',body:JSON.stringify({title:e.target.title.value,body:e.target.body.value,attachment})});homework()}catch(x){say(x)}};
    root.querySelectorAll('[data-review]').forEach(b=>b.onclick=async()=>{const id=b.dataset.review;try{await api('/api/admin/homework',{method:'POST',body:JSON.stringify({id,status:root.querySelector(`[data-status="${id}"]`).value,note:root.querySelector(`[data-note="${id}"]`).value})});homework()}catch(x){say(x)}});
    data.items.forEach(x=>{const sel=root.querySelector(`[data-status="${x.id}"]`);if(sel)sel.value=x.status});
  }
  async function admin(){
    const data=await api('/api/admin');const root=document.querySelector('#msAdmin');
    root.innerHTML=`<div class="ms-card"><h3>Одноразовый пароль активации</h3><p class="ms-note">Создайте пароль и передайте его одному пользователю. После первого входа повторно использовать его нельзя.</p><button id="msNewCode" class="ms-primary">Создать пароль</button><div id="msCodeOut"></div></div><h3>Пользователи</h3>`+data.users.map(x=>`<div class="ms-card ms-row"><strong>${esc(x.login)}</strong><span class="ms-badge ${x.blocked?'blocked':''}">${x.role==='admin'?'Администратор':x.blocked?'Заблокирован':'Активен'}</span><span class="ms-meta">${date(x.created_at)}</span>${x.role!=='admin'?`<button class="${x.blocked?'ms-secondary':'ms-danger'}" data-block="${x.id}" data-value="${x.blocked?'0':'1'}">${x.blocked?'Разблокировать':'Заблокировать'}</button>`:''}</div>`).join('');
    root.querySelector('#msNewCode').onclick=async()=>{try{const x=await api('/api/admin/code',{method:'POST',body:'{}'});root.querySelector('#msCodeOut').innerHTML=`<p class="ms-code">${esc(x.code)}</p><p class="ms-note">Скопируйте сейчас: после закрытия код больше не показывается.</p>`}catch(e){say(e)}};
    root.querySelectorAll('[data-block]').forEach(b=>b.onclick=async()=>{try{await api('/api/admin/block',{method:'POST',body:JSON.stringify({id:b.dataset.block,blocked:b.dataset.value==='1'})});admin()}catch(e){say(e)}});
  }
  function security(){const root=document.querySelector('#msSecurity');root.innerHTML=`<form class="ms-card ms-form-card"><h3>Сменить пароль</h3><input class="ms-input" name="password" type="password" minlength="10" required autocomplete="new-password" placeholder="Новый пароль — минимум 10 символов"><button class="ms-primary">Сохранить</button></form>`;root.querySelector('form').onsubmit=async e=>{e.preventDefault();try{await api('/api/password',{method:'POST',body:JSON.stringify({password:e.target.password.value})});e.target.reset();alert('Пароль изменен')}catch(x){say(x)}}}
  document.querySelector('#msClose').onclick=()=>panel.classList.remove('open');panel.onclick=e=>{if(e.target===panel)panel.classList.remove('open')};
  document.querySelector('#msLogin').onsubmit=async e=>{e.preventDefault();const out=document.querySelector('#msLoginError');out.textContent='';try{await api('/api/login',{method:'POST',body:JSON.stringify({login:e.target.login.value,password:e.target.password.value})});await boot()}catch(x){out.textContent=x.message}};
  boot().catch(e=>{document.querySelector('#msLoginError').textContent='Сервис временно недоступен: '+e.message});
})();
