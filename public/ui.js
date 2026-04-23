window.UI = {
  _createOverlay: () => {
    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-[9999] flex items-center justify-center p-6 opacity-0 transition-opacity duration-200';
    document.body.appendChild(overlay);
    requestAnimationFrame(() => overlay.classList.remove('opacity-0'));
    return overlay;
  },
  _closeModal: (overlay) => {
    overlay.classList.add('opacity-0');
    setTimeout(() => overlay.remove(), 200);
  },
  alert: (message) => {
    return new Promise(resolve => {
      const overlay = UI._createOverlay();
      overlay.innerHTML = `
        <div class="bg-slate-900 border border-slate-800 p-8 w-full max-w-sm rounded-[2rem] shadow-2xl transform transition-transform scale-95 duration-200">
           <h3 class="text-xl font-bold mb-4 flex items-center gap-2 text-white">
             <i data-lucide="bell" class="w-5 h-5 text-indigo-400"></i> Registry Note
           </h3>
           <p class="text-slate-400 mb-8 whitespace-pre-wrap">${message}</p>
           <button class="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-bold transition-all shadow-lg shadow-indigo-600/20" id="ui-ok-btn">Understood</button>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons({ root: overlay });
      requestAnimationFrame(() => overlay.firstElementChild.classList.remove('scale-95'));
      const close = () => { UI._closeModal(overlay); resolve(); };
      const btn = overlay.querySelector('#ui-ok-btn');
      btn.onclick = close;
      btn.focus();
    });
  },
  confirm: (message) => {
    return new Promise(resolve => {
      const overlay = UI._createOverlay();
      overlay.innerHTML = `
        <div class="bg-slate-900 border border-slate-800 p-8 w-full max-w-sm rounded-[2rem] shadow-2xl transform transition-transform scale-95 duration-200">
           <h3 class="text-xl font-bold mb-4 flex items-center gap-2 text-amber-500">
             <i data-lucide="alert-triangle" class="w-5 h-5 text-amber-500"></i> Action Required
           </h3>
           <p class="text-slate-400 mb-8 whitespace-pre-wrap">${message}</p>
           <div class="flex gap-3">
              <button class="flex-1 py-3 rounded-xl font-bold border border-slate-700 hover:bg-slate-800 transition-colors text-white" id="ui-cancel-btn">Cancel</button>
              <button class="flex-1 bg-amber-500 hover:bg-amber-400 text-slate-900 py-3 rounded-xl font-bold transition-all shadow-lg shadow-amber-500/20" id="ui-ok-btn">Confirm</button>
           </div>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons({ root: overlay });
      requestAnimationFrame(() => overlay.firstElementChild.classList.remove('scale-95'));
      overlay.querySelector('#ui-cancel-btn').onclick = () => { UI._closeModal(overlay); resolve(false); };
      const okBtn = overlay.querySelector('#ui-ok-btn');
      okBtn.onclick = () => { UI._closeModal(overlay); resolve(true); };
      okBtn.focus();
    });
  },
  prompt: (message, defaultVal = '') => {
    return new Promise(resolve => {
      const overlay = UI._createOverlay();
      overlay.innerHTML = `
        <div class="bg-slate-900 border border-slate-800 p-8 w-full max-w-md rounded-[2rem] shadow-2xl transform transition-transform scale-95 duration-200">
           <h3 class="text-xl font-bold mb-4 text-white flex items-center gap-2">
             <i data-lucide="edit-3" class="w-5 h-5 text-indigo-400"></i> Input Required
           </h3>
           <p class="text-slate-400 mb-4 whitespace-pre-wrap text-sm">${message}</p>
           <input type="text" id="ui-prompt-input" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white mb-8 focus:border-indigo-500 focus:outline-none" value="${defaultVal}">
           <div class="flex gap-3">
              <button class="flex-1 py-3 rounded-xl font-bold border border-slate-700 hover:bg-slate-800 transition-colors text-white" id="ui-cancel-btn">Cancel</button>
              <button class="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-bold transition-all shadow-lg shadow-indigo-600/20" id="ui-ok-btn">Submit</button>
           </div>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons({ root: overlay });
      const input = overlay.querySelector('#ui-prompt-input');
      requestAnimationFrame(() => {
        overlay.firstElementChild.classList.remove('scale-95');
        input.focus();
      });
      overlay.querySelector('#ui-cancel-btn').onclick = () => { UI._closeModal(overlay); resolve(null); };
      const ok = () => { 
        const val = input.value;
        UI._closeModal(overlay); resolve(val); 
      };
      overlay.querySelector('#ui-ok-btn').onclick = ok;
      input.addEventListener('keypress', e => { if (e.key==='Enter') ok(); });
    });
  },
  promptDeploy: () => {
    return new Promise(resolve => {
      const overlay = UI._createOverlay();
      overlay.innerHTML = `
        <div class="bg-slate-900 border border-slate-800 p-8 w-full max-w-md rounded-[2rem] shadow-2xl transform transition-transform scale-95 duration-200">
           <h3 class="text-xl font-bold mb-4 text-white flex items-center gap-2">
             <i data-lucide="rocket" class="w-5 h-5 text-indigo-400"></i> Deploy to Production
           </h3>
           <p class="text-slate-400 mb-6 text-sm">Bundle currently in Staging will be marked as immutable with the version and name provided below.</p>
           
           <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Semantic Version</label>
           <input type="text" id="ui-deploy-version" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white mb-4 focus:border-indigo-500 focus:outline-none" placeholder="1.0.0">
           
           <label class="block text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Release Name / Changelog</label>
           <input type="text" id="ui-deploy-name" class="w-full bg-slate-950 border border-slate-800 rounded-xl px-4 py-3 text-white mb-8 focus:border-indigo-500 focus:outline-none" placeholder="e.g. Navigation Fixes">
           
           <div class="flex gap-3">
              <button class="flex-1 py-3 rounded-xl font-bold border border-slate-700 hover:bg-slate-800 transition-colors text-white" id="ui-cancel-btn">Cancel</button>
              <button class="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-bold transition-all shadow-lg shadow-indigo-600/20" id="ui-ok-btn">Deploy</button>
           </div>
        </div>
      `;
      if (window.lucide) window.lucide.createIcons({ root: overlay });
      const inputVer = overlay.querySelector('#ui-deploy-version');
      const inputName = overlay.querySelector('#ui-deploy-name');
      requestAnimationFrame(() => {
        overlay.firstElementChild.classList.remove('scale-95');
        inputVer.focus();
      });
      overlay.querySelector('#ui-cancel-btn').onclick = () => { UI._closeModal(overlay); resolve(null); };
      const ok = () => { 
        if (!inputVer.value || !inputName.value) return; 
        UI._closeModal(overlay); resolve({ version: inputVer.value, name: inputName.value }); 
      };
      overlay.querySelector('#ui-ok-btn').onclick = ok;
    });
  }
};
