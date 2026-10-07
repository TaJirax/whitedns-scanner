const {chromium} = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const repo = path.resolve(__dirname,'../..');
const frontend = path.join(repo,'go/cmd/scanner-gui/frontend/dist');
const output = path.join(repo,'build/gui/audit-fixed');
fs.mkdirSync(output,{recursive:true});
const edge = path.join(process.env['ProgramFiles(x86)'] || 'C:/Program Files (x86)','Microsoft/Edge/Application/msedge.exe');
const executablePath = process.env.WHITEDNS_BROWSER || (process.platform==='win32' && fs.existsSync(edge) ? edge : undefined);

async function installFixture(page) {
  await page.addInitScript(() => {
    const names = {'http':'Default Ports (443/80 only)','http-all':'All Cloudflare Ports (13 ports)','custom':'Custom ports','dns':'DNS Resolver Discovery','dns-udptcp':'DNS UDP/TCP only','txt':'TXT Resolver Probe','sni':'SNI scan','http-proxy':'HTTP proxy','socks-proxy':'SOCKS proxy'};
    const settings = {theme:'dark',accent:'purple',targets:Object.fromEntries(Object.keys(names).map(id=>[id,{targetsText:'192.0.2.1',customPorts:id==='custom'?'443':''}])),outputDir:'Scan reports',cacheFile:'last_passed.txt',timeoutSecs:10,retryCount:2,userAgent:'WhiteDNS',spoofedSni:'forged.example',autoConcurrency:true,maxConcurrent:5000,minConcurrent:200,streaming:false,streamingAuto:true,streamingThreshold:50000,streamingSizeMb:64,countTotal:false,targetDomain:'google.com',dnsMaxPingMs:20000,dnsTxtDomain:'txt.example.com',dnsRate:0,dnsRatePerResolver:0,dnsBurst:1,dnsJitter:0,proxyTestUrl:'https://example.com/',speedTestUrl:'https://example.com/file',speedDurationSecs:10,speedMaxSizeMb:25};
    const events={};
    const zero={state:'IDLE',mode:'http',done:0,total:0,counts:{},recent:[],runDir:'',viewing:'',ratePerS:0,elapsedS:0,etaS:0,message:''};
    window.mock={settings,stats:{...zero},calls:[],queries:[],shift:0,delay:0,inFlight:0,copy:'',emit(name,data){Object.assign(this.stats,data);for(const fn of events[name]||[])fn(structuredClone(this.stats));},row(seq){return {seq,label:'192.0.2.'+seq,url:'https://example.com:443',ip:'192.0.2.1',port:443,status:200,latencyMs:42,error:'',protocol:'',category:'ok'};}};
    const providers=[{id:'cloudflare',name:'Cloudflare',modes:['http','http-all','custom'],hosts:['edge.example.com'],platformDomains:['workers.dev','pages.dev'],probeDomains:['workers.dev','pages.dev','gemini.google.com','notebooklm.google.com','instagram.com','chatgpt.com','web.telegram.org','reddit.com','claude.ai']},{id:'custom',name:'Other / custom CDN',modes:['http','custom'],hosts:[],platformDomains:[],probeDomains:[]}];
    const runs=[{mode:'http',dir:'Scan reports/http/run',started:'2026-10-06T10:00:00Z',finished:'2026-10-06T10:01:00Z',state:'completed',done:250,total:250,counts:{all:250,ok:250},message:'Reports ready',targets:'192.0.2.0/24',hasResults:true,files:[{name:'results.csv',path:'Scan reports/http/run/results.csv',kind:'All results (CSV)',size:20000,lines:251}]}];
    const api={
      async GetScanModes(){return Object.entries(names).map(([id,name])=>({id,name}));},async GetEdgeProviders(){return providers;},
      async GetSettings(){return structuredClone(settings);},async GetStats(){return structuredClone(mock.stats);},
      async SaveSettings(s){Object.assign(settings,structuredClone(s));mock.calls.push({method:'save',settings:structuredClone(s)});},
      async StartScan(mode,s){mock.calls.push({method:'start',mode,settings:structuredClone(s)});mock.emit('scan:stats',{...zero,state:'RUNNING',mode,total:100,runDir:'Scan reports/'+mode+'/run'});},
      async PauseScan(){mock.emit('scan:stats',{state:'PAUSED'});},async ResumeScan(){mock.emit('scan:stats',{state:'RUNNING'});},async StopScan(){mock.emit('scan:done',{state:'STOPPED'});},
      async QueryResults(q){const shift=mock.shift;mock.queries.push(structuredClone(q));mock.inFlight++;if(mock.delay)await new Promise(r=>setTimeout(r,mock.delay));mock.inFlight--;return {rows:Array.from({length:q.limit},(_,i)=>mock.row(q.offset+i+1+shift)),total:100000,counts:{all:100000,ok:100000}};},
      async ExportResults(q){mock.export=structuredClone(q);return 'Exported all matching results';},async ListRuns(){return runs;},async ReadReport(){return 'saved report';},
      async SearchASNs(q,f){mock.asnQueries=(mock.asnQueries||[]).concat([[q,f]]);const all=[{asn:'AS58224',name:'Iran Telecommunication Company PJS',domain:'tci.ir',type:'isp',country:'IR',ipv4:120,ipv6:4},{asn:'AS44244',name:'Iran Cell Service and Communication Company',domain:'mtnirancell.ir',type:'isp',country:'IR',ipv4:80,ipv6:0}].concat(Array.from({length:400},(_,i)=>({asn:'AS9'+i,name:'Filler network '+i,type:'hosting',country:'DE',ipv4:1,ipv6:0})));return all.filter(a=>(f!=='ipv6'||a.ipv6)&&(!q||(a.asn+a.name).toLowerCase().includes(q.toLowerCase())));},
      async ExportASNs(ids,f){mock.asnExport=[ids,f];return 'Exported 512 IPs from '+ids.length+' ASNs to Scan reports/asn_ips.txt';},
      async ConfigMakerInspect(c,t){const n=x=>x.split(String.fromCharCode(10)).filter(l=>l.trim()).length;return {configs:c.includes('://')?n(c):0,summary:c.includes('://')?n(c)+' vless':'',targets:t.split(String.fromCharCode(10)).filter(l=>/:[0-9]+$/.test(l.trim())).length};},
      async ConfigMakerRewrite(c,t){mock.rewrite=[c,t];return {text:'vless://u@104.16.0.1:443#1'+String.fromCharCode(10)+'vless://u@104.16.0.2:443#2',count:2,path:'Scan reports/Config maker/rewritten-1.txt',wireguard:0};},
      async ConfigMakerExtract(c){return {text:'1.2.3.4:443',count:1,path:'Scan reports/Config maker/extracted-ips-1.txt'};},
      async PickInputFile(){return 'C:/configs.txt';},async ReadTextFile(p){return 'vless://u@old.example:443#from-file';},
      async CleanIPs(){return '104.16.0.1:443'+String.fromCharCode(10)+'104.16.0.2:443';},
      async DeleteResults(q,seqs){mock.deleted=(mock.deleted||[]).concat([[structuredClone(q),seqs]]);return seqs.length||100000;},
      async TestSpeed(q){mock.speedRequest=q;return {downloadMbps:42.5,bytes:1048576,elapsedS:0.2,latencyMs:40};},async CancelSpeedTest(){},async OpenPath(){},
    };
    window.go={main:{App:api}};
    window.runtime={EventsOn(name,fn){(events[name]||=[]).push(fn);},async ClipboardSetText(text){mock.copy=text;return true;}};
  });
}

async function run() {
  const server=http.createServer((request,response)=>{
    const filename=path.resolve(frontend,'.'+(request.url==='/'?'/index.html':request.url));
    if(!filename.startsWith(frontend+path.sep)){response.writeHead(403);return response.end();}
    const mime={'.js':'text/javascript','.css':'text/css','.png':'image/png','.html':'text/html'};
    try{response.setHeader('Content-Type',mime[path.extname(filename)]||'application/octet-stream');response.end(fs.readFileSync(filename));}catch{response.writeHead(404);response.end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const browser=await chromium.launch({headless:true,executablePath});
  const context=await browser.newContext({viewport:{width:1240,height:800}});
  const page=await context.newPage();
  const errors=[],evidence={browser:await browser.version(),contrast:[],responsive:[],touch:[],performance:{}};
  page.on('pageerror',error=>errors.push(error.message));
  await installFixture(page);
  const go=async mode=>{
    const route=['http','http-all','custom'].includes(mode)?'clean-ip':['http-proxy','socks-proxy'].includes(mode)?'proxies':['dns','dns-udptcp','txt'].includes(mode)?'dns-scans':mode;
    if(await page.locator('#mobileNav').isVisible())await page.locator('#mobileNav').selectOption(route);
    else await page.locator('#nav [data-workspace="'+route+'"],#nav [data-page="'+route+'"]').click();
    if(['http','http-all','custom','http-proxy','socks-proxy','dns','dns-udptcp','txt'].includes(mode))await page.locator('[data-scan-mode="'+mode+'"]').click();
  };
  const axe=async()=>{
    const violations=await page.evaluate(async()=>(await axe.run(document,{runOnly:{type:'tag',values:['wcag2a','wcag2aa','wcag21aa','wcag22aa','best-practice']}})).violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})));
    assert.deepEqual(violations,[]);
  };
  try {
    await page.goto('http://127.0.0.1:'+server.address().port+'/');await page.waitForSelector('#startScan');
    await page.addScriptTag({path:require.resolve('axe-core/axe.min.js')});
    for(const mode of ['http','http-all','custom','sni','http-proxy','socks-proxy','dns','dns-udptcp','txt','edge-domains','settings','reports','speed']){await go(mode);await axe();}
    assert.equal(await page.locator('.nav-item span').first().evaluate(el=>getComputedStyle(el).fontWeight),'600');
    await go('custom');await page.locator('[data-setting=customPorts]').fill('70000');await page.locator('#startScan').click();
    const portError=await page.locator('[data-setting=customPorts]').getAttribute('aria-errormessage');
    assert.match(await page.locator('#'+portError).innerText(),/Port out of range: 70000/);
    assert.match(await page.locator('[data-setting=customPorts]').getAttribute('aria-describedby'),new RegExp(portError));
    assert.equal(await page.evaluate(()=>mock.calls.filter(c=>c.method==='start').length),0);
    await page.locator('[data-setting=customPorts]').fill('443');
    await go('settings');await page.locator('[data-setting=timeoutSecs]').fill('0');
    assert.match(await page.locator('#field-timeoutSecs-error').innerText(),/at least 1/);await page.locator('[data-setting=timeoutSecs]').fill('10');

    // Live activity opens on the scan log; it renders untrusted text inertly and colours each level.
    await go('sni');await page.evaluate(()=>mock.emit('scan:stats',{state:'RUNNING',mode:'sni',total:100,done:1,runDir:'Scan reports/sni/live',recent:[mock.row(1)],log:[{seq:1,at:'10:00:00',level:'info',text:'2,495,462 targets to scan'},{seq:2,at:'10:00:03',level:'fail',text:'Failed 192.0.2.1:443 · <b>TCP_FAILED</b>'},{seq:3,at:'10:00:04',level:'ok',text:'Passed 192.0.2.2:443 · 3/9 service domains · 312 ms'}]}));
    await page.waitForFunction(()=>document.querySelectorAll('#scanLog li').length===3);
    assert.equal(await page.locator('#scanLog .log-fail span').innerText(),'Failed 192.0.2.1:443 · <b>TCP_FAILED</b>');
    assert.equal(await page.locator('#scanLog .log-ok').count(),1);assert.equal(await page.locator('#activityFeed').isVisible(),false);
    assert.match(await page.locator('#progressCount').innerText(),/1 of 100/);await axe();
    await page.locator('[data-action=feed-view][data-view=hits]').click();
    await page.waitForSelector('[data-action=inspect-feed]');await axe();
    await page.mouse.move(0,0);await page.locator('[data-action=copy-feed]').focus();
    await page.evaluate(()=>{window.focusedAction=document.activeElement;mock.emit('scan:stats',{done:2,recent:[mock.row(2),mock.row(1)]});});
    await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>document.activeElement===focusedAction),true);
    await page.keyboard.press('Enter');await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>mock.copy),'192.0.2.1');
    await page.locator('#startScan').evaluate(el=>el.blur());await page.locator('[data-setting=targetsText]').focus();
    await page.waitForFunction(()=>document.querySelectorAll('[data-feed]').length===2);
    await page.locator('[data-action=inspect-feed]').first().focus();await page.keyboard.press('Enter');assert.equal(await page.locator('#drawer').isVisible(),true);await page.keyboard.press('Escape');

    await go('results');await page.waitForSelector('[data-result="0"]');await axe();
    assert.equal(await page.locator('[role=tablist]').count(),0);assert.equal(await page.locator('[aria-label="Result categories"]').getAttribute('role'),'group');
    await page.locator('[data-tab=ok]').focus();await page.keyboard.press('Enter');await page.waitForTimeout(100);assert.equal(await page.locator('[data-tab=ok]').getAttribute('aria-pressed'),'true');
    await page.mouse.move(0,0);await page.locator('[data-action=copy-row]').first().focus();
    await page.evaluate(()=>{window.focusedAction=document.activeElement;mock.shift=1;});await page.waitForTimeout(1400);
    assert.equal(await page.evaluate(()=>document.activeElement===focusedAction),true);await page.keyboard.press('Enter');await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>mock.copy),'192.0.2.1');
    await page.locator('#resultSearch').focus();await page.waitForFunction(()=>document.querySelector('#resultRows tr:first-child td').textContent==='192.0.2.2');
    await page.evaluate(()=>{mock.delay=300;mock.shift=2;});await page.locator('[data-action=refresh-results]').click();await page.waitForFunction(()=>mock.inFlight>0);
    await page.locator('[data-action=copy-row]').first().focus();await page.evaluate(()=>window.focusedAction=document.activeElement);await page.waitForTimeout(400);
    assert.equal(await page.evaluate(()=>document.activeElement===focusedAction),true);await page.keyboard.press('Enter');await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>mock.copy),'192.0.2.2');
    await page.locator('#resultSearch').focus();await page.waitForFunction(()=>document.querySelector('#resultRows tr:first-child td').textContent==='192.0.2.3');
    await page.evaluate(()=>{mock.delay=0;mock.emit('scan:done',{state:'STOPPED'});});await page.waitForTimeout(100);
    await page.evaluate(()=>window.firstStableRow=document.querySelector('#resultRows tr'));await page.locator('[data-action=refresh-results]').click();await page.waitForTimeout(100);
    assert.equal(await page.evaluate(()=>firstStableRow===document.querySelector('#resultRows tr')),true);
    await page.locator('[data-action=export]').click();await page.waitForTimeout(50);assert.equal(await page.evaluate(()=>mock.export.tab),'ok');
    await page.evaluate(()=>{window.longTasks=[];new PerformanceObserver(list=>longTasks.push(...list.getEntries().map(e=>e.duration))).observe({type:'longtask',buffered:false});});
    await page.locator('#pageSize').selectOption('250');await page.waitForFunction(()=>document.querySelectorAll('#resultRows tr').length===250);await page.waitForTimeout(300);
    evidence.performance=await page.evaluate(()=>({rows:document.querySelectorAll('#resultRows tr').length,domNodes:document.querySelectorAll('*').length,longTasks,maximumOffered:Math.max(...[...document.querySelector('#pageSize').options].map(o=>Number(o.value)))}));
    assert.equal(evidence.performance.maximumOffered,250);assert.ok(evidence.performance.domNodes<6500);
    await page.locator('#pageSize').selectOption('100');

    for(const theme of ['light','dark'])for(const accent of ['purple','teal','milk']){
      await go('settings');await page.locator('[data-action=theme][data-theme='+theme+']').click();await page.locator('[data-action=accent][data-accent='+accent+']').click();await axe();
      for(const view of ['http','results']){
        await go(view);if(view==='results')await page.waitForSelector('[data-result="0"]');await axe();await page.waitForTimeout(180);
        const samples=await page.evaluate(()=>[...document.querySelectorAll('.intro p,.subtitle,.field>label,.scan-variant b,.scan-variant small,.lat,.badge,table.data th,.nav-item>span:first-of-type')].map((el,index)=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);const clip=el.closest('.table-wrap,.feed,.scan-log')?.getBoundingClientRect();if(!el.getClientRects().length||r.x<0||r.x+r.width>innerWidth||r.y<0||r.y+r.height>innerHeight||clip&&(r.y<clip.y||r.bottom>clip.bottom))return null;el.dataset.contrastProbe=String(index);return {text:el.textContent.trim(),color:s.color,font:parseFloat(s.fontSize),weight:Number(s.fontWeight),rect:{x:r.x,y:r.y,w:r.width,h:r.height}};}).filter(Boolean).slice(0,50));
        await page.addStyleTag({content:'[data-contrast-probe] {color:transparent!important;text-shadow:none!important;}'});
        const screenshot=await page.screenshot();
        const ratios=await page.evaluate(async({samples,png})=>{
          const image=new Image();image.src='data:image/png;base64,'+png;await image.decode();const canvas=document.createElement('canvas');canvas.width=image.width;canvas.height=image.height;const ctx=canvas.getContext('2d');ctx.drawImage(image,0,0);
          const luminance=rgb=>rgb.map(v=>v/255).map(v=>v<=0.04045?v/12.92:((v+0.055)/1.055)**2.4).reduce((sum,v,i)=>sum+v*[.2126,.7152,.0722][i],0);
          return samples.map(s=>{const fg=s.color.match(/[\d.]+/g).slice(0,3).map(Number),values=[];for(const fx of [.2,.5,.8])for(const fy of [.3,.5,.7]){const bg=[...ctx.getImageData(Math.floor(s.rect.x+s.rect.w*fx),Math.floor(s.rect.y+s.rect.h*fy),1,1).data].slice(0,3),a=luminance(fg),b=luminance(bg);values.push((Math.max(a,b)+.05)/(Math.min(a,b)+.05));}return {text:s.text,minimum:Math.min(...values),required:s.font>=24||(s.font>=18.6667&&s.weight>=700)?3:4.5};});
        },{samples,png:screenshot.toString('base64')});
        await page.evaluate(()=>{document.querySelectorAll('style').forEach(el=>{if(el.textContent.startsWith('[data-contrast-probe]'))el.remove();});document.querySelectorAll('[data-contrast-probe]').forEach(el=>el.removeAttribute('data-contrast-probe'));});
        evidence.contrast.push({theme,accent,view,ratios});
        assert.deepEqual(ratios.filter(r=>r.minimum<r.required),[],theme+'/'+accent+'/'+view+' text contrast');
        if(view==='http')await page.screenshot({path:path.join(output,theme+'-'+accent+'.png')});
      }
    }
    for(const width of [1240,980,760,640,390,320]){await page.setViewportSize({width,height:width===640?560:800});for(const view of ['http','sni','results','reports','speed','settings']){await go(view);await page.waitForTimeout(30);const geometry=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));evidence.responsive.push({view,...geometry});assert.ok(geometry.scroll<=geometry.width,view+' fits '+width);}if(width===390){await go('sni');await page.screenshot({path:path.join(output,'mobile-390.png')});}}
    const touchContext=await browser.newContext({viewport:{width:390,height:800},hasTouch:true});const touchPage=await touchContext.newPage();await installFixture(touchPage);await touchPage.goto('http://127.0.0.1:'+server.address().port+'/');await touchPage.waitForSelector('#startScan');
    await touchPage.locator('#mobileNav').selectOption('results');await touchPage.waitForSelector('[data-result="0"]');
    const copy=touchPage.locator('[data-action=copy-row]').first();await copy.scrollIntoViewIfNeeded();await copy.tap();assert.equal(await touchPage.evaluate(()=>mock.copy),'192.0.2.1');
    evidence.touch=await touchPage.evaluate(()=>[...document.querySelectorAll('.quick-actions .icon-btn,.theme-switch button,.toolbar .btn,.tab')].filter(el=>el.getClientRects().length).slice(0,20).map(el=>{const r=el.getBoundingClientRect();return {label:el.getAttribute('aria-label')||el.textContent||el.title,w:r.width,h:r.height};}));assert.ok(evidence.touch.every(c=>c.w>=44&&c.h>=44));
    await touchPage.locator('#mobileNav').selectOption('sni');await touchPage.evaluate(()=>mock.emit('scan:stats',{state:'RUNNING',mode:'sni',total:100,done:1,recent:[mock.row(1)]}));await touchPage.locator('[data-action=feed-view][data-view=hits]').tap();await touchPage.waitForSelector('.feed-inspect');
    const feedTarget=await touchPage.locator('.feed-inspect').evaluate(el=>{const r=el.getBoundingClientRect();return {label:'Inspect live result',w:r.width,h:r.height};});evidence.touch.push(feedTarget);assert.ok(feedTarget.w>=44&&feedTarget.h>=44);
    await touchContext.close();assert.deepEqual(errors,[]);
    // ASN picker: search, select, add ranges to this mode's targets; IP version persists.
    await go('dns');await page.locator('[data-setting=targetsText]').fill('192.0.2.1');
    await page.locator('[data-action=pick-asn]').click();await page.waitForSelector('#asnList [data-asn]');await axe();
    // A long list must scroll inside the dialog, not push the dialog out of the window.
    const box=await page.locator('#asnPicker .modal').boundingBox(),vp=page.viewportSize();assert.ok(box&&box.y>=0&&box.y+box.height<=vp.height,'ASN dialog is outside the window: '+JSON.stringify(box));
    await page.locator('#asnSearch').fill('cell');await page.waitForFunction(()=>document.querySelectorAll('#asnList [data-asn]').length===1);
    await page.locator('#asnList [data-asn=AS44244]').check();
    assert.match(await page.locator('#asnAdd').innerText(),/Add 1 ASN/);
    await page.locator('#asnExport').click();await page.waitForFunction(()=>mock.asnExport);
    assert.deepEqual(await page.evaluate(()=>mock.asnExport),[['AS44244'],'ipv4']);
    await page.locator('#asnAdd').click();await page.waitForSelector('#asnPicker',{state:'hidden'});
    // The ASN stays an entry (no 26,000-line paste); the pasted list is untouched.
    assert.equal(await page.locator('[data-setting=targetsText]').inputValue(),'192.0.2.1');
    assert.match(await page.locator('#asnChips').innerText(),/AS44244[\s\S]*80 ranges/);
    assert.match(await page.locator('#targetEstimate').innerText(),/1 target lines in pasted list \+ 1 ASN \(80 ranges/);
    await page.waitForTimeout(500);
    assert.deepEqual(await page.evaluate(()=>mock.settings.targets.dns.asns),[{asn:'AS44244',name:'Iran Cell Service and Communication Company',family:'ipv4',ranges:80}]);
    await axe();
    await page.locator('[data-action=asn-remove][data-asn=AS44244]').click();
    assert.equal(await page.locator('#asnChips').isVisible(),false);
    await page.waitForTimeout(500);assert.deepEqual(await page.evaluate(()=>mock.settings.targets.dns.asns),[]);
    await page.locator('[data-action=ip-family][data-family=ipv6]').click();
    await page.locator('[data-action=pick-asn]').click();await page.waitForSelector('#asnList [data-asn]');
    assert.equal(await page.locator('[data-action=asn-family][data-family=ipv6]').getAttribute('aria-pressed'),'true');
    assert.equal(await page.locator('#asnList [data-asn]').count(),1);
    await page.keyboard.press('Escape');await page.waitForSelector('#asnPicker',{state:'hidden'});
    await page.waitForTimeout(500);
    assert.equal(await page.evaluate(()=>mock.settings.targets.dns.ipFamily),'ipv6');
    // Edge domains: the picker is there too, and its ranges land in Clean IP finder.
    await go('edge-domains');await page.locator('[data-action=pick-asn]').click();await page.waitForSelector('#asnList [data-asn]');
    await page.locator('#asnList [data-asn=AS58224]').check();await page.locator('#asnAdd').click();
    await page.waitForSelector('#asnPicker',{state:'hidden'});
    assert.match(await page.locator('#asnChips').innerText(),/AS58224/);
    assert.equal(await page.locator('#nav [data-workspace=clean-ip]').getAttribute('aria-current'),'page');
    // Config maker: configs + clean IPs from Results -> one config per IP; extract mode.
    await go('config');await page.waitForSelector('#cmConfigs');
    assert.equal(await page.locator('#cmRun').isDisabled(),true);
    await page.locator('[data-action=cm-load][data-into=configs]').click();await page.waitForFunction(()=>document.querySelector('#cmConfigs').value.includes('from-file'));
    await page.locator('[data-action=cm-use-clean]').click();await page.waitForFunction(()=>document.querySelector('#cmTargets').value.includes('104.16.0.2:443'));
    await page.waitForFunction(()=>/2 IP:port targets/.test(document.querySelector('#cmTargetsInfo').textContent)&&!document.querySelector('#cmRun').disabled);
    assert.match(await page.locator('#cmConfigsInfo').innerText(),/1 config: 1 vless/);
    await axe();
    await page.locator('#cmRun').click();await page.waitForFunction(()=>document.querySelector('#cmOutput').value.includes('104.16.0.2'));
    assert.deepEqual(await page.evaluate(()=>mock.rewrite),['vless://u@old.example:443#from-file','104.16.0.1:443'+String.fromCharCode(10)+'104.16.0.2:443']);
    assert.match(await page.locator('#cmMessage').innerText(),/Made 2 configs\. Saved to Scan reports\/Config maker\/rewritten-1\.txt/);
    await page.locator('#cmCopy').click();await page.waitForFunction(()=>mock.copy.startsWith('vless://u@104.16.0.1'));
    await page.locator('[data-action=cm-mode][data-mode=extract]').click();
    assert.equal(await page.locator('#cmTargets').count(),0);
    await page.locator('#cmRun').click();await page.waitForFunction(()=>document.querySelector('#cmOutput').value==='1.2.3.4:443');
    await axe();
    // Results: delete one row, or everything shown after a second confirming click.
    await go('results');await page.waitForSelector('[data-result="0"]');
    const firstSeq=Number((await page.locator('[data-result="0"] td').first().innerText()).split('.').pop()); // mock rows are labelled 192.0.2.<seq>
    await page.locator('[data-action=copy-clean]').click();await page.waitForFunction(()=>mock.copy.startsWith('104.16.0.1:443'));
    await page.locator('[data-action=delete-row]').first().click();await page.waitForFunction(()=>mock.deleted?.length===1);
    assert.deepEqual(await page.evaluate(()=>mock.deleted[0][1]),[firstSeq]);
    await page.locator('#deleteResults').click();assert.match(await page.locator('#deleteResults').innerText(),/Delete 100,000 results\?/);
    assert.equal(await page.evaluate(()=>mock.deleted.length),1);
    await page.locator('#deleteResults').click();await page.waitForFunction(()=>mock.deleted?.length===2);
    assert.deepEqual(await page.evaluate(()=>mock.deleted[1][1]),[]);assert.equal(await page.evaluate(()=>mock.deleted[1][0].tab),'ok');
    assert.match(await page.locator('#deleteResults').innerText(),/^Delete shown$/);
    console.log('PASS: ASN picker and IP version, audit fixes, nine modes, valid live-feed semantics, stable keyboard focus and payloads, delayed responses, row reuse, explicit errors, category filters, 250-row rendering, six theme contrasts, responsive layouts, and synthesized touch.');
    console.log(JSON.stringify(evidence.performance));
  } finally {fs.writeFileSync(path.join(output,'verification.json'),JSON.stringify({...evidence,errors},null,2));await browser.close();await new Promise(resolve=>server.close(resolve));}
}
run().catch(error=>{console.error(error);process.exitCode=1;});
