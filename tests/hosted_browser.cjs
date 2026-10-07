const { chromium } = require('playwright');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const port = process.env.HOSTED_TEST_PORT || '8892';
const python = process.env.HOSTED_PYTHON || path.join(root, '.venv-hosted', 'Scripts', 'python.exe');
const output = process.env.UI_OUTPUT_DIR || path.join(root, '.browser-results');
fs.mkdirSync(output, {recursive:true});

(async () => {
  const server = spawn(python, ['tests/hosted_preview.py'], {cwd:root, env:{...process.env, HOSTED_TEST_PORT:port}, stdio:['ignore','pipe','pipe']});
  let browser;
  try {
    const credentials = await new Promise((resolve,reject) => {
      let buffer='';
      const timer=setTimeout(()=>reject(new Error('Fixture startup timed out')),45000);
      server.once('exit', code=>{clearTimeout(timer);reject(new Error(`Fixture exited ${code}`));});
      server.stdout.on('data',data=>{
        buffer+=data.toString();
        for (const line of buffer.split('\n')) {
          try {const result=JSON.parse(line);if(result.ready){clearTimeout(timer);resolve(result);return;}} catch {}
        }
      });
    });
    browser=await chromium.launch({channel:process.env.UI_BROWSER_CHANNEL||'chrome',headless:true});
    const page=await browser.newPage({viewport:{width:1440,height:1000}});
    const errors=[];
    page.on('pageerror',e=>errors.push(e.message));
    const base=`http://127.0.0.1:${port}`;
    await page.goto(base);
    await page.waitForURL('**/login/**');
    await page.screenshot({path:path.join(output,'hosted-login.png'),fullPage:true});
    await page.locator('#id_username').fill(credentials.username);
    await page.locator('#id_password').fill(credentials.password);
    await page.getByRole('button',{name:'Sign in',exact:true}).click();
    await page.waitForURL(base+'/');
    await page.waitForFunction(()=>document.querySelector('#accountName')?.textContent.includes('browser-review'));
    await page.waitForFunction(()=>Number(document.querySelector('#totalEndpointCount')?.textContent)>0);
    const session=await page.evaluate(async()=>fetch('/api/session').then(r=>r.json()));
    assert.equal(session.role,'admin');
    assert.equal(session.workspaces.length,2);
    assert.equal(await page.evaluate(async()=>fetch('/api/logout',{method:'POST',body:'{}',headers:{'Content-Type':'application/json'}}).then(r=>r.status)),403);
    const outcomes=await page.evaluate(async ({csrf,id})=>{
      const headers={'Content-Type':'application/json','X-CSRF-Token':csrf,'X-Workspace-ID':String(id),'Idempotency-Key':'browser-integration-00001'};
      const body=JSON.stringify({method:'POST',path:'/sessions/create',body:{agent_id:1}});
      const first=await fetch('/api/run',{method:'POST',headers,body}).then(r=>r.json());
      const second=await fetch('/api/run',{method:'POST',headers,body}).then(r=>r.json());
      return {first,second};
    },{csrf:session.csrfToken,id:session.workspace.id});
    assert.equal(outcomes.first.ok,true);
    assert.equal(outcomes.second.replayed,true);
    assert.equal(outcomes.first.operationId,outcomes.second.operationId);
    await page.reload();
    await page.waitForFunction(()=>document.querySelector('#accountName')?.textContent.includes('browser-review'));
    await page.waitForFunction(()=>Number(document.querySelector('#totalEndpointCount')?.textContent)>0);
    await page.screenshot({path:path.join(output,'hosted-desktop.png'),fullPage:true});
    await page.setViewportSize({width:390,height:844});
    await page.screenshot({path:path.join(output,'hosted-mobile.png'),fullPage:true});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    assert.deepEqual(errors,[]);
    const report={checks:8,passed:8,pageErrors:errors,upstreamCalls:'mocked only',coverage:['real login','CSRF rejection','database session','workspace memberships','durable mutation','duplicate replay','desktop render','mobile overflow']};
    fs.writeFileSync(path.join(output,'hosted-browser-checks.json'),JSON.stringify(report,null,2));
    console.log(JSON.stringify(report));
  } finally {if(browser)await browser.close();server.kill();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
