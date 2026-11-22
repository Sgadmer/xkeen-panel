// Takes the screenshots of the guide from the demo mode, so they always show
// made-up data and the current interface.
//
//   go build -o build/demo/xkeen-panel-demo .      (after the frontend build)
//   node scripts/capture-screenshots.mjs --demo build/demo/xkeen-panel-demo --browser <chrome or edge> [--only name,name]
//
// Needs Node 22+ (built-in WebSocket) and any Chromium-based browser. The demo
// listens on 127.0.0.1:3300; nothing leaves this computer.
import { spawn } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, index, all) => value.startsWith('--') ? [...pairs, [value.slice(2), all[index + 1]]] : pairs, []))
const demo = resolve(args.demo ?? 'build/demo/xkeen-panel-demo')
const browser = args.browser ?? process.env.BROWSER
const out = resolve(args.out ?? 'docs/screenshots')
const only = args.only ? args.only.split(',') : null
if (!browser) {
    console.error('Pass --browser <path to chrome or edge>')
    process.exit(2)
}

const wide = [1280, 720], tall = [1440, 1360], phone = [375, 812]
// click: the visible text of a button or link; scroll: the text of a heading to bring into view.
const shots = [
    { file: 'overview', core: 'mihomo', path: '/', size: wide },
    { file: 'servers', core: 'mihomo', path: '/servers', size: wide, storage: { servers_tab: 'pool' } },
    { file: 'all-servers', core: 'mihomo', path: '/servers', size: wide, storage: { servers_tab: 'all' } },
    { file: 'sources', core: 'mihomo', path: '/servers?sources=1', size: wide },
    { file: 'multipools', core: 'mihomo', path: '/servers', size: wide, storage: { servers_tab: 'all' }, steps: [{ click: 'Мультипулы' }] },
    { file: 'services', core: 'mihomo', path: '/services', size: tall },
    { file: 'service-picker', core: 'mihomo', path: '/services', size: wide, steps: [{ scroll: 'YouTube' }, { click: 'Маршрут · YouTube' }, { click: 'Северный ветер' }] },
    { file: 'ai-route-warning', core: 'mihomo', path: '/services', size: tall, steps: [{ click: 'Маршрут · Claude' }, { click: 'Северный ветер' }, { click: 'Франкфурт' }], settle: 1200 },
    { file: 'custom-service', core: 'mihomo', path: '/services', size: wide, steps: [{ click: 'Свой сервис' }] },
    { file: 'devices', core: 'mihomo', path: '/devices', size: wide },
    { file: 'exclusions', core: 'mihomo', path: '/exclusions', size: wide },
    { file: 'journal', core: 'mihomo', path: '/journal?src=recent', size: tall },
    { file: 'history-settings', core: 'mihomo', path: '/journal?settings=1', size: tall },
    { file: 'diagnostics', core: 'mihomo', path: '/diagnostics', size: tall },
    { file: 'settings', core: 'mihomo', path: '/settings', size: wide },
    { file: 'protection', core: 'mihomo', path: '/settings/protection', size: wide },
    { file: 'components', core: 'mihomo', path: '/settings/components', size: tall },
    { file: 'security', core: 'mihomo', path: '/settings/security', size: wide },
    { file: 'transfer', core: 'mihomo', path: '/settings/transfer', size: wide },
    { file: 'recommended', core: 'mihomo', path: '/settings/recommended', size: wide },
    { file: 'updates', core: 'mihomo', path: '/settings/update', size: wide },
    { file: 'access', core: 'mihomo', path: '/settings/access', size: wide },
    { file: 'mobile', core: 'mihomo', path: '/', size: phone, mobile: true },
    { file: 'xray-routing', core: 'xray', path: '/settings/protection', size: wide },
    { file: 'ports', core: 'xray', path: '/exclusions', size: wide, steps: [{ click: 'Полный обход VPN' }] },
    // notifications.jpg and wizard.jpg need a browser with push support and an
    // unfinished setup; the demo has neither, so those two are kept as they are.
    { file: 'geobases', core: 'xray', path: '/settings/components', size: wide, steps: [{ scroll: 'Источники геобаз' }] },
]

const sleep = ms => new Promise(done => setTimeout(done, ms))
const port = 9333

async function until(check, what) {
    for (let attempt = 0; attempt < 60; attempt++) {
        try {
            if (await check()) return
        } catch { /* not up yet */ }
        await sleep(250)
    }
    throw new Error('timed out waiting for ' + what)
}

function connect(url) {
    const socket = new WebSocket(url)
    const waiting = new Map()
    let next = 0
    socket.addEventListener('message', event => {
        const message = JSON.parse(event.data)
        const pending = waiting.get(message.id)
        if (!pending) return
        waiting.delete(message.id)
        if (message.error) pending.reject(new Error(message.error.message))
        else pending.resolve(message.result)
    })
    const send = (method, params = {}) => new Promise((resolve, reject) => {
        const id = ++next
        waiting.set(id, { resolve, reject })
        socket.send(JSON.stringify({ id, method, params }))
    })
    return new Promise((ready, failed) => {
        socket.addEventListener('open', () => ready({ send, close: () => socket.close() }))
        socket.addEventListener('error', () => failed(new Error('browser connection failed')))
    })
}

// Finds what a person would click: the innermost button, link or summary with this text.
const clicker = text => `(() => {
    const wanted = ${JSON.stringify(text)}
    // An open dialog covers the page: what is clicked next is inside it.
    const dialogs = document.querySelectorAll('[role=dialog], [role=alertdialog]')
    const scope = dialogs.length ? dialogs[dialogs.length - 1] : document
    const all = [...scope.querySelectorAll('button, a, summary, [role=button], [role=option], li')]
    const found = all.filter(el => (el.getAttribute('aria-label') || el.textContent || '').includes(wanted) && el.offsetParent !== null)
        .sort((a, b) => a.textContent.length - b.textContent.length)[0]
    if (!found) return false
    found.scrollIntoView({ block: 'center' })
    found.click()
    return true
})()`
const scroller = text => `(() => {
    const found = [...document.querySelectorAll('h1, h2, h3')].find(el => el.textContent.includes(${JSON.stringify(text)}))
    if (!found) return false
    found.scrollIntoView({ block: 'start' })
    window.scrollBy(0, -24)
    return true
})()`

async function capture(shot) {
    const created = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' }).then(response => response.json())
    const page = await connect(created.webSocketDebuggerUrl)
    try {
        const [width, height] = shot.size
        await page.send('Page.enable')
        await page.send('Runtime.enable')
        await page.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: !!shot.mobile })
        const storage = Object.entries(shot.storage ?? {}).map(([key, value]) => `localStorage.setItem(${JSON.stringify(key)}, ${JSON.stringify(value)});`).join('')
        await page.send('Page.addScriptToEvaluateOnNewDocument', { source: `try { ${storage} } catch {}` })
        await page.send('Page.navigate', { url: `http://127.0.0.1:3300${shot.path}` })
        await until(async () => (await page.send('Runtime.evaluate', { expression: 'document.readyState === "complete" && !!document.querySelector("main, h1")', returnByValue: true })).result.value, shot.file)
        await sleep(1600)
        for (const step of shot.steps ?? []) {
            const expression = step.click ? clicker(step.click) : scroller(step.scroll)
            const done = (await page.send('Runtime.evaluate', { expression, returnByValue: true })).result.value
            if (!done) throw new Error(`${shot.file}: nothing to ${step.click ? 'click' : 'scroll to'} for "${step.click ?? step.scroll}"`)
            await sleep(700)
        }
        await sleep(shot.settle ?? 400)
        const image = await page.send('Page.captureScreenshot', { format: 'jpeg', quality: 86 })
        writeFileSync(join(out, shot.file + '.jpg'), Buffer.from(image.data, 'base64'))
        console.log('saved', shot.file + '.jpg', `${width}x${height}`)
    } finally {
        page.close()
        await fetch(`http://127.0.0.1:${port}/json/close/${created.id}`).catch(() => {})
    }
}

mkdirSync(out, { recursive: true })
const profile = mkdtempSync(join(tmpdir(), 'xkeen-shots-'))
const chrome = spawn(browser, ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', '--disable-extensions', '--hide-scrollbars', '--force-dark-mode', '--lang=ru', 'about:blank'], { stdio: 'ignore' })
let failed = false
try {
    await until(() => fetch(`http://127.0.0.1:${port}/json/version`).then(response => response.ok), 'the browser')
    for (const core of ['mihomo', 'xray']) {
        const wanted = shots.filter(shot => shot.core === core && (!only || only.includes(shot.file)))
        if (wanted.length === 0) continue
        const server = spawn(demo, ['-demo'], { stdio: 'ignore', env: { ...process.env, XKEEN_DEMO_CORE: core } })
        try {
            await until(() => fetch('http://127.0.0.1:3300/api/status').then(response => response.ok), 'the demo')
            for (const shot of wanted) {
                try {
                    await capture(shot)
                } catch (error) {
                    failed = true
                    console.error('FAILED', shot.file, error.message)
                }
            }
        } finally {
            server.kill()
            await sleep(600)
        }
    }
} finally {
    chrome.kill()
    await sleep(500)
    try { rmSync(profile, { recursive: true, force: true }) } catch { /* the browser may still hold a file */ }
}
process.exit(failed ? 1 : 0)
