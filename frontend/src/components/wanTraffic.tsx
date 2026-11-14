import { useState } from 'react'
import type { RouterSample } from './routerMetrics'

export type WanInterval = {
    interface: string
    seconds?: number
    rx_bytes: number
    tx_bytes: number
}

const number = new Intl.NumberFormat('ru', { maximumFractionDigits: 1 })
const clock = new Intl.DateTimeFormat('ru', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const rates = ['бит/с', 'кбит/с', 'Мбит/с', 'Гбит/с']
const volumes = ['Б', 'кБ', 'МБ', 'ГБ', 'ТБ']

function format(value: number, units: string[]) {
    let idx = 0
    while (value >= 1000 && idx < units.length - 1) {
        value /= 1000
        idx++
    }
    return number.format(value) + ' ' + units[idx]
}

type Point = { at: number; down: number; up: number } | undefined

function plot(points: Point[], key: 'down' | 'up', end: number, duration: number, peak: number) {
    let path = ''
    let previous = 0
    let last: {x: number; y: number} | undefined
    for (const p of points) {
        if (!p) {
            previous = 0
            continue
        }
        const x = 2 + 596 * (1 - (end - p.at) / duration)
        const y = 83 - 80 * p[key] / peak
        path += (previous && p.at - previous < 12000 ? ' L' : ' M') + x.toFixed(1) + ' ' + y.toFixed(1)
        previous = p.at
        last = {x, y}
    }
    return { path, last }
}

export function WanTraffic({ history, current, minutes }: { history: RouterSample[]; current?: RouterSample; minutes: number }) {
    const [chosen, setChosen] = useState('')
    const end = current ? Date.parse(current.at) : Date.now()
    const duration = minutes * 60000
    const period = history.filter(s => Date.parse(s.at) > end - duration)
    const now = current?.wan ?? []
    const interfaces = [...new Set(period.flatMap(s => s.wan?.map(w => w.interface) ?? []))].sort()
    const id = interfaces.includes(chosen) ? chosen : now[0]?.interface ?? interfaces[0]
    const latest = now.find(w => w.interface === id)
    let rx = 0, tx = 0, peak = 0
    const points = period.map(sample => {
        const w = sample.wan?.find(item => item.interface === id)
        if (!w?.seconds) return undefined
        const down = w.rx_bytes * 8 / w.seconds
        const up = w.tx_bytes * 8 / w.seconds
        rx += w.rx_bytes
        tx += w.tx_bytes
        peak = Math.max(peak, down, up)
        return {at: Date.parse(sample.at), down, up}
    })
    const directions = [
        {key: 'down' as const, label: 'Приём', total: rx, bytes: latest?.rx_bytes, color: 'var(--tint, var(--primary))'},
        {key: 'up' as const, label: 'Передача', total: tx, bytes: latest?.tx_bytes, color: '#39b99e'},
    ]
    const hasReadings = points.some(p => p !== undefined)
    return <section className='min-w-0 rounded-card bg-card px-4 py-3' aria-label='Интернет-трафик'>
        <header className='flex flex-wrap items-baseline justify-between gap-2'>
            <h3 className='font-medium'>Интернет-трафик</h3>
            {interfaces.length > 1 ? <select aria-label='Интернет-интерфейс' value={id}
                onChange={e => setChosen(e.target.value)} className='min-h-10 max-w-full rounded-xl bg-fill px-3 text-sm'>
                {interfaces.map(name => <option key={name}>{name}</option>)}
            </select> : id && <span className='text-xs text-muted-foreground'>WAN · {id}</span>}
        </header>
        <div className='mt-2 grid grid-cols-2 gap-3'>
            {directions.map(d => <div key={d.key}>
                <div className='flex items-center gap-2 text-sm'>
                    <span aria-hidden className='w-5 border-t-2' style={{borderColor: d.color, borderTopStyle: d.key === 'up' ? 'dashed' : 'solid'}} />
                    {d.label}
                </div>
                <strong className='block text-lg tabular-nums'>{latest?.seconds && d.bytes != null ? format(d.bytes * 8 / latest.seconds, rates) : '—'}</strong>
                {hasReadings && <p className='text-xs text-muted-foreground'>{format(d.total, volumes)} за период наблюдения</p>}
            </div>)}
        </div>
        {hasReadings && <>
            <svg viewBox='0 0 600 87' preserveAspectRatio='none' role='img'
                aria-label={`Приём и передача за ${minutes} мин. Пиковая скорость ${format(peak, rates)}`} className='mt-3 h-24 w-full'>
                {[3, 43, 83].map(y => <line key={y} x1='0' x2='600' y1={y} y2={y} stroke='currentColor' opacity='.18' strokeDasharray='2 4' />)}
                {directions.map(d => {
                    const {path, last} = plot(points, d.key, end, duration, peak || 1)
                    return <g key={d.key} style={{color:d.color}}>
                        <path d={path} stroke='currentColor' fill='none' strokeWidth='2' vectorEffect='non-scaling-stroke' strokeDasharray={d.key === 'up' ? '5 3' : undefined} />
                        {last && <circle cx={last.x} cy={last.y} r='2' fill='currentColor' />}
                    </g>
                })}
            </svg>
            <div className='mt-1 flex justify-between text-[11px] text-muted-foreground'>
                <span>−{minutes} мин</span><span>Пик · {format(peak, rates)}</span><span>{clock.format(end)}</span>
            </div>
        </>}
        {!latest?.seconds && <p className='mt-3 text-sm text-muted-foreground'>{!current || latest ? 'Ожидаем измерение скорости…' : 'Счётчики интернет-интерфейса сейчас недоступны.'}</p>}
    </section>
}
