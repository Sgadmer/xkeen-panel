import { useState } from 'react'

export type RouterSample = {
    at: string
    cpu_percent?: number
    cores?: number
    load?: number[]
    ram_total_kib?: number
    ram_used_kib?: number
    temperature_c?: number
}

const valueFormat = new Intl.NumberFormat('ru', { maximumFractionDigits: 1 })
const timeFormat = new Intl.DateTimeFormat('ru', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
})

type MetricProps = {
    name: string
    unit: string
    value?: number
    detail: string
    color: string
    samples: RouterSample[]
    minutes: number
    read: (sample: RouterSample) => number | undefined
    percent?: boolean
}

function Metric({
    name,
    unit,
    value,
    detail,
    color,
    samples,
    minutes,
    read,
    percent,
}: MetricProps) {
    const end = samples.length
        ? Date.parse(samples[samples.length - 1].at)
        : Date.now()
    const span = minutes * 60000
    const series = samples
        .map(s => ({ time: Date.parse(s.at), value: read(s) }))
        .filter(p => p.time >= end - span)
    const values = series.flatMap(p => (p.value == null ? [] : [p.value]))
    const min =
        percent || !values.length
            ? 0
            : Math.floor((Math.min(...values) - 1) / 5) * 5
    const max =
        percent || !values.length
            ? 100
            : Math.ceil((Math.max(...values) + 1) / 5) * 5
    let continuous = false
    let lastTime = 0
    let path = ''
    let point: { x: number; y: number } | undefined
    for (const p of series) {
        if (p.value == null) {
            continuous = false
            continue
        }
        const x = 2 + (1 - (end - p.time) / span) * 296
        const y = 66 - ((p.value - min) / (max - min)) * 63
        path +=
            (continuous && p.time - lastTime < 11000 ? ' L' : ' M') +
            x.toFixed(1) +
            ' ' +
            y.toFixed(1)
        point = { x, y }
        continuous = true
        lastTime = p.time
    }
    return (
        <section className='min-w-0 rounded-card bg-card px-4 py-3'>
            <div className='flex items-baseline justify-between gap-2'>
                <h3 className='font-medium'>{name}</h3>
                <strong className='text-xl tabular-nums'>
                    {value == null
                        ? '—'
                        : valueFormat.format(value) + ' ' + unit}
                </strong>
            </div>
            <p className='text-xs text-muted-foreground'>{detail}</p>
            {point ? (
                <>
                    <svg
                        role='img'
                        aria-label={
                            name +
                            ' за ' +
                            minutes +
                            ' минут. Минимум ' +
                            valueFormat.format(Math.min(...values)) +
                            ' ' +
                            unit +
                            ', максимум ' +
                            valueFormat.format(Math.max(...values)) +
                            ' ' +
                            unit
                        }
                        viewBox='0 0 300 69'
                        preserveAspectRatio='none'
                        className='mt-4 h-16 w-full'
                        style={{ color }}
                    >
                        {[4, 35, 66].map(y => (
                            <line
                                key={y}
                                x1='0'
                                x2='300'
                                y1={y}
                                y2={y}
                                stroke='currentColor'
                                opacity='.19'
                                strokeDasharray='2 4'
                            />
                        ))}
                        <path
                            d={path}
                            stroke='currentColor'
                            strokeWidth='2'
                            fill='none'
                            vectorEffect='non-scaling-stroke'
                        />
                        <circle
                            cx={point.x}
                            cy={point.y}
                            r='2.5'
                            fill='currentColor'
                        />
                    </svg>
                    <div className='mt-1 flex justify-between text-[11px] text-muted-foreground'>
                        <span>−{minutes} мин</span>
                        <span>{valueFormat.format(min)}–{valueFormat.format(max)} {unit}</span>
                        <span>{timeFormat.format(end)}</span>
                    </div>
                </>
            ) : (
                <p className='mt-4 text-sm text-muted-foreground'>
                    {name === 'Температура'
                        ? 'Нет показаний датчика'
                        : 'Ожидаем измерение…'}
                </p>
            )}
        </section>
    )
}

export function RouterMetrics({
    system,
    history = [],
}: {
    system?: RouterSample
    history?: RouterSample[]
}) {
    const [minutes, setMinutes] = useState(5)
    const ram = (s: RouterSample) =>
        s.ram_total_kib
            ? ((s.ram_used_kib ?? 0) * 100) / s.ram_total_kib
            : undefined
    return (
        <section className='space-y-2'>
            <div className='flex flex-wrap items-center justify-between gap-2 px-1'>
                <h2 className='text-sm font-medium text-muted-foreground'>
                    Нагрузка роутера
                </h2>
                <div
                    role='group'
                    aria-label='Период графиков'
                    className='flex gap-1 rounded-xl bg-fill p-1'
                >
                    {[1, 5, 15].map(m => (
                        <button
                            key={m}
                            type='button'
                            aria-pressed={minutes === m}
                            onClick={() => setMinutes(m)}
                            className={
                                'rounded-lg px-3 py-1 text-xs ' +
                                (minutes === m
                                    ? 'bg-tint text-white'
                                    : 'text-muted-foreground')
                            }
                        >
                            {m} мин
                        </button>
                    ))}
                </div>
            </div>
            <div className='grid gap-2 md:grid-cols-3'>
                <Metric
                    name='Процессор'
                    unit='%'
                    percent
                    color='var(--primary)'
                    read={s => s.cpu_percent}
                    samples={history}
                    minutes={minutes}
                    value={system?.cpu_percent}
                    detail={
                        system?.cores ? 'Ядер: ' + system.cores : 'Загрузка CPU'
                    }
                />
                <Metric
                    name='Оперативная память'
                    unit='%'
                    percent
                    color='#39b99e'
                    read={ram}
                    samples={history}
                    minutes={minutes}
                    value={system && ram(system)}
                    detail={
                        system?.ram_total_kib
                            ? Math.round((system.ram_used_kib ?? 0) / 1024) +
                              ' из ' +
                              Math.round(system.ram_total_kib / 1024) +
                              ' МиБ'
                            : 'Использование памяти'
                    }
                />
                <Metric
                    name='Температура'
                    unit='°C'
                    color='#e99a47'
                    read={s => s.temperature_c}
                    samples={history}
                    minutes={minutes}
                    value={system?.temperature_c}
                    detail='Максимум по датчикам роутера'
                />
            </div>
            {!!system?.load?.length && (
                <p className='px-2 text-xs text-muted-foreground'>
                    Средняя нагрузка за 1 / 5 / 15 мин ·{' '}
                    {system.load.map(v => valueFormat.format(v)).join(' / ')}
                </p>
            )}
        </section>
    )
}
