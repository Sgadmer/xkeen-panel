import { useState } from 'react'
import { cn } from '@/lib/utils'

// Every running indicator follows one clock: a negative delay of «now modulo
// period» puts an animation started at any moment into the same phase as all
// the others, so a page full of them moves like one picture.
const BAR_PERIOD = 1500
const COLOR_PERIOD = 4500

function syncDelay(period: number, offset = 0) {
    const now = typeof performance !== 'undefined' ? performance.now() : Date.now()
    return `${Math.round(offset - (now % period))}ms`
}

// Three bars lighting up one after another, «searching for a network»; the
// colour drifts from green through yellow to red and back.
export function SignalBars({ className }: { className?: string }) {
    const [delays] = useState(() => ({
        color: syncDelay(COLOR_PERIOD),
        bars: [0, 1, 2].map(i => syncDelay(BAR_PERIOD, i * 250)),
    }))
    return (
        <span aria-hidden className={cn('signal-bars inline-flex h-[18px] items-end gap-[3px]', className)}
            style={{ animationDelay: delays.color }}>
            {[8, 13, 18].map((height, i) => (
                <i key={height} className='block w-[4px] rounded-full bg-current' style={{ height, animationDelay: delays.bars[i] }} />
            ))}
        </span>
    )
}

// The place of a number that is being measured again.
export function LatencySkeleton() {
    return <span aria-label='Проверяем задержку' className='inline-block h-2.5 w-11 rounded-full bg-white/12' />
}
