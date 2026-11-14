import { useEffect, useRef, useState, type PointerEvent } from 'react'
import { Dialog } from '@base-ui/react/dialog'
import { IconArrowDown, IconArrowUp, IconGripVertical, IconListDetails } from '@tabler/icons-react'
import { ServiceLogo } from '@/components/serviceLogo'
import { cn } from '@/lib/utils'

const storageKey = 'xkeen.service-card-order'
const defaultOrder = [
    'claude', 'openai', 'ai', 'google', 'youtube', 'telegram', 'whatsapp', 'instagram',
    'discord', 'steam', 'github', 'spotify', 'twitch', 'playstation', 'xbox', 'twitter',
    'facebook', 'netflix', 'amazon', 'primevideo', 'disney', 'hbo', 'hulu', 'line',
]

type Item = { id: string; name: string }

function readOrder(): string[] {
    try {
        const saved: unknown = JSON.parse(localStorage.getItem(storageKey) ?? '[]')
        return Array.isArray(saved) ? saved.filter((id): id is string => typeof id === 'string') : []
    } catch {
        return []
    }
}

function ordered<T extends Item>(items: T[], preference: string[]): T[] {
    const byId = new Map(items.map(item => [item.id, item]))
    const ids = new Set([...preference, ...defaultOrder, ...byId.keys()])
    return Array.from(ids).flatMap(id => byId.has(id) ? [byId.get(id)!] : [])
}

export function useServiceOrder<T extends Item>(items: T[]) {
    const [preference, setPreference] = useState(readOrder)
    useEffect(() => {
        const refresh = (event: StorageEvent) => {
            if (event.key === storageKey || event.key === null) setPreference(readOrder())
        }
        window.addEventListener('storage', refresh)
        return () => window.removeEventListener('storage', refresh)
    }, [])

    function save(ids: string[]) {
        if (ids.length) localStorage.setItem(storageKey, JSON.stringify(ids))
        else localStorage.removeItem(storageKey)
        setPreference(ids)
    }
    return { services: ordered(items, preference), save }
}

type Drop = { id: string; after: boolean }
type Drag = { id: string; pointer: number; x: number; y: number }
const arrowClass = 'grid size-11 shrink-0 cursor-pointer place-items-center rounded-xl text-tint hover:bg-muted disabled:cursor-default disabled:opacity-25'

export function ServiceOrderControl({ services, save }: { services: Item[]; save: (ids: string[]) => void }) {
    const [open, setOpen] = useState(false)
    const [draft, setDraft] = useState<string[]>([])
    const [message, setMessage] = useState('')
    const [error, setError] = useState('')
    const [dragging, setDragging] = useState('')
    const [drop, setDrop] = useState<Drop | null>(null)
    const drag = useRef<Drag | null>(null)
    const list = useRef<HTMLOListElement>(null)
    const frame = useRef(0)
    const rows = ordered(services, draft)

    useEffect(() => () => cancelAnimationFrame(frame.current), [])

    function stopDragging() {
        cancelAnimationFrame(frame.current)
        drag.current = null
        setDragging('')
        setDrop(null)
    }

    function place(id: string, target: Drop) {
        if (id === target.id) return
        const ids = rows.map(item => item.id).filter(key => key !== id)
        const targetIndex = ids.indexOf(target.id)
        if (targetIndex < 0) return
        const position = targetIndex + Number(target.after)
        ids.splice(position, 0, id)
        setDraft(ids)
        setMessage(`${rows.find(item => item.id === id)?.name}, позиция ${position + 1} из ${ids.length}`)
    }

    function targetAt(x: number, y: number, id: string): Drop | null {
        const row = document.elementFromPoint(x, y)?.closest<HTMLElement>('[data-order-id]')
        if (!row || !list.current?.contains(row) || row.dataset.orderId === id) return null
        const bounds = row.getBoundingClientRect()
        return { id: row.dataset.orderId!, after: y >= bounds.top + bounds.height / 2 }
    }

    function track() {
        const active = drag.current
        if (!active || !list.current) return
        const box = list.current.getBoundingClientRect()
        if (active.x >= box.left && active.x <= box.right) {
            const edge = 40
            if (active.y < box.top + edge) list.current.scrollTop -= 8
            if (active.y > box.bottom - edge) list.current.scrollTop += 8
        }
        const target = targetAt(active.x, active.y, active.id)
        setDrop(previous => previous?.id === target?.id && previous?.after === target?.after ? previous : target)
        frame.current = requestAnimationFrame(track)
    }

    function startDrag(event: PointerEvent, id: string) {
        if (!event.isPrimary || event.button !== 0 || drag.current || !list.current) return
        event.preventDefault()
        drag.current = { id, pointer: event.pointerId, x: event.clientX, y: event.clientY }
        list.current.setPointerCapture(event.pointerId)
        setDragging(id)
        frame.current = requestAnimationFrame(track)
    }

    function finishDrag(event: PointerEvent) {
        const active = drag.current
        if (!active || active.pointer !== event.pointerId) return
        const target = targetAt(event.clientX, event.clientY, active.id)
        if (target) place(active.id, target)
        stopDragging()
    }

    return <Dialog.Root open={open} onOpenChange={next => {
        stopDragging()
        if (next) {
            setDraft(services.map(item => item.id))
            setMessage('')
            setError('')
        }
        setOpen(next)
    }}>
        <Dialog.Trigger type='button' className='inline-flex min-h-11 items-center gap-2 rounded-xl bg-card px-3 text-sm font-medium text-tint hover:bg-muted'>
            <IconListDetails aria-hidden className='size-5' /> Изменить порядок
        </Dialog.Trigger>
        <Dialog.Portal>
            <Dialog.Backdrop className='fixed inset-0 z-50 bg-black/55 backdrop-blur-[2px]' />
            <Dialog.Popup className='fixed inset-x-0 bottom-0 z-50 flex max-h-[90dvh] flex-col overflow-hidden rounded-t-[26px] border bg-popover text-popover-foreground shadow-2xl outline-none sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:max-h-[min(90dvh,46rem)] sm:w-[28rem] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-[26px]'>
                <header className='shrink-0 border-b px-4 py-3'>
                    <Dialog.Title className='font-semibold'>Порядок сервисов</Dialog.Title>
                    <Dialog.Description className='mt-1 text-sm text-muted-foreground'>Перетащите сервис за ручку или нажмите на стрелку. Порядок сохранится в этом браузере.</Dialog.Description>
                </header>
                <ol ref={list} className='min-h-0 overflow-y-auto overscroll-contain px-3' onPointerMove={event => {
                    if (drag.current?.pointer === event.pointerId) {
                        drag.current.x = event.clientX
                        drag.current.y = event.clientY
                    }
                }} onPointerUp={finishDrag} onPointerCancel={stopDragging} onLostPointerCapture={stopDragging}>
                    {rows.map((item, index) => <li key={item.id} data-order-id={item.id} className={cn(
                        'relative flex min-h-12 items-center border-b border-separator last:border-b-0',
                        dragging === item.id && 'rounded-xl bg-muted',
                        drop?.id === item.id && 'before:pointer-events-none before:absolute before:inset-x-0 before:z-10 before:h-0.5 before:bg-tint',
                        drop?.id === item.id && (drop.after ? 'before:bottom-0' : 'before:top-0'))}>
                        <span aria-hidden className='grid size-11 shrink-0 cursor-grab touch-none select-none place-items-center text-muted-foreground active:cursor-grabbing'
                            onPointerDown={event => startDrag(event, item.id)}><IconGripVertical className='size-5' /></span>
                        <ServiceLogo id={item.id} className='me-2 size-5 shrink-0' />
                        <span className='min-w-0 flex-1 break-words text-sm font-medium'>{item.name}</span>
                        <button type='button' className={arrowClass} aria-label={item.name + ' выше'} disabled={index === 0}
                            onClick={() => place(item.id, { id: rows[index - 1].id, after: false })}><IconArrowUp aria-hidden className='size-4' /></button>
                        <button type='button' className={arrowClass} aria-label={item.name + ' ниже'} disabled={index === rows.length - 1}
                            onClick={() => place(item.id, { id: rows[index + 1].id, after: true })}><IconArrowDown aria-hidden className='size-4' /></button>
                    </li>)}
                </ol>
                <p role='status' className='sr-only'>{message}</p>
                {error && <p role='alert' className='px-4 text-sm text-destructive'>{error}</p>}
                <footer className='flex shrink-0 flex-wrap items-center justify-end gap-x-3 border-t px-4 py-2 pb-[max(.5rem,env(safe-area-inset-bottom))] text-sm'>
                    <button type='button' className='me-auto min-h-11 text-tint' onClick={() => { setDraft([]); setMessage('Восстановлен порядок по умолчанию') }}>По умолчанию</button>
                    <Dialog.Close className='min-h-11 text-tint'>Отмена</Dialog.Close>
                    <button type='button' className='min-h-11 rounded-xl bg-primary px-3 font-medium text-primary-foreground' onClick={() => {
                        const ids = rows.map(item => item.id)
                        const standard = ordered(services, [])
                        try {
                            save(ids.every((id, i) => standard[i].id === id) ? [] : ids)
                            setOpen(false)
                        } catch {
                            setError('Не удалось сохранить порядок. Проверьте, разрешено ли браузеру хранить данные сайта.')
                        }
                    }}>Готово</button>
                </footer>
            </Dialog.Popup>
        </Dialog.Portal>
    </Dialog.Root>
}
