import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Dialog } from '@base-ui/react/dialog'
import { IconAlertTriangle, IconX } from '@tabler/icons-react'

// The wait before a choice that lowers protection can be confirmed. Mounted
// with each new choice, so the countdown always starts from the beginning.
export function useConfirmDelay(seconds = 5) {
    const deadline = useRef(performance.now() + seconds * 1000)
    const [remaining, setRemaining] = useState(seconds)
    useEffect(() => {
        if (seconds <= 0) return
        const timer = window.setInterval(() => setRemaining(Math.max(0, Math.ceil((deadline.current - performance.now()) / 1000))), 100)
        return () => window.clearInterval(timer)
    }, [seconds])
    return { remaining, ready: () => performance.now() >= deadline.current }
}

// One window for every action that lowers protection: what will change, a few
// seconds to read it, then the confirming button. Cancelling never waits.
export function ProtectionWarning({ title, children, confirmLabel, busy = false, error, delay = 5, onConfirm, onCancel }: {
    title: string
    children: ReactNode
    confirmLabel: string
    busy?: boolean
    error?: string
    delay?: number
    onConfirm: () => void
    onCancel: () => void
}) {
    const wait = useConfirmDelay(delay)
    const cancel = () => {
        if (!busy) onCancel()
    }
    const confirm = () => {
        if (!busy && wait.ready()) onConfirm()
    }
    return <Dialog.Root open onOpenChange={next => { if (!next) cancel() }}>
        <Dialog.Portal>
            <Dialog.Backdrop className='fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]' />
            <Dialog.Popup className='fixed inset-x-3 top-1/2 z-50 flex max-h-[90dvh] -translate-y-1/2 flex-col overflow-hidden rounded-[26px] border bg-popover text-popover-foreground shadow-2xl outline-none sm:inset-x-auto sm:left-1/2 sm:w-[min(34rem,calc(100vw-2rem))] sm:-translate-x-1/2'>
                <header className='flex shrink-0 items-center gap-3 border-b px-4 py-3'>
                    <IconAlertTriangle aria-hidden className='size-6 shrink-0 text-warning' />
                    <Dialog.Title className='min-w-0 flex-1 font-semibold'>{title}</Dialog.Title>
                    <button type='button' aria-label='Закрыть предупреждение' disabled={busy} onClick={cancel} className='grid size-11 shrink-0 place-items-center rounded-full text-muted-foreground hover:bg-muted disabled:opacity-30'><IconX aria-hidden className='size-5' /></button>
                </header>
                <Dialog.Description render={<div />} className='min-h-0 space-y-3 overflow-y-auto px-5 py-4 text-sm'>
                    {children}
                    {error && <p role='alert' className='text-destructive'>{error}</p>}
                </Dialog.Description>
                <footer className='shrink-0 space-y-2 border-t p-4 pb-[max(1rem,env(safe-area-inset-bottom))]'>
                    <p role='status' aria-live='polite' className='min-h-5 text-center text-sm tabular-nums text-muted-foreground'>{busy ? 'Применяем…' : wait.remaining > 0 ? `Прочитайте предупреждение · ${wait.remaining} с` : ''}</p>
                    <button type='button' disabled={busy || wait.remaining > 0} onClick={confirm} className='min-h-11 w-full rounded-xl bg-primary px-3 py-2 font-semibold text-primary-foreground disabled:opacity-40'>{confirmLabel}</button>
                    <button type='button' disabled={busy} onClick={cancel} className='min-h-11 w-full text-muted-foreground disabled:opacity-40'>Отмена</button>
                </footer>
            </Dialog.Popup>
        </Dialog.Portal>
    </Dialog.Root>
}
