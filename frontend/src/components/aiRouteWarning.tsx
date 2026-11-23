import { useEffect, useRef, useState } from 'react'
import { Dialog } from '@base-ui/react/dialog'
import { IconAlertTriangle, IconX } from '@tabler/icons-react'
import type { ServiceTarget } from '@/lib/serviceRouteOptions'

interface Props {
    serviceName: string
    targetLabel: string
    targetKind?: ServiceTarget['kind']
    canApplyGroup: boolean
    busy: boolean
    error?: string
    onGroup: () => void
    onSingle: () => void
    onCancel: () => void
}

// Mount for each new choice, before writing any route. The delay applies to the
// buttons that change a route; cancelling (button, close, Escape, backdrop) is
// available at once and is refused only while a route is being applied.
export function AiRouteWarning({ serviceName, targetLabel, targetKind, canApplyGroup, busy, error, onGroup, onSingle, onCancel }: Props) {
    const deadline = useRef(performance.now() + 5000)
    const [remaining, setRemaining] = useState(5)
    useEffect(() => {
        const timer = window.setInterval(() => setRemaining(Math.max(0, Math.ceil((deadline.current - performance.now()) / 1000))), 100)
        return () => window.clearInterval(timer)
    }, [])
    const locked = remaining > 0 || busy
    const act = (action: () => void) => {
        if (!busy && performance.now() >= deadline.current) action()
    }
    const cancel = () => {
        if (!busy) onCancel()
    }
    return <Dialog.Root open onOpenChange={next => { if (!next) cancel() }}>
        <Dialog.Portal>
            <Dialog.Backdrop className='fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]' />
            <Dialog.Popup className='fixed inset-x-3 top-1/2 z-50 flex max-h-[90dvh] -translate-y-1/2 flex-col overflow-hidden rounded-[26px] border bg-popover text-popover-foreground shadow-2xl outline-none sm:inset-x-auto sm:left-1/2 sm:w-[min(34rem,calc(100vw-2rem))] sm:-translate-x-1/2'>
                <header className='flex shrink-0 items-center gap-3 border-b px-4 py-3'>
                    <IconAlertTriangle aria-hidden className='size-6 shrink-0 text-warning' />
                    <Dialog.Title className='min-w-0 flex-1 font-semibold'>Один VPN для AI и аналитики</Dialog.Title>
                    <button type='button' aria-label='Закрыть предупреждение' disabled={busy} onClick={cancel} className='grid size-11 shrink-0 place-items-center rounded-full text-muted-foreground hover:bg-muted disabled:opacity-30'><IconX aria-hidden className='size-5' /></button>
                </header>
                <div className='min-h-0 space-y-3 overflow-y-auto px-5 py-4 text-sm'>
                    <Dialog.Description>Вы выбираете <strong className='text-foreground'>{targetLabel}</strong> для {serviceName}. Применить тот же конфиг к Claude, ChatGPT, AI и аналитике?</Dialog.Description>
                    <p className='text-muted-foreground'>AI-приложения и агенты обращаются к общим адресам аналитики и проверки безопасности. Эти запросы могут не попасть в правила самого AI-сервиса и пойти по карточке аналитики.</p>
                    <p className='text-muted-foreground'>Разные VPN могут показать одному сервису разные IP. Крайне рекомендуем один конфиг для всех четырёх карточек, особенно для Claude / Anthropic: это помогает избежать разных выходов и уменьшить риск проблем с аккаунтом.</p>
                    {targetKind === 'pool' && <p className='rounded-xl bg-warning/10 p-3 text-warning'>Один пул может выбрать разные серверы для разных соединений. Для постоянного общего выхода выберите конкретный сервер.</p>}
                    {!canApplyGroup && <p className='text-warning'>Одним действием всем четырём карточкам можно назначить только VPN. Прямой выход нельзя применить ко всей группе: Claude требует VPN.</p>}
                    <p className='text-muted-foreground'>Если пользуетесь голосовым чатом, проверьте его на выбранном сервере. Настройки kill switch сохраняются.</p>
                    {error && <p role='alert' className='text-destructive'>{error}</p>}
                </div>
                <footer className='shrink-0 space-y-2 border-t p-4 pb-[max(1rem,env(safe-area-inset-bottom))]'>
                    <p role='status' aria-live='polite' className='min-h-5 text-center text-sm tabular-nums text-muted-foreground'>{busy ? 'Применяем маршрут…' : remaining > 0 ? `Прочитайте предупреждение · ${remaining} с` : 'Выберите, какие карточки изменить'}</p>
                    <button type='button' disabled={locked || !canApplyGroup} onClick={() => act(onGroup)} className='min-h-11 w-full rounded-xl bg-primary px-3 py-2 font-semibold text-primary-foreground disabled:opacity-40'>Применить ко всем четырём</button>
                    <button type='button' disabled={locked} onClick={() => act(onSingle)} className='min-h-11 w-full rounded-xl border px-3 py-2 text-tint disabled:opacity-40'>Только для {serviceName}</button>
                    <button type='button' disabled={busy} onClick={cancel} className='min-h-11 w-full text-muted-foreground disabled:opacity-40'>Отмена</button>
                </footer>
            </Dialog.Popup>
        </Dialog.Portal>
    </Dialog.Root>
}
