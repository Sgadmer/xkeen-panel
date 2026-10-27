import { useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import { IconLoader2, IconX } from '@tabler/icons-react'

export interface SettingChange {
    setting_id: string
    name: string
    current: boolean
    desired: boolean
    effects: string[]
}

const actionTargets: Record<string, string> = {
    autostart: 'автозапуск XKeen',
    dns: 'перехват DNS',
    router_proxy: 'обработку трафика Entware',
    ipv6: 'IPv6',
    verbose: 'подробные сообщения запуска',
    backup: 'резервную копию XKeen',
    native_geodata_schedule: 'штатное расписание геобаз XKeen',
}

export function SettingChangeDialog({
    name, current, desired, change, warnings, requiredBytes, loading, error,
    applying, ready, onRetry, onCancel, onConfirm,
}: {
    name: string
    current: boolean
    desired: boolean
    change?: SettingChange
    warnings: string[]
    requiredBytes?: number
    loading: boolean
    error?: string
    applying: boolean
    ready: boolean
    onRetry: () => void
    onCancel: () => void
    onConfirm: () => void
}) {
    const dialog = useRef<HTMLDialogElement>(null)
    const cancelButton = useRef<HTMLButtonElement>(null)
    const titleId = useId()
    const descriptionId = useId()

    useEffect(() => {
        const element = dialog.current
        if (!element) return
        const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null
        const overflow = document.body.style.overflow
        document.body.style.overflow = 'hidden'
        element.showModal()
        cancelButton.current?.focus()
        return () => {
            element.close()
            document.body.style.overflow = overflow
            if (opener?.isConnected) opener.focus()
        }
    }, [])

    const actual = change?.current ?? current
    const next = change?.desired ?? desired
    const settingName = change?.name || name
    const action = next ? 'Включить' : 'Выключить'
    const actionTarget = actionTargets[change?.setting_id || ''] || 'параметр'

    return createPortal(
        <dialog
            ref={dialog}
            aria-modal='true'
            aria-labelledby={titleId}
            aria-describedby={descriptionId}
            onCancel={event => { event.preventDefault(); if (!applying) onCancel() }}
            onClick={event => {
                if (event.target !== event.currentTarget || applying) return
                const bounds = event.currentTarget.getBoundingClientRect()
                if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) onCancel()
            }}
            className='fixed inset-0 m-auto max-h-[90dvh] w-[calc(100%_-_2rem)] max-w-lg flex-col overflow-hidden rounded-[26px] border border-white/10 bg-card p-0 text-foreground shadow-2xl outline-none [color-scheme:dark] backdrop:bg-black/65 backdrop:backdrop-blur-[2px] open:flex'
        >
            <header className='flex shrink-0 items-start gap-3 border-b border-white/10 px-5 py-4'>
                <div className='min-w-0 flex-1'>
                    <h2 id={titleId} className='text-[19px] font-semibold'>Изменить параметр XKeen</h2>
                    <p className='mt-1 break-words text-[15px] text-muted-foreground'>{settingName}</p>
                </div>
                <button type='button' aria-label='Закрыть подтверждение изменения' disabled={applying} onClick={onCancel} className='-mr-2 -mt-1 flex size-11 shrink-0 cursor-pointer items-center justify-center rounded-full text-muted-foreground focus-visible:outline-2 focus-visible:outline-tint disabled:opacity-50'>
                    <IconX className='size-5' aria-hidden='true' />
                </button>
            </header>
            <div className='space-y-4 overflow-y-auto px-5 py-4'>
                <p id={descriptionId} className='text-[14px] text-muted-foreground'>Проверьте изменение перед применением. Параметр пока остаётся в текущем состоянии.</p>
                <dl className='grid grid-cols-2 gap-3 rounded-xl bg-fill p-3 text-[15px]'>
                    <div><dt className='text-[13px] text-muted-foreground'>Сейчас</dt><dd className='mt-1 font-semibold'>{actual ? 'Включено' : 'Выключено'}</dd></div>
                    <div><dt className='text-[13px] text-muted-foreground'>После применения</dt><dd className='mt-1 font-semibold text-tint'>{next ? 'Включено' : 'Выключено'}</dd></div>
                </dl>
                {loading && <p role='status' className='flex items-start gap-2 text-[14px] text-muted-foreground'><IconLoader2 aria-hidden='true' className='mt-0.5 size-5 shrink-0 animate-spin' />Проверяем параметр, резервную копию и свободное место…</p>}
                {change && <div><h3 className='mb-2 text-[14px] font-semibold'>Что изменится</h3><ul className='list-disc space-y-2 pl-5 text-[14px] leading-relaxed'>{change.effects.map(effect => <li key={effect}>{effect}</li>)}</ul></div>}
                {warnings.length > 0 && <div className='space-y-2 rounded-xl bg-amber-500/10 p-3 text-[14px] leading-relaxed text-amber-200'>{warnings.map(warning => <p key={warning}>{warning}</p>)}</div>}
                <p className='text-[13px] leading-relaxed text-muted-foreground'>Новая версия XKeen не скачивается. Перед изменением панель сохранит резервную копию для отката.{requiredBytes !== undefined && ` Проверено свободное место: для копии и восстановления нужно не менее ${Math.ceil(requiredBytes / 1048576)} МБ.`}</p>
                {error && <div role='alert' className='space-y-2 text-[14px] text-destructive'><p>{error}</p>{!applying && <button type='button' onClick={onRetry} className='min-h-11 cursor-pointer text-tint underline underline-offset-4'>Повторить проверку</button>}</div>}
            </div>
            <footer className='flex shrink-0 flex-col gap-2 border-t border-white/10 px-5 pb-[max(16px,env(safe-area-inset-bottom))] pt-4'>
                <button type='button' disabled={!ready || loading || applying} onClick={onConfirm} className='min-h-11 cursor-pointer rounded-xl bg-primary px-4 py-3 text-[15px] font-semibold leading-snug text-primary-foreground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tint disabled:cursor-default disabled:opacity-50'>{applying ? 'Запускаем изменение…' : `${action} ${actionTarget}`}</button>
                <button ref={cancelButton} type='button' disabled={applying} onClick={onCancel} className='min-h-11 cursor-pointer rounded-xl px-4 text-[15px] text-tint focus-visible:outline-2 focus-visible:outline-tint disabled:opacity-50'>Отменить</button>
            </footer>
        </dialog>,
        document.body,
    )
}
