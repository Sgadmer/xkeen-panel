import { useEffect, useRef, useState } from 'react'
import { Dialog } from '@base-ui/react/dialog'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { IconTrash, IconX } from '@tabler/icons-react'
import { api } from '@/lib/api'
import type { Device } from '@/types'

export function DeviceEditor({ device, returnFocus, onClose, onSaved }: {
    device: Device
    returnFocus: () => HTMLElement | null
    onClose: () => void
    onSaved: (message: string) => void
}) {
    const [name, setName] = useState(device.name)
    const [confirmForget, setConfirmForget] = useState(false)
    const cancel = useRef<HTMLButtonElement>(null)
    const forget = useRef<HTMLButtonElement>(null)
    const close = useRef<HTMLButtonElement>(null)
    const qc = useQueryClient()
    const action = useMutation({
        mutationFn: (kind: 'rename' | 'register' | 'forget') => kind === 'forget'
            ? api.post('/api/devices/forget', { mac: device.mac })
            : api.post('/api/devices/rename', { mac: device.mac, name: name.trim() }),
        onSuccess: async (_, kind) => {
            await qc.invalidateQueries({ queryKey: ['devices'] })
            onSaved(kind === 'forget' ? 'Регистрация устройства удалена.'
                : kind === 'rename' ? 'Имя устройства сохранено.' : 'Устройство зарегистрировано.')
        },
    })
    useEffect(() => {
        if (confirmForget) cancel.current?.focus()
    }, [confirmForget])
    const canSave = !!name.trim() && (!device.registered || name.trim() !== device.name) && !action.isPending

    return <Dialog.Root open onOpenChange={open => { if (!open && !action.isPending) onClose() }}>
        <Dialog.Portal>
            <Dialog.Backdrop className='fixed inset-0 z-50 bg-black/55 backdrop-blur-[2px]' />
            <Dialog.Popup initialFocus={close} finalFocus={returnFocus}
                className='fixed inset-x-0 bottom-0 z-50 max-h-[90dvh] overflow-y-auto overscroll-contain rounded-t-[26px] border bg-popover p-4 pb-[max(1rem,env(safe-area-inset-bottom))] text-popover-foreground shadow-2xl outline-none sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:w-[27rem] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-[26px]'>
                <header className='mb-4 flex items-start justify-between gap-2'>
                    <div className='min-w-0'>
                        <Dialog.Title className='text-lg font-semibold'>
                            {confirmForget ? 'Удалить регистрацию?' : 'Устройство'}
                        </Dialog.Title>
                        <Dialog.Description className='mt-1 text-sm text-muted-foreground [overflow-wrap:anywhere]'>
                            {device.name} · {device.mac}
                        </Dialog.Description>
                    </div>
                    <Dialog.Close ref={close} aria-label='Закрыть' disabled={action.isPending}
                        className='grid size-11 shrink-0 cursor-pointer place-items-center rounded-full text-muted-foreground hover:bg-muted'>
                        <IconX aria-hidden className='size-5' />
                    </Dialog.Close>
                </header>
                {confirmForget ? <div className='space-y-4'>
                    <p className='text-sm'>Роутер забудет имя устройства. Его личные настройки, включая правила VPN и проброс портов, могут сброситься. Если устройство в сети, оно может сразу появиться в списке снова.</p>
                    <div className='flex flex-wrap justify-end gap-2'>
                        <button ref={cancel} type='button' disabled={action.isPending}
                            onClick={() => { action.reset(); setConfirmForget(false); requestAnimationFrame(() => forget.current?.focus()) }}
                            className='min-h-11 rounded-xl px-4 text-tint hover:bg-muted'>Оставить</button>
                        <button type='button' disabled={action.isPending || !device.registered} onClick={() => action.mutate('forget')}
                            className='min-h-11 rounded-xl bg-destructive/10 px-4 font-semibold text-destructive disabled:opacity-50'>
                            {action.isPending ? 'Удаляем…' : 'Удалить регистрацию'}
                        </button>
                    </div>
                </div> : <>
                    <form onSubmit={event => { event.preventDefault(); if (canSave) action.mutate(device.registered ? 'rename' : 'register') }}>
                        <label className='block text-sm font-medium'>
                            Имя на роутере
                            <input type='text' required value={name} onChange={event => setName(event.target.value)}
                                disabled={action.isPending} autoComplete='off'
                                className='mt-1 block min-h-11 w-full rounded-xl border bg-card px-3 text-base text-foreground' />
                        </label>
                        {!device.registered && <p className='mt-2 text-sm text-muted-foreground'>Роутер запомнит это устройство под выбранным именем.</p>}
                        <button type='submit' disabled={!canSave}
                            className='mt-3 min-h-11 w-full rounded-xl bg-primary px-4 font-semibold text-primary-foreground disabled:opacity-50'>
                            {action.isPending ? 'Сохраняем…' : device.registered ? 'Сохранить имя' : 'Зарегистрировать'}
                        </button>
                    </form>
                    {device.registered && <div className='mt-4 border-t pt-2'>
                        <button ref={forget} type='button' disabled={action.isPending}
                            className='flex min-h-11 items-center gap-2 rounded-lg px-2 text-sm text-destructive hover:bg-destructive/10'
                            onClick={() => { action.reset(); setConfirmForget(true) }}>
                            <IconTrash aria-hidden className='size-4' /> Удалить регистрацию…
                        </button>
                    </div>}
                </>}
                {action.error && <p role='alert' className='mt-3 text-sm text-destructive'>{action.error.message}</p>}
            </Dialog.Popup>
        </Dialog.Portal>
    </Dialog.Root>
}
