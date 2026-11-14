import { useState, type KeyboardEvent } from 'react'
import { Dialog } from '@base-ui/react/dialog'
import { IconCheck, IconChevronDown, IconX } from '@tabler/icons-react'
import type { RouteGroup } from '@/lib/serviceRouteOptions'
import { cn } from '@/lib/utils'

interface ServiceRoutePickerProps {
    id: string
    serviceName: string
    groups: RouteGroup[]
    value: string
    inheritedLabel: string
    allowInherited: boolean
    allowDirect: boolean
    disabled: boolean
    onSelect: (id: string) => void
}

const focusRing = 'focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring'

function RouteChoice({ label, detail, current, disabled, onClick }: {
    label: string
    detail?: string
    current: boolean
    disabled: boolean
    onClick: () => void
}) {
    return (
        <button type='button' aria-pressed={current} disabled={disabled} onClick={onClick}
            className={cn('flex min-h-11 w-full cursor-pointer items-center gap-3 px-4 py-2 text-start text-[15px] hover:bg-muted disabled:cursor-default disabled:opacity-60',
                current && 'bg-primary/10', focusRing)}>
            <span className='min-w-0 flex-1 whitespace-pre-wrap [overflow-wrap:anywhere]'>
                {label}
                {detail && <span className='block text-[13px] text-muted-foreground'>{detail}</span>}
            </span>
            {current && <IconCheck aria-hidden className='size-5 shrink-0 text-primary dark:text-tint' />}
        </button>
    )
}

function moveFocus(event: KeyboardEvent<HTMLDivElement>) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return
    const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'))
    const index = buttons.indexOf(event.target as HTMLButtonElement)
    if (index === -1) return
    event.preventDefault()
    let next = index
    if (event.key === 'ArrowDown') next = Math.min(index + 1, buttons.length - 1)
    if (event.key === 'ArrowUp') next = Math.max(index - 1, 0)
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = buttons.length - 1
    buttons[next].focus()
}

export function ServiceRoutePicker({ id, serviceName, groups, value, inheritedLabel, allowInherited, allowDirect, disabled, onSelect }: ServiceRoutePickerProps) {
    const [open, setOpen] = useState(false)
    const [expanded, setExpanded] = useState<string | null>(null)
    const selectedGroup = groups.find(group => group.targets.some(target => target.id === value))
    const selected = selectedGroup?.targets.find(target => target.id === value)
    const missing = !!value && !(value === 'direct' && allowDirect) && !selected
    const currentLabel = selected?.label ?? (missing ? 'Назначенный маршрут недоступен' : value === 'direct' ? 'Напрямую' : inheritedLabel)

    function choose(next: string) {
        if (disabled) return
        setOpen(false)
        if (next !== value) onSelect(next)
    }

    return (
        <Dialog.Root open={open} onOpenChange={next => {
            if (next && disabled) return
            if (next) setExpanded(null)
            setOpen(next)
        }}>
            <Dialog.Trigger id={id} type='button' aria-disabled={disabled || undefined}
                aria-label={`Маршрут · ${serviceName} · ${currentLabel}`}
                className={cn('mt-1 flex min-h-11 w-full cursor-pointer items-center gap-2 rounded-xl border bg-popover px-3 py-2 text-start text-[15px] text-popover-foreground aria-disabled:cursor-default aria-disabled:opacity-60', focusRing)}>
                <span className='min-w-0 flex-1 whitespace-pre-wrap [overflow-wrap:anywhere]'>{currentLabel}</span>
                <IconChevronDown aria-hidden className='size-4 shrink-0 text-muted-foreground' />
            </Dialog.Trigger>
            <Dialog.Portal>
                <Dialog.Backdrop className='fixed inset-0 z-50 bg-black/55 backdrop-blur-[2px]' />
                <Dialog.Popup className='fixed inset-x-0 bottom-0 z-50 flex max-h-[90dvh] flex-col overflow-hidden rounded-t-[26px] border bg-popover text-popover-foreground shadow-2xl outline-none sm:inset-x-auto sm:bottom-auto sm:left-1/2 sm:top-1/2 sm:max-h-[min(90dvh,46rem)] sm:w-[30rem] sm:-translate-x-1/2 sm:-translate-y-1/2 sm:rounded-[26px]'>
                    <header className='flex shrink-0 items-center gap-3 border-b px-4 py-3'>
                        <Dialog.Title className='min-w-0 flex-1 text-lg font-semibold'>Маршрут · {serviceName}</Dialog.Title>
                        <Dialog.Close aria-label='Закрыть' className={cn('grid size-11 shrink-0 cursor-pointer place-items-center rounded-full text-muted-foreground hover:bg-muted', focusRing)}>
                            <IconX aria-hidden className='size-5' />
                        </Dialog.Close>
                    </header>
                    <div className='min-h-0 overflow-y-auto overscroll-contain bg-muted/40' onKeyDown={moveFocus}>
                      <div className='space-y-2.5 p-3 pb-[max(.75rem,env(safe-area-inset-bottom))]'>
                        {(allowInherited || allowDirect || missing) && <div className='divide-y overflow-hidden rounded-2xl border bg-card'>
                            {missing && <p className='px-4 py-3 text-sm text-muted-foreground'>{currentLabel}</p>}
                            {allowInherited && <RouteChoice label={inheritedLabel} current={value === ''} disabled={disabled} onClick={() => choose('')} />}
                            {allowDirect && <RouteChoice label='Напрямую' current={value === 'direct'} disabled={disabled} onClick={() => choose('direct')} />}
                        </div>}
                        {groups.map((group, index) => {
                            const active = expanded === group.key
                            const contentId = id + '-options-' + index
                            return (
                                <section key={group.key} className='overflow-clip rounded-2xl border bg-card'>
                                    <h3 className='sticky top-0 z-10 bg-card'>
                                        <button type='button' aria-expanded={active} aria-controls={active ? contentId : undefined}
                                            className={cn('flex min-h-12 w-full cursor-pointer items-center gap-3 bg-muted/60 px-4 py-2.5 text-start hover:bg-muted', focusRing)}
                                            onClick={() => setExpanded(active ? null : group.key)}>
                                            <span className='min-w-0 flex-1'>
                                                <span className='block whitespace-pre-wrap font-semibold [overflow-wrap:anywhere]'>{group.title}</span>
                                                {selectedGroup === group && <span className='block whitespace-pre-wrap text-[13px] text-primary [overflow-wrap:anywhere] dark:text-tint'>{selected?.label}</span>}
                                            </span>
                                            <span aria-hidden className='text-sm tabular-nums text-muted-foreground'>{group.targets.length}</span>
                                            <IconChevronDown aria-hidden className={cn('size-4 shrink-0 text-muted-foreground', active && 'rotate-180')} />
                                        </button>
                                    </h3>
                                    {active && <div id={contentId} className='divide-y border-t'>
                                        {group.targets.map(target => <RouteChoice key={target.id} label={target.label} detail={target.detail}
                                            current={value === target.id} disabled={disabled} onClick={() => choose(target.id)} />)}
                                    </div>}
                                </section>
                            )
                        })}
                        {!groups.length && <p className='p-2 text-sm text-muted-foreground'>Доступных VPN-маршрутов нет.</p>}
                      </div>
                    </div>
                </Dialog.Popup>
            </Dialog.Portal>
        </Dialog.Root>
    )
}
