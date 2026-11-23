import { useEffect, useState } from 'react'
import { IconCheck } from '@tabler/icons-react'
import { Group, Row } from '@/components/ios'
import { Sheet } from '@/components/sheet'
import { countryLabel } from '@/lib/format'

const check = <IconCheck className='size-5 shrink-0 text-tint' stroke={2.6} />

export function CountriesSheet({
    open,
    onClose,
    value,
    candidates,
    catalogStatus,
    onRetry,
    onSave,
}: {
    open: boolean
    onClose: () => void
    value: string[]
    candidates: string[]
    catalogStatus?: string
    onRetry?: () => void
    onSave: (countries: string[]) => Promise<unknown>
}) {
    const [edits, setEdits] = useState<Record<string, boolean>>({})
    const [error, setError] = useState('')
    const [saving, setSaving] = useState(false)

    useEffect(() => {
        if (open) {
            setEdits({})
            setError('')
        }
    }, [open])

    const save = async () => {
        // Keep saved countries that disappeared while editing. Apply only visible edits.
        const next = new Set(value)
        for (const code of candidates) {
            if (edits[code] === true) next.add(code)
            if (edits[code] === false) next.delete(code)
        }
        if (value.length === next.size && value.every(code => next.has(code))) {
            onClose()
            return
        }
        setSaving(true)
        try {
            await onSave([...next])
            onClose()
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Не удалось сохранить')
        } finally {
            setSaving(false)
        }
    }

    return (
        <Sheet
            open={open}
            onClose={onClose}
            title='Исключенные локации'
            done={{ label: 'Готово', onClick: save, disabled: saving }}
        >
            <Group
                footer={
                    error ? (
                        <span className='text-destructive'>{error}</span>
                    ) : (
                        'Автовыбор и автоматическая замена пропускают серверы с отмеченной локацией. Локацию серверу задаёт подписка. Во вкладке «Все серверы» любой сервер по-прежнему можно выбрать вручную. Сборные профили используют свои правила.'
                    )
                }
            >
                {candidates.map(code => (
                    <Row
                        key={code}
                        label={countryLabel(code)}
                        disabled={saving}
                        onClick={() => setEdits(prev => ({ ...prev, [code]: !(prev[code] ?? value.includes(code)) }))}
                        trailing={
                            (edits[code] ?? value.includes(code)) ? (
                                check
                            ) : (
                                <span className='size-5' />
                            )
                        }
                    />
                ))}
                {catalogStatus && <Row label={catalogStatus} />}
                {onRetry && <Row label='Повторить загрузку стран' tone='tint' onClick={onRetry} />}
                {!catalogStatus && !candidates.length && <Row label='В подписках пока нет серверов с известной страной' />}
            </Group>
        </Sheet>
    )
}

const INTERVALS = [
    { minutes: 15, label: 'Каждые 15 минут' },
    { minutes: 30, label: 'Каждые 30 минут' },
    { minutes: 60, label: 'Каждый час' },
    { minutes: 180, label: 'Каждые 3 часа' },
    { minutes: 360, label: 'Каждые 6 часов' },
    { minutes: 1440, label: 'Раз в сутки' },
    { minutes: 0, label: 'Не обновлять' },
]

export function intervalLabel(minutes: number) {
    if (minutes === 0) return 'Выкл.'
    if (minutes === 1440) return 'раз в сутки'
    if (minutes % 60 === 0) return `каждые ${minutes / 60} ч`
    return `каждые ${minutes} мин`
}

export function RefreshSheet({
    open,
    onClose,
    value,
    onSave,
}: {
    open: boolean
    onClose: () => void
    value: number
    onSave: (minutes: number) => Promise<unknown>
}) {
    const [picked, setPicked] = useState(value)
    const [error, setError] = useState('')

    useEffect(() => {
        if (open) {
            setPicked(value)
            setError('')
        }
    }, [open, value])

    const save = async () => {
        try {
            await onSave(picked)
            onClose()
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Не удалось сохранить')
        }
    }

    return (
        <Sheet
            open={open}
            onClose={onClose}
            title='Обновлять подписку'
            done={{ label: 'Готово', onClick: save }}
        >
            <Group
                footer={
                    error ? (
                        <span className='text-destructive'>{error}</span>
                    ) : (
                        'Провайдеры меняют адреса серверов. Панель скачивает подписку заново и обновляет пул без перезапуска, если сервер в нём не изменился.'
                    )
                }
            >
                {INTERVALS.map(i => (
                    <Row
                        key={i.minutes}
                        label={i.label}
                        onClick={() => setPicked(i.minutes)}
                        trailing={
                            picked === i.minutes ? (
                                check
                            ) : (
                                <span className='size-5' />
                            )
                        }
                    />
                ))}
            </Group>
        </Sheet>
    )
}
