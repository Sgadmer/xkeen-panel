import { useEffect, useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { IconLoader2, IconLock } from '@tabler/icons-react'
import { Group, PageTitle, Row, Segmented, Switch } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { useUpdate } from '@/hooks/usePanelData'
import { api } from '@/lib/api'
import { isSet } from '@/lib/format'
import type { UpdateState } from '@/types'

type Channel = 'stable' | 'preview'

const back = { to: '/settings', label: 'Настройки' }
const channels: { value: Channel; label: string }[] = [
    { value: 'stable', label: 'Стабильные' },
    { value: 'preview', label: 'Стабильные и бета' },
]
const field =
    'min-h-11 min-w-0 flex-1 rounded-xl border border-white/10 bg-fill px-3 text-[16px] outline-none focus:border-tint disabled:opacity-50'

// Release notes are GitHub markdown; plain text reads fine here
const plainNotes = (md: string) =>
    md.replace(/\*\*/g, '').replace(/^#+\s*/gm, '')

export function UpdatePage() {
    const qc = useQueryClient()
    const u = useUpdate().data
    const [showNotes, setShowNotes] = useState(false)
    const [picked, setPicked] = useState('')
    const [asking, setAsking] = useState('')

    const store = (state: UpdateState) => qc.setQueryData(['update'], state)
    const check = useMutation({
        mutationFn: () => api.post<UpdateState>('/api/update/check'),
        onSuccess: store,
    })
    const apply = useMutation({
        mutationFn: (tag?: string) =>
            api.post<UpdateState>(
                '/api/update/apply',
                tag ? { tag } : undefined,
            ),
        onSuccess: state => {
            store(state)
            setAsking('')
        },
    })
    const setAuto = useMutation({
        mutationFn: (auto: boolean) =>
            api.put<UpdateState>('/api/update/settings', { auto }),
        onMutate: auto =>
            qc.setQueryData<UpdateState>(['update'], old =>
                old ? { ...old, auto } : old,
            ),
        onSuccess: store,
        onError: () => qc.invalidateQueries({ queryKey: ['update'] }),
    })
    const setChannel = useMutation({
        mutationFn: (channel: Channel) =>
            api.put<UpdateState>('/api/update/settings', { channel }),
        onSuccess: store,
    })

    // A panel that has just started has not looked for releases yet. The page
    // asks at once, so it never shows an empty answer after an installation.
    const asked = useRef(false)
    const { mutate: runCheck } = check
    const unchecked =
        !!u &&
        u.supported &&
        !u.locked &&
        !u.updating &&
        !setChannel.isPending &&
        !isSet(u.last_check) &&
        !u.check_error
    useEffect(() => {
        if (!unchecked || asked.current) return
        asked.current = true
        runCheck()
    }, [unchecked, runCheck])

    if (!u) return <PageTitle title='О панели и обновление' back={back} />

    if (u.locked) {
        return (
            <>
                <PageTitle
                    title='О панели и обновление'
                    subtitle={`Установлена ${u.current}`}
                    back={back}
                />
                <Group footer='Обновление подписки продолжает работать по расписанию из настроек.'>
                    <Row
                        icon={<IconLock className='size-5 shrink-0 text-tint' />}
                        label='Обновление кода панели заблокировано'
                        hint='Защита персональной сборки. Изменения кода устанавливаются отдельно.'
                    />
                </Group>
            </>
        )
    }

    if (!u.supported) {
        return (
            <>
                <PageTitle title='О панели и обновление' back={back} />
                <Group>
                    <Row
                        label='Самообновление недоступно'
                        hint={u.reason}
                        detail={u.current}
                    />
                </Group>
            </>
        )
    }

    const busy =
        u.updating ||
        check.isPending ||
        apply.isPending ||
        setChannel.isPending
    const error =
        (check.error ?? setAuto.error ?? setChannel.error)?.message ??
        (asking ? undefined : apply.error?.message) ??
        u.apply_error ??
        u.check_error
    const hour = String(u.auto_hour).padStart(2, '0')
    const lastCheck = isSet(u.last_check)
        ? new Date(u.last_check!).toLocaleString('ru-RU', {
              day: 'numeric',
              month: 'short',
              hour: '2-digit',
              minute: '2-digit',
          })
        : null

    const channel: Channel =
        setChannel.isPending && setChannel.variables
            ? setChannel.variables
            : u.channel === 'preview'
              ? 'preview'
              : 'stable'
    const versions = u.versions ?? []
    const place = (tag: string) => versions.findIndex(v => v.tag === tag)
    const choice = versions.some(v => v.tag === picked)
        ? picked
        : (versions.find(v => v.tag !== u.current)?.tag ?? '')
    // The list runs from the newest version down
    const older = place(u.current) >= 0 && place(choice) > place(u.current)

    const onInstall = () => {
        apply.reset()
        if (older) setAsking(choice)
        else apply.mutate(choice)
    }

    return (
        <>
            <PageTitle
                title='О панели и обновление'
                subtitle={`Установлена ${u.current}`}
                back={back}
            />

            <Group footer='Здесь обновляется только панель. Версии XKeen, Xray и геобазы управляются в разделе «Роутер и XKeen».'>
                <Row label='Источник обновлений' detail={u.repository ?? 'Sgadmer/xkeen-panel'} />
                <Row label='Проверка выпуска' detail='По подписи автора' hint='Панель ставит только выпуск, контрольные суммы которого подписаны ключом автора. Файл, подменённый на GitHub, не установится.' />
            </Group>

            <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
                <div className='grid min-w-0 gap-5'>
                    <Group
                        footer={
                            u.auto
                                ? `Новые версии ставятся сами ночью, в ${hour}:00 по времени роутера.`
                                : 'Панель только проверяет новые версии — ставить их нужно вручную.'
                        }
                    >
                        <Row
                            label='Обновляться автоматически'
                            trailing={
                                <Switch
                                    checked={u.auto}
                                    onChange={auto => setAuto.mutate(auto)}
                                    label='Обновляться автоматически'
                                    disabled={setAuto.isPending}
                                />
                            }
                        />
                    </Group>

                    <Group
                        title='Какие версии получать'
                        footer={
                            channel === 'preview'
                                ? 'Бета-версии выходят раньше стабильных и могут работать с ошибками.'
                                : 'Только готовые версии. Бета-версии не предлагаются и сами не ставятся.'
                        }
                    >
                        <div className='py-3'>
                            <Segmented
                                label='Какие версии получать'
                                options={channels}
                                value={channel}
                                onChange={next => {
                                    if (busy || next === channel) return
                                    setPicked('')
                                    setChannel.mutate(next)
                                }}
                            />
                        </div>
                    </Group>
                </div>

                <div className='grid min-w-0 gap-5'>
                    <Group
                        footer={
                            error && !u.updating ? (
                                <span className='text-destructive'>{error}</span>
                            ) : undefined
                        }
                    >
                        {u.updating ? (
                            <Row
                                icon={
                                    <IconLoader2 className='size-5 animate-spin text-warning' />
                                }
                                label={`Устанавливаю ${u.installing ?? u.latest?.tag ?? ''}`}
                                hint='Панель перезапустится сама'
                            />
                        ) : u.available && u.latest ? (
                            <>
                                <Row
                                    label={`Доступна ${u.latest.tag}`}
                                    hint={
                                        u.skip === u.latest.tag
                                            ? u.failed_start === u.latest.tag
                                                ? 'Не запустилась и была откачена — ставится только вручную'
                                                : 'Вы выбрали другую версию — эта ставится только вручную'
                                            : undefined
                                    }
                                />
                                {u.latest.notes && (
                                    <Row
                                        label={
                                            showNotes
                                                ? 'Скрыть изменения'
                                                : 'Что нового'
                                        }
                                        tone='tint'
                                        onClick={() => setShowNotes(v => !v)}
                                    />
                                )}
                                {showNotes && u.latest.notes && (
                                    <pre className='max-h-72 overflow-auto whitespace-pre-wrap py-3 font-sans text-[13px] leading-snug text-muted-foreground'>
                                        {plainNotes(u.latest.notes)}
                                    </pre>
                                )}
                                <Row
                                    label={`Обновить до ${u.latest.tag}`}
                                    tone='tint'
                                    onClick={() => apply.mutate(undefined)}
                                    disabled={busy}
                                />
                            </>
                        ) : (
                            <Row
                                label={
                                    check.isPending || setChannel.isPending
                                        ? 'Проверяю…'
                                        : error
                                          ? 'Не удалось проверить обновления'
                                          : !lastCheck
                                            ? 'Проверка ещё не выполнялась'
                                            : !u.latest
                                              ? 'Подходящих версий пока нет'
                                              : 'Установлена последняя версия'
                                }
                                hint={
                                    lastCheck ? `Проверено ${lastCheck}` : undefined
                                }
                            />
                        )}
                        {u.failed_start && u.skip !== u.latest?.tag && (
                            <Row
                                label={`${u.failed_start} не запустилась`}
                                hint={`Панель вернулась на ${u.current}`}
                            />
                        )}
                        <Row
                            label={
                                check.isPending ? 'Проверяю…' : 'Проверить сейчас'
                            }
                            tone='tint'
                            onClick={() => check.mutate()}
                            disabled={busy}
                        />
                    </Group>

                    <Group
                        title='Другая версия'
                        footer='В списке только версии с подписью автора. Если поставить не самую новую, панель не заменит её сама — до выхода следующей.'
                    >
                        {versions.length === 0 ? (
                            <Row
                                label='Список пока пуст'
                                hint='Он появится после проверки обновлений.'
                            />
                        ) : (
                            <div className='flex flex-wrap items-center gap-2 py-3'>
                                <select
                                    aria-label='Версия панели'
                                    className={field}
                                    value={choice}
                                    disabled={busy}
                                    onChange={event =>
                                        setPicked(event.target.value)
                                    }
                                >
                                    {versions.map(v => (
                                        <option
                                            key={v.tag}
                                            value={v.tag}
                                            disabled={v.tag === u.current}
                                        >
                                            {v.tag}
                                            {v.prerelease ? ' · бета' : ''}
                                            {v.tag === u.current
                                                ? ' · установлена'
                                                : ''}
                                        </option>
                                    ))}
                                </select>
                                <button
                                    type='button'
                                    disabled={
                                        busy || !choice || choice === u.current
                                    }
                                    onClick={onInstall}
                                    className='min-h-11 cursor-pointer rounded-xl bg-fill px-4 text-[15px] text-tint disabled:cursor-default disabled:opacity-50'
                                >
                                    Установить
                                </button>
                            </div>
                        )}
                    </Group>
                </div>
            </div>

            {asking && (
                <ProtectionWarning
                    title={`Вернуться на ${asking}?`}
                    confirmLabel='Установить'
                    busy={apply.isPending}
                    error={apply.error?.message}
                    onCancel={() => {
                        if (!apply.isPending) setAsking('')
                    }}
                    onConfirm={() => apply.mutate(asking)}
                >
                    <p>
                        Это более старая версия панели.{' '}
                        <strong className='text-foreground'>
                            Она может не знать настроек и защит, которые
                            появились позже.
                        </strong>
                    </p>
                    <p>
                        Панель не станет сама возвращать {u.latest?.tag ?? 'новую версию'}.
                        Обновиться обратно можно здесь же в любой момент.
                    </p>
                </ProtectionWarning>
            )}
        </>
    )
}
