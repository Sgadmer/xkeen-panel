import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Group } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { Sheet } from '@/components/sheet'
import { api } from '@/lib/api'

// A card the owner describes: a name and the addresses that belong to it.
export type CustomDraft = { id?: string; name: string; addresses: string }

type Saved = { services: { id: string; name: string; addresses: string[] }[]; limit: number }

const field = 'mt-1.5 w-full rounded-xl border border-white/10 bg-fill px-3 py-2 text-[16px] outline-none focus:border-tint disabled:opacity-50'

// What the card shows as its domains, turned back into lines for editing.
export function customDraft(service: { id: string; name: string; domains?: string[]; networks?: string[] }): CustomDraft {
    const lines = [...(service.domains ?? []).map(domain => domain.replace(/^domain:/, '')), ...(service.networks ?? [])]
    return { id: service.id, name: service.name, addresses: lines.join('\n') }
}

function useRefresh() {
    const client = useQueryClient()
    return () => Promise.all([['service-routes'], ['kill-switch'], ['protection-routes'], ['diagnostics']].map(queryKey => client.invalidateQueries({ queryKey })))
}

export function CustomServiceSheet({ draft, onClose, onSaved }: { draft: CustomDraft | null; onClose: () => void; onSaved: (message: string) => void }) {
    const refresh = useRefresh()
    const [name, setName] = useState('')
    const [addresses, setAddresses] = useState('')
    const save = useMutation({
        mutationFn: () => {
            const body = { name, addresses: addresses.split(/\r?\n/).map(line => line.trim()).filter(Boolean) }
            return draft?.id ? api.put<Saved>('/api/custom-services/' + encodeURIComponent(draft.id), body) : api.post<Saved>('/api/custom-services', body)
        },
        onSuccess: async () => {
            await refresh()
            onSaved(draft?.id ? 'Сервис изменён · ' + name.trim() : 'Сервис добавлен · ' + name.trim() + '. Маршрут — автовыбор; его можно сменить в карточке.')
        },
    })
    const { reset } = save
    useEffect(() => {
        if (!draft) return
        setName(draft.name)
        setAddresses(draft.addresses)
        reset()
    }, [draft, reset])
    const ready = name.trim().length > 0 && addresses.trim().length > 0 && !save.isPending

    return <Sheet open={!!draft} onClose={() => { if (!save.isPending) onClose() }} title={draft?.id ? 'Изменить сервис' : 'Свой сервис'}
        done={{ label: save.isPending ? 'Проверяем…' : 'Сохранить', disabled: !ready, onClick: () => save.mutate() }}>
        <div className='flex flex-col gap-5'>
            <Group footer='Так карточка будет называться в списке сервисов и в журнале.'>
                <label className='block py-3 text-[15px] font-medium'>Название
                    <input type='text' value={name} maxLength={40} disabled={save.isPending} onChange={event => setName(event.target.value)}
                        placeholder='Например, Рабочий портал' className={field} />
                </label>
            </Group>
            <Group footer='По одному адресу в строке. Домен включает свои поддомены; full: перед именем — только это точное имя. Можно вставить ссылку, IP-адрес или подсеть.'>
                <label className='block py-3 text-[15px] font-medium'>Адреса сервиса
                    <textarea value={addresses} rows={7} disabled={save.isPending} spellCheck={false} autoCapitalize='none'
                        onChange={event => setAddresses(event.target.value)} placeholder={'portal.example.com\nfull:files.example.net\n203.0.113.0/24'}
                        className={field + ' min-h-40 resize-y font-mono text-[15px]'} />
                </label>
            </Group>
            <p className='px-4 text-[13px] leading-relaxed text-muted-foreground'>
                Адрес может принадлежать только одной карточке. Если он уже есть у другой, в том числе у готовой, панель назовёт её и не сохранит изменения.
                {draft?.id ? ' Соединения этой карточки переподключатся.' : ' Новая карточка сразу идёт через VPN с включённым kill switch.'}
            </p>
            {save.error && <p role='alert' className='px-4 text-sm text-destructive'>{save.error.message}</p>}
        </div>
    </Sheet>
}

export function DeleteCustomService({ service, onClose, onDeleted }: { service: { id: string; name: string } | null; onClose: () => void; onDeleted: (message: string) => void }) {
    const refresh = useRefresh()
    const remove = useMutation({
        mutationFn: (id: string) => api.del<Saved>('/api/custom-services/' + encodeURIComponent(id)),
        onSuccess: async () => {
            await refresh()
            onDeleted('Сервис удалён · ' + (service?.name ?? ''))
        },
    })
    if (!service) return null
    return <ProtectionWarning title='Удалить свой сервис?' confirmLabel='Удалить сервис' delay={0}
        busy={remove.isPending} error={remove.error?.message}
        onCancel={() => { if (!remove.isPending) { remove.reset(); onClose() } }} onConfirm={() => remove.mutate(service.id)}>
        <p>Карточка <strong className='text-foreground'>{service.name}</strong> исчезнет. Её адреса пойдут по общим правилам: в защищённом режиме — через основной VPN, в режиме «по списку блокировок» — напрямую, если их нет в списке.</p>
    </ProtectionWarning>
}
