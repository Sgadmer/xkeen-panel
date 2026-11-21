import { useRef, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Group, PageTitle, Row } from '@/components/ios'
import { ProtectionWarning } from '@/components/protectionWarning'
import { ApiError, api } from '@/lib/api'
import { saveTextFile } from '@/lib/journal'

type Section = { id: string; title: string; changes: string[]; skipped?: string[]; weakens?: boolean }
type Preview = { sections: Section[]; created?: string; panel_version?: string }
type Result = { id: string; title: string; done: string[]; failed?: string[] }

const MAX_FILE = 1024 * 1024

// The owner's settings as one file: for another router or after a reinstall.
export function TransferPage() {
    const client = useQueryClient()
    const input = useRef<HTMLInputElement>(null)
    const [file, setFile] = useState<unknown>(null)
    const [fileName, setFileName] = useState('')
    const [problem, setProblem] = useState('')
    const [chosen, setChosen] = useState<string[]>([])
    const [confirming, setConfirming] = useState(false)
    const [results, setResults] = useState<Result[] | null>(null)

    const download = useMutation({
        mutationFn: () => api.get<Record<string, unknown>>('/api/settings/export'),
        onSuccess: data => saveTextFile(`xkeen-panel-settings-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(data, null, 2) + '\n', 'application/json'),
    })
    const preview = useMutation({
        mutationFn: (body: unknown) => api.post<Preview>('/api/settings/import/preview', body),
        onSuccess: data => setChosen(data.sections.filter(section => !section.weakens && section.changes.length > 0).map(section => section.id)),
    })
    const apply = useMutation({
        mutationFn: () => api.post<{ results: Result[] }>('/api/settings/import/apply', { file, sections: chosen }),
        onSuccess: data => {
            setResults(data.results)
            setConfirming(false)
            void client.invalidateQueries()
        },
        onError: error => {
            // The panel reports what it managed to do before it stopped.
            const partial = error instanceof ApiError ? (error.body as { results?: Result[] } | undefined)?.results : undefined
            if (partial?.length) setResults(partial)
            setConfirming(false)
            void client.invalidateQueries()
        },
    })

    const open = async (picked: File | undefined) => {
        setProblem(''); setResults(null); setFile(null); setFileName(''); preview.reset(); apply.reset()
        if (!picked) return
        if (picked.size > MAX_FILE) { setProblem('Файл слишком большой для файла настроек.'); return }
        try {
            const parsed: unknown = JSON.parse(await picked.text())
            setFile(parsed)
            setFileName(picked.name)
            preview.mutate(parsed)
        } catch {
            setProblem('Файл не читается: это не файл настроек панели.')
        }
    }
    const toggle = (id: string) => setChosen(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id])
    const sections = preview.data?.sections ?? []
    const safe = sections.filter(section => !section.weakens)
    const weak = sections.filter(section => section.weakens)
    const weakChosen = weak.some(section => chosen.includes(section.id))
    const nothing = !!preview.data && sections.every(section => section.changes.length === 0)

    const list = (section: Section) => <div key={section.id} className='py-3'>
        <label className='flex cursor-pointer items-start gap-3'>
            <input type='checkbox' checked={chosen.includes(section.id)} disabled={apply.isPending || section.changes.length === 0} onChange={() => toggle(section.id)}
                className='mt-1 size-5 shrink-0 accent-indigo-500' />
            <span className='min-w-0 flex-1'>
                <span className={'block text-[17px] ' + (section.weakens ? 'text-warning' : '')}>{section.title}</span>
                {section.changes.map(line => <span key={line} className='mt-1 block break-words text-[14px] text-muted-foreground'>{line}</span>)}
                {section.changes.length === 0 && <span className='mt-1 block text-[14px] text-muted-foreground'>Применять нечего.</span>}
            </span>
        </label>
        {section.skipped?.map(line => <p key={line} className='mt-2 break-words pl-8 text-[13px] text-muted-foreground'>Пропущено · {line}</p>)}
    </div>

    return <>
        <PageTitle title='Перенос настроек' subtitle='Сохранить настройки в файл или загрузить их из файла' back={{ to: '/settings', label: 'Настройки' }} />
        <div className='grid grid-cols-1 gap-5 lg:grid-cols-2 lg:items-start'>
            <Group title='Сохранить' footer='В файле — маршруты карточек, kill switch, исключения, свои сервисы, DNS, автоматика и шаблоны журнала. Пароля, ссылок подписок, ключей и адресов серверов в нём нет: серверы названы только именами.'>
                <Row label={download.isPending ? 'Готовим файл…' : 'Скачать файл настроек'} tone='tint' disabled={download.isPending} onClick={() => download.mutate()} />
                {download.error && <p role='alert' className='py-3 text-sm text-destructive'>{download.error.message}</p>}
            </Group>

            <div className='flex min-w-0 flex-col gap-5'>
                <Group title='Загрузить' footer='Сначала панель покажет, что изменится. Ничего не применяется, пока вы не нажмёте «Применить выбранное». Подписки нужно добавить до загрузки: серверы из файла ищутся по именам.'>
                    <Row label={fileName ? 'Выбрать другой файл' : 'Выбрать файл настроек'} hint={fileName || undefined} tone='tint' disabled={apply.isPending} onClick={() => input.current?.click()} />
                    <input ref={input} type='file' accept='application/json,.json' className='hidden' onChange={event => { void open(event.target.files?.[0]); event.target.value = '' }} />
                    {preview.isPending && <Row label='Сравниваем с настройками роутера…' />}
                    {(problem || preview.error) && <p role='alert' className='py-3 text-sm text-destructive'>{problem || preview.error?.message}</p>}
                </Group>

                {preview.data && !results && <>
                    {nothing && <Group><Row label='Изменений нет' hint='Настройки роутера уже совпадают с файлом, либо применить их здесь нельзя.' /></Group>}
                    {safe.length > 0 && <Group title='Что изменится'>{safe.map(list)}</Group>}
                    {weak.length > 0 && <Group title='Ослабляет защиту' footer='Эти изменения не выбраны заранее. Отметьте их, только если хотите того же, что было на прежнем роутере.'>{weak.map(list)}</Group>}
                    {!nothing && <Group>
                        <Row label={apply.isPending ? 'Применяем…' : 'Применить выбранное'} tone='tint' disabled={apply.isPending || chosen.length === 0}
                            onClick={() => { apply.reset(); if (weakChosen) setConfirming(true); else apply.mutate() }} />
                    </Group>}
                </>}

                {results && <Group title='Что сделано' footer='Каждое изменение прошло ту же проверку, что и сделанное вручную. Непринятое изменение роутер оставил как было.'>
                    {results.length === 0 && <Row label='Изменений не потребовалось' />}
                    {results.map(result => <div key={result.id} className='py-3'>
                        <p className='text-[17px]'>{result.title}</p>
                        {result.done.map(line => <p key={line} className='mt-1 break-words text-[14px] text-muted-foreground'>{line}</p>)}
                        {result.failed?.map(line => <p key={line} role='alert' className='mt-1 break-words text-[14px] text-destructive'>Не применено · {line}</p>)}
                    </div>)}
                </Group>}
                {apply.error && <p role='alert' className='px-4 text-sm text-destructive'>{apply.error.message}</p>}
            </div>
        </div>

        {confirming && <ProtectionWarning title='Применить настройки, которые ослабляют защиту?' confirmLabel='Применить' busy={apply.isPending} error={apply.error?.message}
            onCancel={() => { if (!apply.isPending) setConfirming(false) }} onConfirm={() => apply.mutate()}>
            <p>Среди выбранного есть изменения, после которых часть трафика сможет выйти <strong className='text-foreground'>напрямую</strong>, с домашнего адреса:</p>
            <ul className='list-disc space-y-1 pl-5 text-muted-foreground'>
                {weak.filter(section => chosen.includes(section.id)).flatMap(section => section.changes).slice(0, 8).map(line => <li key={line} className='break-words'>{line}</li>)}
            </ul>
        </ProtectionWarning>}
    </>
}
