import { countryLabel, scopeLabel, unavailableCountryReason } from '@/lib/format'
import { serverPathDetail, type ServerCountries } from '@/lib/serverPath'
import type { AutoScope } from '@/types'

export interface ServiceTarget extends ServerCountries {
    id: string
    name: string
    kind: 'server' | 'profile' | 'pool'
    country?: string
    sources?: string[]
}

interface RouteOption {
    id: string
    label: string
    detail?: string
    disabled?: boolean
    kind: ServiceTarget['kind']
}

export interface RouteGroup {
    key: string
    title: string
    order: number
    targets: RouteOption[]
}

const poolGroups = {
    all: { title: 'Автовыбор', order: 0 },
    country: { title: 'Пулы стран', order: 1 },
    custom: { title: 'Мультипулы', order: 2 },
    pool: { title: 'Пулы', order: 3 },
}

const collator = new Intl.Collator('ru', { numeric: true })

export function serviceRouteOptions(targets: ServiceTarget[], scopes: AutoScope[] = [], avoided: string[] = [], defaultServiceTarget?: string, fullPath = true) {
    const scopeById = new Map(scopes.map(scope => [scope.id, scope]))
    const groups = new Map<string, RouteGroup>()
    for (const target of targets) {
        let key: string
        let title: string
        let order: number
        let label = target.name
        let detail: string | undefined
        let disabled = false
        if (target.kind === 'pool') {
            const scope = scopeById.get(target.id)
            const kind = target.id === defaultServiceTarget ? 'all' : scope?.kind ?? (target.country ? 'country' : 'pool')
            key = kind
            title = poolGroups[kind].title
            order = poolGroups[kind].order
            if (scope) {
                label = scopeLabel(scope)
                disabled = kind === 'country' && scope.member_count === 0
                detail = disabled ? unavailableCountryReason(scope, avoided) : 'Серверов: ' + scope.member_count
            } else if (target.country) {
                label = countryLabel(target.country)
            }
        } else {
            const sources = [...new Set(target.sources?.filter(s => s.trim()))].sort(collator.compare)
            key = 'providers:' + JSON.stringify(sources)
            title = sources.length > 1 ? 'Общие · ' + sources.join(' + ') : sources[0] || 'Без провайдера'
            order = sources.length > 1 ? 5 : sources.length ? 4 : 6
            if (target.kind === 'profile') detail = 'Режим провайдера'
            if (target.kind === 'server') {
                detail = [serverPathDetail(target, fullPath), target.country && avoided.includes(target.country) && 'Только вручную'].filter(Boolean).join(' · ') || undefined
            }
        }
        let group = groups.get(key)
        if (!group) {
            group = { key, title, order, targets: [] }
            groups.set(key, group)
        }
        group.targets.push({ id: target.id, label, detail, kind: target.kind, disabled })
    }
    for (const group of groups.values()) {
        if (group.targets[0].kind !== 'pool') {
            group.targets.sort((a, b) => Number(b.kind === 'profile') - Number(a.kind === 'profile') || collator.compare(a.label, b.label))
        }
        const counts = new Map<string, number>()
        for (const item of group.targets) counts.set(item.label, (counts.get(item.label) ?? 0) + 1)
        for (const item of group.targets) {
            if ((counts.get(item.label) ?? 0) > 1) {
                item.detail = [item.detail, item.id.slice(0, 8)].filter(Boolean).join(' · ')
            }
        }
    }
    return [...groups.values()].sort((a, b) => a.order - b.order || collator.compare(a.title, b.title))
}
