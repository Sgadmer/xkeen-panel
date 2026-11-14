import { countryLabel, scopeLabel, withCountryFlag } from '@/lib/format'
import type { AutoScope } from '@/types'

export interface ServiceTarget {
    id: string
    name: string
    kind: 'server' | 'profile' | 'pool'
    country?: string
    sources?: string[]
}

interface RouteOption {
    id: string
    label: string
    kind: ServiceTarget['kind']
}

interface RouteGroup {
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

export function serviceRouteOptions(targets: ServiceTarget[], scopes: AutoScope[] = [], avoided: string[] = []) {
    const scopeById = new Map(scopes.map(scope => [scope.id, scope]))
    const groups = new Map<string, RouteGroup>()
    for (const target of targets) {
        let key: string, title: string, order: number, label: string
        if (target.kind === 'pool') {
            const scope = scopeById.get(target.id)
            const kind = scope?.kind ?? (target.country ? 'country' : 'pool')
            key = kind
            title = poolGroups[kind].title
            order = poolGroups[kind].order
            const name = scope ? scopeLabel(scope) : target.country ? countryLabel(target.country) : target.name
            label = scope ? name + ' · ' + scope.member_count : name
        } else {
            const sources = [...new Set(target.sources?.map(s => s.trim()).filter(Boolean))].sort(collator.compare)
            key = 'providers:' + JSON.stringify(sources)
            title = sources.length > 1 ? 'Общие · ' + sources.join(' + ') : sources[0] || 'Без провайдера'
            order = sources.length > 1 ? 5 : sources.length ? 4 : 6
            label = withCountryFlag(target.name, target.country)
            if (target.kind === 'profile') label = 'Режим провайдера · ' + label
            if (target.kind === 'server' && target.country && avoided.includes(target.country)) label += ' · только вручную'
        }
        let group = groups.get(key)
        if (!group) {
            group = { key, title, order, targets: [] }
            groups.set(key, group)
        }
        group.targets.push({ id: target.id, label, kind: target.kind })
    }
    for (const group of groups.values()) {
        if (group.targets[0].kind !== 'pool') {
            group.targets.sort((a, b) => Number(b.kind === 'profile') - Number(a.kind === 'profile') || collator.compare(a.label, b.label))
        }
        const counts = new Map<string, number>()
        for (const item of group.targets) counts.set(item.label, (counts.get(item.label) ?? 0) + 1)
        for (const item of group.targets) if (counts.get(item.label)! > 1) item.label += ' · ' + item.id.slice(0, 8)
    }
    return [...groups.values()].sort((a, b) => a.order - b.order || collator.compare(a.title, b.title))
}
