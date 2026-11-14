import { countryLabel } from '@/lib/format'

export type ServerCountries = {
    country_path?: string[]
    entry_country?: string
    exit_country?: string
}

export function serverPathLabel(path?: string[]) {
    return (path ?? []).map(code => countryLabel(code)).filter(Boolean).join(' → ')
}

export function serverPathDetail(location?: ServerCountries, full = true) {
    if (!location) return ''
    if (!full) return countryLabel(location.exit_country)
    const path = serverPathLabel(location.country_path)
    if (path) return path
    if (location.exit_country) return 'Выход · ' + countryLabel(location.exit_country)
    if (location.entry_country) return 'Вход · ' + countryLabel(location.entry_country)
    return ''
}
