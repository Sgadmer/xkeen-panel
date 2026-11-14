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
    return serverPathLabel(location.country_path) || countryLabel(location.exit_country || location.entry_country)
}
