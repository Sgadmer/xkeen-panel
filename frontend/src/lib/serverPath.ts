import { countryLabel, countryName, serverCountry } from '@/lib/format'

export type ServerCountries = {
    country?: string
    country_override?: string
    declared_country_path?: string[]
}

export function serverPathDetail(location?: ServerCountries, full = true, visibleName?: string) {
    const country = serverCountry(location)
    if (!country) return ''
    const path = location?.declared_country_path
    if (full && path && path.length > 1 && path.at(-1) === country && path.every(code => /^[A-Z]{2}$/.test(code))) {
        return path.map(countryLabel).join(' → ')
    }
    const title = visibleName?.replace(/\p{Regional_Indicator}{2}\uFE0F?/gu, '').trim()
    if (title?.localeCompare(countryName(country), 'ru', {sensitivity: 'base'}) === 0) return ''
    return countryLabel(country)
}
