/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.9
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The language of the returned content.  1. **\\*** (or header not defined) Default language 2. **en** English 2. **fr** French  
 * @export
 * @enum {string}
 */

export const HeaderAcceptLanguage = {
    Star: '*',
    en: 'en',
    fr: 'fr'
} as const;

export type HeaderAcceptLanguage = typeof HeaderAcceptLanguage[keyof typeof HeaderAcceptLanguage];



