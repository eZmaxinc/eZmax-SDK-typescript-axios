/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Signer requirement of the Ezsignformfieldgroup. **All** means anyone can fill it, **One** means a specific person must fill it.
 * @export
 * @enum {string}
 */

export const FieldEEzsignformfieldgroupSignerrequirement = {
    All: 'All',
    One: 'One'
} as const;

export type FieldEEzsignformfieldgroupSignerrequirement = typeof FieldEEzsignformfieldgroupSignerrequirement[keyof typeof FieldEEzsignformfieldgroupSignerrequirement];



