/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Type of Ezsigntemplate  **Usergroup** is now deprecated and replace with **Ezsignfoldertype**
 * @export
 * @enum {string}
 */

export const FieldEEzsigntemplateType = {
    User: 'User',
    Usergroup: 'Usergroup',
    Company: 'Company',
    Ezsignfoldertype: 'Ezsignfoldertype'
} as const;

export type FieldEEzsigntemplateType = typeof FieldEEzsigntemplateType[keyof typeof FieldEEzsigntemplateType];



