/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The Type of Ezsigntemplate
 * @export
 * @enum {string}
 */

export const FieldEEzsigntemplateType = {
    User: 'User',
    Usergroup: 'Usergroup',
    Company: 'Company'
} as const;

export type FieldEEzsigntemplateType = typeof FieldEEzsigntemplateType[keyof typeof FieldEEzsigntemplateType];



