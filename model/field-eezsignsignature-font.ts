/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The font of the signature. This can only be set if eEzsignsignatureType is **Name** or **Initials**
 * @export
 * @enum {string}
 */

export const FieldEEzsignsignatureFont = {
    Normal: 'Normal',
    Cursive: 'Cursive'
} as const;

export type FieldEEzsignsignatureFont = typeof FieldEEzsignsignatureFont[keyof typeof FieldEEzsignsignatureFont];



