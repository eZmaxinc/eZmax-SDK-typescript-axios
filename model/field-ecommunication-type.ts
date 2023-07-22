/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * The type of the Communication
 * @export
 * @enum {string}
 */

export const FieldECommunicationType = {
    Email: 'Email',
    Fax: 'Fax',
    Sms: 'Sms'
} as const;

export type FieldECommunicationType = typeof FieldECommunicationType[keyof typeof FieldECommunicationType];



