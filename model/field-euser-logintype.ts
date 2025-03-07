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
 * The type of authentication for the User
 * @export
 * @enum {string}
 */

export const FieldEUserLogintype = {
    Password: 'Password',
    PasswordPhone: 'PasswordPhone',
    PasswordQuestion: 'PasswordQuestion'
} as const;

export type FieldEUserLogintype = typeof FieldEUserLogintype[keyof typeof FieldEUserLogintype];



