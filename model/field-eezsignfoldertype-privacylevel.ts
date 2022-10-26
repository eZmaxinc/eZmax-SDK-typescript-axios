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
 * The Privacy level of the Ezsignfolder type.  * **User** is for personal folders use and cannot be shared * **Usergroup** is for shared folders and complex permission can be configured to control access
 * @export
 * @enum {string}
 */

export const FieldEEzsignfoldertypePrivacylevel = {
    User: 'User',
    Usergroup: 'Usergroup'
} as const;

export type FieldEEzsignfoldertypePrivacylevel = typeof FieldEEzsignfoldertypePrivacylevel[keyof typeof FieldEEzsignfoldertypePrivacylevel];



