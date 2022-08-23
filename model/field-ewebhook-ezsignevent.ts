/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * This Ezsign Event. This property will be set only if the Module is \"Ezsign\"
 * @export
 * @enum {string}
 */

export const FieldEWebhookEzsignevent = {
    DocumentCompleted: 'DocumentCompleted',
    FolderCompleted: 'FolderCompleted'
} as const;

export type FieldEWebhookEzsignevent = typeof FieldEWebhookEzsignevent[keyof typeof FieldEWebhookEzsignevent];



