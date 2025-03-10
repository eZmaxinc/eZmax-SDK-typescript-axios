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
 * This Management Event. This property will be set only if the Module is \"Management\".
 * @export
 * @enum {string}
 */

export const FieldEWebhookManagementevent = {
    UserCreated: 'UserCreated',
    UserstagedCreated: 'UserstagedCreated'
} as const;

export type FieldEWebhookManagementevent = typeof FieldEWebhookManagementevent[keyof typeof FieldEWebhookManagementevent];



