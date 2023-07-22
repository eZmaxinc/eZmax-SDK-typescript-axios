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
 * The module for the Webhook
 * @export
 * @enum {string}
 */

export const FieldEWebhookModule = {
    Ezsign: 'Ezsign',
    Management: 'Management'
} as const;

export type FieldEWebhookModule = typeof FieldEWebhookModule[keyof typeof FieldEWebhookModule];



