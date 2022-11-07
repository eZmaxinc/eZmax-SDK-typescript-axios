/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface WebhookResponseCompoundAllOf
 */
export interface WebhookResponseCompoundAllOf {
    /**
     * The concatenated string to describe the Webhook event
     * @type {string}
     * @memberof WebhookResponseCompoundAllOf
     */
    'sWebhookEvent'?: string;
}
/**
 * A WebhookResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookResponseCompoundAllOf
 */
export class DefaultObjectWebhookResponseCompoundAllOf extends DefaultObject {
   sWebhookEvent?:string = undefined
}


