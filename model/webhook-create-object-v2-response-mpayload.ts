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


// May contain unused imports in some cases
// @ts-ignore
import { WebhookResponseCompound } from './webhook-response-compound';

/**
 * Payload for POST /2/object/webhook
 * @export
 * @interface WebhookCreateObjectV2ResponseMPayload
 */
export interface WebhookCreateObjectV2ResponseMPayload {
    /**
     * 
     * @type {Array<WebhookResponseCompound>}
     * @memberof WebhookCreateObjectV2ResponseMPayload
     */
    /*'a_objWebhook': Array<WebhookResponseCompound>;*/
    'a_objWebhook': Array<WebhookResponseCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A WebhookCreateObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookCreateObjectV2ResponseMPayload
 */
export class DataObjectWebhookCreateObjectV2ResponseMPayload {
   a_objWebhook:Array<WebhookResponseCompound> = []
}

/**
 * @export 
 * A WebhookCreateObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectWebhookCreateObjectV2ResponseMPayload
 */
export class ValidationObjectWebhookCreateObjectV2ResponseMPayload {
   a_objWebhook = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


