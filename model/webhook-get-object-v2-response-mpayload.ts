/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
 * Payload for GET /2/object/webhook/{pkiWebhookID}
 * @export
 * @interface WebhookGetObjectV2ResponseMPayload
 */
export interface WebhookGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {WebhookResponseCompound}
     * @memberof WebhookGetObjectV2ResponseMPayload
     */
    'objWebhook': WebhookResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookResponseCompound } from './'
// @ts-ignore
import { ValidationObjectWebhookResponseCompound } from './'

/**
 * @export 
 * A WebhookGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetObjectV2ResponseMPayload
 */
export class DataObjectWebhookGetObjectV2ResponseMPayload {
   objWebhook:WebhookResponseCompound = new DataObjectWebhookResponseCompound()
}

/**
 * @export 
 * A WebhookGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectWebhookGetObjectV2ResponseMPayload
 */
export class ValidationObjectWebhookGetObjectV2ResponseMPayload {
   objWebhook = new ValidationObjectWebhookResponseCompound()
} 


