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
 * Response for POST /1/object/webhook/{pkiWebhookID}/regenerateApikey
 * @export
 * @interface WebhookRegenerateApikeyV1ResponseMPayload
 */
export interface WebhookRegenerateApikeyV1ResponseMPayload {
    /**
     * 
     * @type {WebhookResponseCompound}
     * @memberof WebhookRegenerateApikeyV1ResponseMPayload
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
 * A WebhookRegenerateApikeyV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookRegenerateApikeyV1ResponseMPayload
 */
export class DataObjectWebhookRegenerateApikeyV1ResponseMPayload {
   objWebhook:WebhookResponseCompound = new DataObjectWebhookResponseCompound()
}

/**
 * @export 
 * A WebhookRegenerateApikeyV1ResponseMPayload Validation Object
 * @class ValidationObjectWebhookRegenerateApikeyV1ResponseMPayload
 */
export class ValidationObjectWebhookRegenerateApikeyV1ResponseMPayload {
   objWebhook = new ValidationObjectWebhookResponseCompound()
} 

