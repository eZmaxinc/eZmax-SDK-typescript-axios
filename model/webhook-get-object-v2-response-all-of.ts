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


// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetObjectV2ResponseMPayload } from './webhook-get-object-v2-response-mpayload';

/**
 * 
 * @export
 * @interface WebhookGetObjectV2ResponseAllOf
 */
export interface WebhookGetObjectV2ResponseAllOf {
    /**
     * 
     * @type {WebhookGetObjectV2ResponseMPayload}
     * @memberof WebhookGetObjectV2ResponseAllOf
     */
    'mPayload': WebhookGetObjectV2ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectWebhookGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A WebhookGetObjectV2ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetObjectV2ResponseAllOf
 */
export class DataObjectWebhookGetObjectV2ResponseAllOf {
   mPayload:WebhookGetObjectV2ResponseMPayload = new DataObjectWebhookGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A WebhookGetObjectV2ResponseAllOf Validation Object
 * @class ValidationObjectWebhookGetObjectV2ResponseAllOf
 */
export class ValidationObjectWebhookGetObjectV2ResponseAllOf {
   mPayload = new ValidationObjectWebhookGetObjectV2ResponseMPayload()
} 


