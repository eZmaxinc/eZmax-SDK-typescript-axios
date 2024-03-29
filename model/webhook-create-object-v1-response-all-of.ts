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
import { WebhookCreateObjectV1ResponseMPayload } from './webhook-create-object-v1-response-mpayload';

/**
 * 
 * @export
 * @interface WebhookCreateObjectV1ResponseAllOf
 */
export interface WebhookCreateObjectV1ResponseAllOf {
    /**
     * 
     * @type {WebhookCreateObjectV1ResponseMPayload}
     * @memberof WebhookCreateObjectV1ResponseAllOf
     */
    'mPayload': WebhookCreateObjectV1ResponseMPayload;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectWebhookCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A WebhookCreateObjectV1ResponseAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookCreateObjectV1ResponseAllOf
 */
export class DataObjectWebhookCreateObjectV1ResponseAllOf {
   mPayload:WebhookCreateObjectV1ResponseMPayload = new DataObjectWebhookCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A WebhookCreateObjectV1ResponseAllOf Validation Object
 * @class ValidationObjectWebhookCreateObjectV1ResponseAllOf
 */
export class ValidationObjectWebhookCreateObjectV1ResponseAllOf {
   mPayload = new ValidationObjectWebhookCreateObjectV1ResponseMPayload()
} 


