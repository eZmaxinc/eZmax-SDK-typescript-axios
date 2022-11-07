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


// May contain unused imports in some cases
// @ts-ignore
import { WebhookResponseCompound } from './webhook-response-compound';

import { DefaultObject } from '../base'

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
 * A WebhookGetObjectV2ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookGetObjectV2ResponseMPayload
 */
export class DefaultObjectWebhookGetObjectV2ResponseMPayload extends DefaultObject {
   objWebhook:Partial<WebhookResponseCompound> = {}
}


