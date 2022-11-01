/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomWebhooklogResponse } from './custom-webhooklog-response';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetHistoryV1ResponseMPayloadAllOf } from './webhook-get-history-v1-response-mpayload-all-of';

import { DefaultObject } from '../base'

/**
 * @type WebhookGetHistoryV1ResponseMPayload
 * Payload for GET /1/object/webhook/{pkiWebhookID}/getHistory
 * @export
 */
export type WebhookGetHistoryV1ResponseMPayload = WebhookGetHistoryV1ResponseMPayloadAllOf;


/**
 * @export 
 * A WebhookGetHistoryV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookGetHistoryV1ResponseMPayload
 */
export class DefaultObjectWebhookGetHistoryV1ResponseMPayload extends DefaultObject {
   a_objWebhooklog:Array<CustomWebhooklogResponse> = []
}


