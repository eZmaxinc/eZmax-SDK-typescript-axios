/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.12
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetHistoryV1ResponseMPayload } from './webhook-get-history-v1-response-mpayload';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface WebhookGetHistoryV1ResponseAllOf
 */
export interface WebhookGetHistoryV1ResponseAllOf {
    /**
     * 
     * @type {WebhookGetHistoryV1ResponseMPayload}
     * @memberof WebhookGetHistoryV1ResponseAllOf
     */
    'mPayload': WebhookGetHistoryV1ResponseMPayload;
}
/**
 * A WebhookGetHistoryV1ResponseAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookGetHistoryV1ResponseAllOf
 */
export class DefaultObjectWebhookGetHistoryV1ResponseAllOf extends DefaultObject {
   mPayload:Partial<WebhookGetHistoryV1ResponseMPayload> = {}
}


