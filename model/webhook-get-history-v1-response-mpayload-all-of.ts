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
import { CustomWebhooklogResponse } from './custom-webhooklog-response';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface WebhookGetHistoryV1ResponseMPayloadAllOf
 */
export interface WebhookGetHistoryV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<CustomWebhooklogResponse>}
     * @memberof WebhookGetHistoryV1ResponseMPayloadAllOf
     */
    'a_objWebhooklog': Array<CustomWebhooklogResponse>;
}
/**
 * A WebhookGetHistoryV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookGetHistoryV1ResponseMPayloadAllOf
 */
export class DefaultObjectWebhookGetHistoryV1ResponseMPayloadAllOf extends DefaultObject {
   a_objWebhooklog:Array<CustomWebhooklogResponse> = []
}


