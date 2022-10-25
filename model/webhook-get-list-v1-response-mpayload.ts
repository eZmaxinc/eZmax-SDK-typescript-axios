/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonGetListV1ResponseMPayload } from './common-get-list-v1-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetListV1ResponseMPayloadAllOf } from './webhook-get-list-v1-response-mpayload-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookListElement } from './webhook-list-element';

import { DefaultObject } from '../base'

/**
 * @type WebhookGetListV1ResponseMPayload
 * Payload for GET /1/object/webhook/getList
 * @export
 */
export type WebhookGetListV1ResponseMPayload = CommonGetListV1ResponseMPayload & WebhookGetListV1ResponseMPayloadAllOf;


/**
 * @export 
 * A WebhookGetListV1ResponseMPayload Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookGetListV1ResponseMPayload
 */
export class DefaultObjectWebhookGetListV1ResponseMPayload extends DefaultObject {
   a_objWebhook:Array<WebhookListElement> = []
   iRowReturned:number = 0
   iRowFiltered:number = 0
}

