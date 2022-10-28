/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { WebhookListElement } from './webhook-list-element';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface WebhookGetListV1ResponseMPayloadAllOf
 */
export interface WebhookGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<WebhookListElement>}
     * @memberof WebhookGetListV1ResponseMPayloadAllOf
     */
    'a_objWebhook': Array<WebhookListElement>;
}
/**
 * A WebhookGetListV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectWebhookGetListV1ResponseMPayloadAllOf
 */
export class DefaultObjectWebhookGetListV1ResponseMPayloadAllOf extends DefaultObject {
   a_objWebhook:Array<WebhookListElement> = []
}


