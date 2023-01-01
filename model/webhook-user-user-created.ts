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
import { AttemptResponseCompound } from './attempt-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommonWebhook } from './common-webhook';
// May contain unused imports in some cases
// @ts-ignore
import { CustomWebhookResponse } from './custom-webhook-response';
// May contain unused imports in some cases
// @ts-ignore
import { UserResponseCompound } from './user-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookUserUserCreatedAllOf } from './webhook-user-user-created-all-of';

import { DefaultObject } from '../base'

/**
 * @type WebhookUserUserCreated
 * This is the base Webhook object
 * @export
 */
export type WebhookUserUserCreated = CommonWebhook & WebhookUserUserCreatedAllOf;


/**
 * @export 
 * A WebhookUserUserCreated Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectWebhookUserUserCreated
 */
export class DefaultObjectWebhookUserUserCreated extends DefaultObject {
   objUser:Partial<UserResponseCompound> = {}
   objWebhook:Partial<CustomWebhookResponse> = {}
   a_objAttempt:Array<AttemptResponseCompound> = []
}


