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
import { AttemptResponseCompound } from './attempt-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { CommonWebhook } from './common-webhook';
// May contain unused imports in some cases
// @ts-ignore
import { CustomWebhookResponse } from './custom-webhook-response';
// May contain unused imports in some cases
// @ts-ignore
import { UserstagedResponseCompound } from './userstaged-response-compound';

/**
 * @type WebhookUserstagedUserstagedCreated
 * This is the base Webhook object
 * @export
 */
export type WebhookUserstagedUserstagedCreated = CommonWebhook;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomWebhookResponse } from './'
// @ts-ignore
import { DataObjectUserstagedResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCustomWebhookResponse } from './'
// @ts-ignore
import { ValidationObjectUserstagedResponseCompound } from './'

/**
 * @export 
 * A WebhookUserstagedUserstagedCreated Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookUserstagedUserstagedCreated
 */
export class DataObjectWebhookUserstagedUserstagedCreated {
    objWebhook:CustomWebhookResponse = new DataObjectCustomWebhookResponse()
    a_objAttempt:Array<AttemptResponseCompound> = []
    objUserstaged:UserstagedResponseCompound = new DataObjectUserstagedResponseCompound()
}

/**
 * @export 
 * A WebhookUserstagedUserstagedCreated Validation Object
 * @class ValidationObjectWebhookUserstagedUserstagedCreated
 */
export class ValidationObjectWebhookUserstagedUserstagedCreated {
   objWebhook = new ValidationObjectCustomWebhookResponse()
   a_objAttempt = {
      type: 'array',
      required: true
   }
   objUserstaged = new ValidationObjectUserstagedResponseCompound()
} 


