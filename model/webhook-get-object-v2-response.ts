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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetObjectV2ResponseAllOf } from './webhook-get-object-v2-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetObjectV2ResponseMPayload } from './webhook-get-object-v2-response-mpayload';

/**
 * @type WebhookGetObjectV2Response
 * Response for GET /2/object/webhook/{pkiWebhookID}
 * @export
 */
export type WebhookGetObjectV2Response = CommonResponse & WebhookGetObjectV2ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectWebhookGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A WebhookGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetObjectV2Response
 */
export class DataObjectWebhookGetObjectV2Response {
   mPayload:WebhookGetObjectV2ResponseMPayload = new DataObjectWebhookGetObjectV2ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A WebhookGetObjectV2Response Validation Object
 * @class ValidationObjectWebhookGetObjectV2Response
 */
export class ValidationObjectWebhookGetObjectV2Response {
   mPayload = new ValidationObjectWebhookGetObjectV2ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


