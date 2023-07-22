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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetListV1ResponseAllOf } from './webhook-get-list-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { WebhookGetListV1ResponseMPayload } from './webhook-get-list-v1-response-mpayload';

/**
 * @type WebhookGetListV1Response
 * Response for GET /1/object/webhook/getList
 * @export
 */
export type WebhookGetListV1Response = CommonResponseGetList & WebhookGetListV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectWebhookGetListV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectWebhookGetListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A WebhookGetListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetListV1Response
 */
export class DataObjectWebhookGetListV1Response {
    mPayload:WebhookGetListV1ResponseMPayload = new DataObjectWebhookGetListV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayloadGetList = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A WebhookGetListV1Response Validation Object
 * @class ValidationObjectWebhookGetListV1Response
 */
export class ValidationObjectWebhookGetListV1Response {
   mPayload = new ValidationObjectWebhookGetListV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


