/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type WebhookGetHistoryV1Response
 * Response for GET /1/object/webhook/{pkiWebhookID}/getHistory
 * @export
 */
/*export type WebhookGetHistoryV1Response = CommonResponse;*/
export interface WebhookGetHistoryV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof WebhookGetHistoryV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof WebhookGetHistoryV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * Payload for GET /1/object/webhook/{pkiWebhookID}/getHistory
     * @type {object}
     * @memberof WebhookGetHistoryV1Response
     */
    mPayload:object 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectobject } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectobject } from './'

/**
 * @export 
 * A WebhookGetHistoryV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookGetHistoryV1Response
 */
export class DataObjectWebhookGetHistoryV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:object = new DataObjectobject()
}

/**
 * @export 
 * A WebhookGetHistoryV1Response Validation Object
 * @class ValidationObjectWebhookGetHistoryV1Response
 */
export class ValidationObjectWebhookGetHistoryV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectobject()
} 


