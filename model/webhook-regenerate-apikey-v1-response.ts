/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
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
import { WebhookRegenerateApikeyV1ResponseMPayload } from './webhook-regenerate-apikey-v1-response-mpayload';

/**
 * @type WebhookRegenerateApikeyV1Response
 * Response for POST /1/object/webhook/{pkiWebhookID}/regenerateApikey
 * @export
 */
/** export type WebhookRegenerateApikeyV1Response = CommonResponse; */
export interface WebhookRegenerateApikeyV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof WebhookRegenerateApikeyV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof WebhookRegenerateApikeyV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {WebhookRegenerateApikeyV1ResponseMPayload}
     * @memberof WebhookRegenerateApikeyV1Response
     */
    mPayload:WebhookRegenerateApikeyV1ResponseMPayload 
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
import { DataObjectWebhookRegenerateApikeyV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectWebhookRegenerateApikeyV1ResponseMPayload } from './'

/**
 * @export 
 * A WebhookRegenerateApikeyV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookRegenerateApikeyV1Response
 */
export class DataObjectWebhookRegenerateApikeyV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:WebhookRegenerateApikeyV1ResponseMPayload = new DataObjectWebhookRegenerateApikeyV1ResponseMPayload()
}

/**
 * @export 
 * A WebhookRegenerateApikeyV1Response Validation Object
 * @class ValidationObjectWebhookRegenerateApikeyV1Response
 */
export class ValidationObjectWebhookRegenerateApikeyV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectWebhookRegenerateApikeyV1ResponseMPayload()
} 

