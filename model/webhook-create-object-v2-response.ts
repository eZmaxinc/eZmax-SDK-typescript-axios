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
import { WebhookCreateObjectV2ResponseMPayload } from './webhook-create-object-v2-response-mpayload';

/**
 * @type WebhookCreateObjectV2Response
 * Response for POST /2/object/webhook
 * @export
 */
/** export type WebhookCreateObjectV2Response = CommonResponse; */
export interface WebhookCreateObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof WebhookCreateObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof WebhookCreateObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {WebhookCreateObjectV2ResponseMPayload}
     * @memberof WebhookCreateObjectV2Response
     */
    mPayload:WebhookCreateObjectV2ResponseMPayload 
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
import { DataObjectWebhookCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectWebhookCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A WebhookCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectWebhookCreateObjectV2Response
 */
export class DataObjectWebhookCreateObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:WebhookCreateObjectV2ResponseMPayload = new DataObjectWebhookCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A WebhookCreateObjectV2Response Validation Object
 * @class ValidationObjectWebhookCreateObjectV2Response
 */
export class ValidationObjectWebhookCreateObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectWebhookCreateObjectV2ResponseMPayload()
} 


