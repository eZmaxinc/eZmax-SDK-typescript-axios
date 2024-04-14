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
import { ApikeyCreateObjectV2ResponseMPayload } from './apikey-create-object-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type ApikeyCreateObjectV2Response
 * Response for POST /2/object/apikey
 * @export
 */
/*export type ApikeyCreateObjectV2Response = CommonResponse;*/
export interface ApikeyCreateObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ApikeyCreateObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ApikeyCreateObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ApikeyCreateObjectV2ResponseMPayload}
     * @memberof ApikeyCreateObjectV2Response
     */
    mPayload:ApikeyCreateObjectV2ResponseMPayload 
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
import { DataObjectApikeyCreateObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectApikeyCreateObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A ApikeyCreateObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyCreateObjectV2Response
 */
export class DataObjectApikeyCreateObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ApikeyCreateObjectV2ResponseMPayload = new DataObjectApikeyCreateObjectV2ResponseMPayload()
}

/**
 * @export 
 * A ApikeyCreateObjectV2Response Validation Object
 * @class ValidationObjectApikeyCreateObjectV2Response
 */
export class ValidationObjectApikeyCreateObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectApikeyCreateObjectV2ResponseMPayload()
} 


