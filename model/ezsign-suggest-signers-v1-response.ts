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
import { EzsignSuggestSignersV1ResponseMPayload } from './ezsign-suggest-signers-v1-response-mpayload';

/**
 * @type EzsignSuggestSignersV1Response
 * Response for GET /1/module/ezsign/suggestSigners
 * @export
 */
/*export type EzsignSuggestSignersV1Response = CommonResponse;*/
export interface EzsignSuggestSignersV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignSuggestSignersV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignSuggestSignersV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignSuggestSignersV1ResponseMPayload}
     * @memberof EzsignSuggestSignersV1Response
     */
    mPayload:EzsignSuggestSignersV1ResponseMPayload 
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
import { DataObjectEzsignSuggestSignersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignSuggestSignersV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignSuggestSignersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignSuggestSignersV1Response
 */
export class DataObjectEzsignSuggestSignersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignSuggestSignersV1ResponseMPayload = new DataObjectEzsignSuggestSignersV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignSuggestSignersV1Response Validation Object
 * @class ValidationObjectEzsignSuggestSignersV1Response
 */
export class ValidationObjectEzsignSuggestSignersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignSuggestSignersV1ResponseMPayload()
} 


