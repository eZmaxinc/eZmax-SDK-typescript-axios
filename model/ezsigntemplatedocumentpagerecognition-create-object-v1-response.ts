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
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload } from './ezsigntemplatedocumentpagerecognition-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentpagerecognitionCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatedocumentpagerecognition
 * @export
 */
/*export type EzsigntemplatedocumentpagerecognitionCreateObjectV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentpagerecognitionCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentpagerecognitionCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentpagerecognitionCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentpagerecognitionCreateObjectV1Response
     */
    mPayload:EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Response
 */
export class DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentpagerecognitionCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatedocumentpagerecognitionCreateObjectV1ResponseMPayload()
} 


