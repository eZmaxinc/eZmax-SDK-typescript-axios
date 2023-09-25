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
import { EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplatedocumentpages-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
 * Response for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocumentID}/getEzsigntemplatedocumentpages
 * @export
 */
/** export type EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response = CommonResponse; */
export interface EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
     */
    mPayload:EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload 
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
import { DataObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload = new DataObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatedocumentGetEzsigntemplatedocumentpagesV1ResponseMPayload()
} 


