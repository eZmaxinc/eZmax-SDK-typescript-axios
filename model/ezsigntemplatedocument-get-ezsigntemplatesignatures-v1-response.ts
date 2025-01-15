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
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload } from './ezsigntemplatedocument-get-ezsigntemplatesignatures-v1-response-mpayload';

/**
 * @type EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
 * Response for GET /1/object/ezsigntemplatedocument/{pkiEzsigntemplatedocument}/getEzsigntemplatesignatures
 * @export
 */
/*export type EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response = CommonResponse;*/
export interface EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload}
     * @memberof EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
     */
    mPayload:EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload 
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
import { DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
 */
export class DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload = new DataObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response Validation Object
 * @class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response
 */
export class ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatedocumentGetEzsigntemplatesignaturesV1ResponseMPayload()
} 


