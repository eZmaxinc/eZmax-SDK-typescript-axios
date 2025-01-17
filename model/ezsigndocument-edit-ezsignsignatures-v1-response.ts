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
import type { EzsigndocumentEditEzsignsignaturesV1ResponseMPayload } from './ezsigndocument-edit-ezsignsignatures-v1-response-mpayload';

/**
 * @type EzsigndocumentEditEzsignsignaturesV1Response
 * Response for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}/editEzsignsignatures
 * @export
 */
/*export type EzsigndocumentEditEzsignsignaturesV1Response = CommonResponse;*/
export interface EzsigndocumentEditEzsignsignaturesV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigndocumentEditEzsignsignaturesV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigndocumentEditEzsignsignaturesV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigndocumentEditEzsignsignaturesV1ResponseMPayload}
     * @memberof EzsigndocumentEditEzsignsignaturesV1Response
     */
    mPayload:EzsigndocumentEditEzsignsignaturesV1ResponseMPayload 
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
import { DataObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigndocumentEditEzsignsignaturesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentEditEzsignsignaturesV1Response
 */
export class DataObjectEzsigndocumentEditEzsignsignaturesV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigndocumentEditEzsignsignaturesV1ResponseMPayload = new DataObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigndocumentEditEzsignsignaturesV1Response Validation Object
 * @class ValidationObjectEzsigndocumentEditEzsignsignaturesV1Response
 */
export class ValidationObjectEzsigndocumentEditEzsignsignaturesV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigndocumentEditEzsignsignaturesV1ResponseMPayload()
} 


