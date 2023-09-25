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
import { EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignsignature-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * @type EzsignsignatureGetEzsignsignaturesAutomaticV1Response
 * Response for GET /1/object/ezsignsignature/getEzsignsignaturesAutomatic
 * @export
 */
/** export type EzsignsignatureGetEzsignsignaturesAutomaticV1Response = CommonResponse; */
export interface EzsignsignatureGetEzsignsignaturesAutomaticV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignatureGetEzsignsignaturesAutomaticV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignatureGetEzsignsignaturesAutomaticV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignsignatureGetEzsignsignaturesAutomaticV1Response
     */
    mPayload:EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload 
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
import { DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignatureGetEzsignsignaturesAutomaticV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1Response
 */
export class DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignatureGetEzsignsignaturesAutomaticV1Response Validation Object
 * @class ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1Response
 */
export class ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignatureGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


