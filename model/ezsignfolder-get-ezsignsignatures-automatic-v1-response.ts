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
import { EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignfolder-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * @type EzsignfolderGetEzsignsignaturesAutomaticV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getEzsignsignaturesAutomatic
 * @export
 */
/*export type EzsignfolderGetEzsignsignaturesAutomaticV1Response = CommonResponse;*/
export interface EzsignfolderGetEzsignsignaturesAutomaticV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetEzsignsignaturesAutomaticV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetEzsignsignaturesAutomaticV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignfolderGetEzsignsignaturesAutomaticV1Response
     */
    mPayload:EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload 
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
import { DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetEzsignsignaturesAutomaticV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1Response
 */
export class DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetEzsignsignaturesAutomaticV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1Response
 */
export class ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


