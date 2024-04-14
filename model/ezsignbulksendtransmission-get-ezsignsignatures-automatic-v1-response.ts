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
import { EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignbulksendtransmission-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * @type EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 * Response for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getEzsignsignaturesAutomatic
 * @export
 */
/*export type EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response = CommonResponse;*/
export interface EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload}
     * @memberof EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
     */
    mPayload:EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload 
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
import { DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 */
export class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 */
export class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload()
} 


