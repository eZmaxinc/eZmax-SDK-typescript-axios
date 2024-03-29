/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseAllOf } from './ezsignbulksendtransmission-get-ezsignsignatures-automatic-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './ezsignbulksendtransmission-get-ezsignsignatures-automatic-v1-response-mpayload';

/**
 * @type EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 * Response for GET /1/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}/getEzsignsignaturesAutomatic
 * @export
 */
export type EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response = CommonResponse & EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 */
export class DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response {
    mPayload:EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload = new DataObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response
 */
export class ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1Response {
   mPayload = new ValidationObjectEzsignbulksendtransmissionGetEzsignsignaturesAutomaticV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


