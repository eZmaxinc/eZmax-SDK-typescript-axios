/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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
import { EzsigndocumentGetEzsignsignaturesV1ResponseAllOf } from './ezsigndocument-get-ezsignsignatures-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigndocumentGetEzsignsignaturesV1ResponseMPayload } from './ezsigndocument-get-ezsignsignatures-v1-response-mpayload';

/**
 * @type EzsigndocumentGetEzsignsignaturesV1Response
 * Response for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getEzsignsignatures
 * @export
 */
export type EzsigndocumentGetEzsignsignaturesV1Response = CommonResponse & EzsigndocumentGetEzsignsignaturesV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsigndocumentGetEzsignsignaturesV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetEzsignsignaturesV1Response
 */
export class DataObjectEzsigndocumentGetEzsignsignaturesV1Response {
   mPayload:EzsigndocumentGetEzsignsignaturesV1ResponseMPayload = new DataObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload()
   objDebugPayload?:CommonResponseObjDebugPayload = undefined
   objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigndocumentGetEzsignsignaturesV1Response Validation Object
 * @class ValidationObjectEzsigndocumentGetEzsignsignaturesV1Response
 */
export class ValidationObjectEzsigndocumentGetEzsignsignaturesV1Response {
   mPayload = new ValidationObjectEzsigndocumentGetEzsignsignaturesV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


