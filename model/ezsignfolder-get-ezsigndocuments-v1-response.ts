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
import { EzsignfolderGetEzsigndocumentsV1ResponseAllOf } from './ezsignfolder-get-ezsigndocuments-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetEzsigndocumentsV1ResponseMPayload } from './ezsignfolder-get-ezsigndocuments-v1-response-mpayload';

/**
 * @type EzsignfolderGetEzsigndocumentsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolder}/getEzsigndocuments
 * @export
 */
export type EzsignfolderGetEzsigndocumentsV1Response = CommonResponse & EzsignfolderGetEzsigndocumentsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfolderGetEzsigndocumentsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetEzsigndocumentsV1Response
 */
export class DataObjectEzsignfolderGetEzsigndocumentsV1Response {
    mPayload:EzsignfolderGetEzsigndocumentsV1ResponseMPayload = new DataObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfolderGetEzsigndocumentsV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetEzsigndocumentsV1Response
 */
export class ValidationObjectEzsignfolderGetEzsigndocumentsV1Response {
   mPayload = new ValidationObjectEzsignfolderGetEzsigndocumentsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


