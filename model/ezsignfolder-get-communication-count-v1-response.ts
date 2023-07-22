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
import { EzsignfolderGetCommunicationCountV1ResponseAllOf } from './ezsignfolder-get-communication-count-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderGetCommunicationCountV1ResponseMPayload } from './ezsignfolder-get-communication-count-v1-response-mpayload';

/**
 * @type EzsignfolderGetCommunicationCountV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationCount
 * @export
 */
export type EzsignfolderGetCommunicationCountV1Response = CommonResponse & EzsignfolderGetCommunicationCountV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfolderGetCommunicationCountV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationCountV1Response
 */
export class DataObjectEzsignfolderGetCommunicationCountV1Response {
    mPayload:EzsignfolderGetCommunicationCountV1ResponseMPayload = new DataObjectEzsignfolderGetCommunicationCountV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfolderGetCommunicationCountV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationCountV1Response
 */
export class ValidationObjectEzsignfolderGetCommunicationCountV1Response {
   mPayload = new ValidationObjectEzsignfolderGetCommunicationCountV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


