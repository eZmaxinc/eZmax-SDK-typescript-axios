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
import { EzsignfolderGetCommunicationsendersV1ResponseMPayload } from './ezsignfolder-get-communicationsenders-v1-response-mpayload';

/**
 * @type EzsignfolderGetCommunicationsendersV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationrecipients
 * @export
 */
/*export type EzsignfolderGetCommunicationsendersV1Response = CommonResponse;*/
export interface EzsignfolderGetCommunicationsendersV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetCommunicationsendersV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetCommunicationsendersV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderGetCommunicationsendersV1ResponseMPayload}
     * @memberof EzsignfolderGetCommunicationsendersV1Response
     */
    mPayload:EzsignfolderGetCommunicationsendersV1ResponseMPayload 
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
import { DataObjectEzsignfolderGetCommunicationsendersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetCommunicationsendersV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetCommunicationsendersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationsendersV1Response
 */
export class DataObjectEzsignfolderGetCommunicationsendersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderGetCommunicationsendersV1ResponseMPayload = new DataObjectEzsignfolderGetCommunicationsendersV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetCommunicationsendersV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationsendersV1Response
 */
export class ValidationObjectEzsignfolderGetCommunicationsendersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderGetCommunicationsendersV1ResponseMPayload()
} 


