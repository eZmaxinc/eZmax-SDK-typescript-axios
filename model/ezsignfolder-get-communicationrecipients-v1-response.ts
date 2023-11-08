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
import { EzsignfolderGetCommunicationrecipientsV1ResponseMPayload } from './ezsignfolder-get-communicationrecipients-v1-response-mpayload';

/**
 * @type EzsignfolderGetCommunicationrecipientsV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationrecipients
 * @export
 */
/** export type EzsignfolderGetCommunicationrecipientsV1Response = CommonResponse; */
export interface EzsignfolderGetCommunicationrecipientsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfolderGetCommunicationrecipientsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetCommunicationrecipientsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderGetCommunicationrecipientsV1ResponseMPayload}
     * @memberof EzsignfolderGetCommunicationrecipientsV1Response
     */
    mPayload:EzsignfolderGetCommunicationrecipientsV1ResponseMPayload 
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
import { DataObjectEzsignfolderGetCommunicationrecipientsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetCommunicationrecipientsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetCommunicationrecipientsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationrecipientsV1Response
 */
export class DataObjectEzsignfolderGetCommunicationrecipientsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderGetCommunicationrecipientsV1ResponseMPayload = new DataObjectEzsignfolderGetCommunicationrecipientsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetCommunicationrecipientsV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationrecipientsV1Response
 */
export class ValidationObjectEzsignfolderGetCommunicationrecipientsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderGetCommunicationrecipientsV1ResponseMPayload()
} 


