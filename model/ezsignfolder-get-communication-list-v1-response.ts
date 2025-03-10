/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfolderGetCommunicationListV1ResponseMPayload } from './ezsignfolder-get-communication-list-v1-response-mpayload';

/**
 * @type EzsignfolderGetCommunicationListV1Response
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationList
 * @export
 */
/*export type EzsignfolderGetCommunicationListV1Response = CommonResponseGetList;*/
export interface EzsignfolderGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof EzsignfolderGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfolderGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfolderGetCommunicationListV1ResponseMPayload}
     * @memberof EzsignfolderGetCommunicationListV1Response
     */
    mPayload:EzsignfolderGetCommunicationListV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectEzsignfolderGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationListV1Response
 */
export class DataObjectEzsignfolderGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfolderGetCommunicationListV1ResponseMPayload = new DataObjectEzsignfolderGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1Response Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationListV1Response
 */
export class ValidationObjectEzsignfolderGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayload()
} 


