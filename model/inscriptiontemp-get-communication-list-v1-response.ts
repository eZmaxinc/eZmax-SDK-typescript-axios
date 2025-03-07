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
import type { InscriptiontempGetCommunicationListV1ResponseMPayload } from './inscriptiontemp-get-communication-list-v1-response-mpayload';

/**
 * @type InscriptiontempGetCommunicationListV1Response
 * Response for GET /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationList
 * @export
 */
/*export type InscriptiontempGetCommunicationListV1Response = CommonResponseGetList;*/
export interface InscriptiontempGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof InscriptiontempGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof InscriptiontempGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {InscriptiontempGetCommunicationListV1ResponseMPayload}
     * @memberof InscriptiontempGetCommunicationListV1Response
     */
    mPayload:InscriptiontempGetCommunicationListV1ResponseMPayload 
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
import { DataObjectInscriptiontempGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectInscriptiontempGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A InscriptiontempGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptiontempGetCommunicationListV1Response
 */
export class DataObjectInscriptiontempGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:InscriptiontempGetCommunicationListV1ResponseMPayload = new DataObjectInscriptiontempGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A InscriptiontempGetCommunicationListV1Response Validation Object
 * @class ValidationObjectInscriptiontempGetCommunicationListV1Response
 */
export class ValidationObjectInscriptiontempGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectInscriptiontempGetCommunicationListV1ResponseMPayload()
} 


