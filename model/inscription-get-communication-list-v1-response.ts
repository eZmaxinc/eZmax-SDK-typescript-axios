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
import { CommonResponseGetList } from './common-response-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayloadGetList } from './common-response-obj-debug-payload-get-list';
// May contain unused imports in some cases
// @ts-ignore
import { InscriptionGetCommunicationListV1ResponseMPayload } from './inscription-get-communication-list-v1-response-mpayload';

/**
 * @type InscriptionGetCommunicationListV1Response
 * Response for GET /1/object/inscription/{pkiInscriptionID}/getCommunicationList
 * @export
 */
/** export type InscriptionGetCommunicationListV1Response = CommonResponseGetList; */
export interface InscriptionGetCommunicationListV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayloadGetList}
     * @memberof InscriptionGetCommunicationListV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayloadGetList 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof InscriptionGetCommunicationListV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {InscriptionGetCommunicationListV1ResponseMPayload}
     * @memberof InscriptionGetCommunicationListV1Response
     */
    mPayload:InscriptionGetCommunicationListV1ResponseMPayload 
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
import { DataObjectInscriptionGetCommunicationListV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayloadGetList } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectInscriptionGetCommunicationListV1ResponseMPayload } from './'

/**
 * @export 
 * A InscriptionGetCommunicationListV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptionGetCommunicationListV1Response
 */
export class DataObjectInscriptionGetCommunicationListV1Response {
    objDebugPayload:CommonResponseObjDebugPayloadGetList = new DataObjectCommonResponseObjDebugPayloadGetList()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:InscriptionGetCommunicationListV1ResponseMPayload = new DataObjectInscriptionGetCommunicationListV1ResponseMPayload()
}

/**
 * @export 
 * A InscriptionGetCommunicationListV1Response Validation Object
 * @class ValidationObjectInscriptionGetCommunicationListV1Response
 */
export class ValidationObjectInscriptionGetCommunicationListV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayloadGetList()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectInscriptionGetCommunicationListV1ResponseMPayload()
} 

