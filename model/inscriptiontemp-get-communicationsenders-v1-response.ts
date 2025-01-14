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
import { InscriptiontempGetCommunicationsendersV1ResponseMPayload } from './inscriptiontemp-get-communicationsenders-v1-response-mpayload';

/**
 * @type InscriptiontempGetCommunicationsendersV1Response
 * Response for GET /1/object/inscriptiontemp/{pkiInscriptiontempID}/getCommunicationrecipients
 * @export
 */
/*export type InscriptiontempGetCommunicationsendersV1Response = CommonResponse;*/
export interface InscriptiontempGetCommunicationsendersV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof InscriptiontempGetCommunicationsendersV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof InscriptiontempGetCommunicationsendersV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {InscriptiontempGetCommunicationsendersV1ResponseMPayload}
     * @memberof InscriptiontempGetCommunicationsendersV1Response
     */
    mPayload:InscriptiontempGetCommunicationsendersV1ResponseMPayload 
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
import { DataObjectInscriptiontempGetCommunicationsendersV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectInscriptiontempGetCommunicationsendersV1ResponseMPayload } from './'

/**
 * @export 
 * A InscriptiontempGetCommunicationsendersV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInscriptiontempGetCommunicationsendersV1Response
 */
export class DataObjectInscriptiontempGetCommunicationsendersV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:InscriptiontempGetCommunicationsendersV1ResponseMPayload = new DataObjectInscriptiontempGetCommunicationsendersV1ResponseMPayload()
}

/**
 * @export 
 * A InscriptiontempGetCommunicationsendersV1Response Validation Object
 * @class ValidationObjectInscriptiontempGetCommunicationsendersV1Response
 */
export class ValidationObjectInscriptiontempGetCommunicationsendersV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectInscriptiontempGetCommunicationsendersV1ResponseMPayload()
} 


