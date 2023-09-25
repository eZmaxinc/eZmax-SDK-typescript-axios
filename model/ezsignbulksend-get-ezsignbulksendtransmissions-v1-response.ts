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
import { EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload } from './ezsignbulksend-get-ezsignbulksendtransmissions-v1-response-mpayload';

/**
 * @type EzsignbulksendGetEzsignbulksendtransmissionsV1Response
 * Response for GET /1/object/ezsignbulksend/{pkiEzsignbulksend}/getEzsignbulksendtransmissions
 * @export
 */
/** export type EzsignbulksendGetEzsignbulksendtransmissionsV1Response = CommonResponse; */
export interface EzsignbulksendGetEzsignbulksendtransmissionsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignbulksendGetEzsignbulksendtransmissionsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignbulksendGetEzsignbulksendtransmissionsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload}
     * @memberof EzsignbulksendGetEzsignbulksendtransmissionsV1Response
     */
    mPayload:EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload 
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
import { DataObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignbulksendGetEzsignbulksendtransmissionsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response
 */
export class DataObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload = new DataObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignbulksendGetEzsignbulksendtransmissionsV1Response Validation Object
 * @class ValidationObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response
 */
export class ValidationObjectEzsignbulksendGetEzsignbulksendtransmissionsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignbulksendGetEzsignbulksendtransmissionsV1ResponseMPayload()
} 


