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
import { EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload } from './ezsigntemplatepublic-get-ezsigntemplatepublic-details-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
 * Response for POST /1/object/ezsigntemplatepublic/getEzsigntemplatepublicDetails
 * @export
 */
/*export type EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response = CommonResponse;*/
export interface EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload}
     * @memberof EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
     */
    mPayload:EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
 */
export class DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload = new DataObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response
 */
export class ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepublicGetEzsigntemplatepublicDetailsV1ResponseMPayload()
} 


