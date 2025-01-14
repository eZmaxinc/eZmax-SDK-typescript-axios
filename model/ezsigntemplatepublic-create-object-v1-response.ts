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
import { EzsigntemplatepublicCreateObjectV1ResponseMPayload } from './ezsigntemplatepublic-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatepublic
 * @export
 */
/*export type EzsigntemplatepublicCreateObjectV1Response = CommonResponse;*/
export interface EzsigntemplatepublicCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepublicCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepublicCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepublicCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepublicCreateObjectV1Response
     */
    mPayload:EzsigntemplatepublicCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepublicCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicCreateObjectV1Response
 */
export class DataObjectEzsigntemplatepublicCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepublicCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatepublicCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplatepublicCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepublicCreateObjectV1ResponseMPayload()
} 


