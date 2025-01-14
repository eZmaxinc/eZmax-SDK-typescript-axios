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
import { EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload } from './ezsigntemplatepublic-create-ezsignfolder-v1-response-mpayload';

/**
 * @type EzsigntemplatepublicCreateEzsignfolderV1Response
 * Response for POST /1/object/ezsigntemplatepublic/createEzsignfolder
 * @export
 */
/*export type EzsigntemplatepublicCreateEzsignfolderV1Response = CommonResponse;*/
export interface EzsigntemplatepublicCreateEzsignfolderV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepublicCreateEzsignfolderV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepublicCreateEzsignfolderV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload}
     * @memberof EzsigntemplatepublicCreateEzsignfolderV1Response
     */
    mPayload:EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepublicCreateEzsignfolderV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicCreateEzsignfolderV1Response
 */
export class DataObjectEzsigntemplatepublicCreateEzsignfolderV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload = new DataObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepublicCreateEzsignfolderV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1Response
 */
export class ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepublicCreateEzsignfolderV1ResponseMPayload()
} 


