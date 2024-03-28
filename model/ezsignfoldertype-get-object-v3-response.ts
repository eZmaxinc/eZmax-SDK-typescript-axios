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
import { EzsignfoldertypeGetObjectV3ResponseMPayload } from './ezsignfoldertype-get-object-v3-response-mpayload';

/**
 * @type EzsignfoldertypeGetObjectV3Response
 * Response for GET /3/object/ezsignfoldertype/{pkiEzsignfoldertypeID}
 * @export
 */
/** export type EzsignfoldertypeGetObjectV3Response = CommonResponse; */
export interface EzsignfoldertypeGetObjectV3Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldertypeGetObjectV3Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldertypeGetObjectV3Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfoldertypeGetObjectV3ResponseMPayload}
     * @memberof EzsignfoldertypeGetObjectV3Response
     */
    mPayload:EzsignfoldertypeGetObjectV3ResponseMPayload 
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
import { DataObjectEzsignfoldertypeGetObjectV3ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldertypeGetObjectV3ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldertypeGetObjectV3Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeGetObjectV3Response
 */
export class DataObjectEzsignfoldertypeGetObjectV3Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfoldertypeGetObjectV3ResponseMPayload = new DataObjectEzsignfoldertypeGetObjectV3ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldertypeGetObjectV3Response Validation Object
 * @class ValidationObjectEzsignfoldertypeGetObjectV3Response
 */
export class ValidationObjectEzsignfoldertypeGetObjectV3Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfoldertypeGetObjectV3ResponseMPayload()
} 


