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

/**
 * @type EzsignfoldertypeEditObjectV2Response
 * Response for PUT /2/object/ezsignfoldertype/{pkiEzsignfoldertypeID}
 * @export
 */
/*export type EzsignfoldertypeEditObjectV2Response = CommonResponse;*/
export interface EzsignfoldertypeEditObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldertypeEditObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldertypeEditObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
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
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A EzsignfoldertypeEditObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeEditObjectV2Response
 */
export class DataObjectEzsignfoldertypeEditObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsignfoldertypeEditObjectV2Response Validation Object
 * @class ValidationObjectEzsignfoldertypeEditObjectV2Response
 */
export class ValidationObjectEzsignfoldertypeEditObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


