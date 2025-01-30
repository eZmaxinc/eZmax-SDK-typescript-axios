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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsignfoldertypeGetObjectV2ResponseMPayload } from './ezsignfoldertype-get-object-v2-response-mpayload';

/**
 * @type EzsignfoldertypeGetObjectV2Response
 * Response for GET /2/object/ezsignfoldertype/{pkiEzsignfoldertypeID}
 * @export
 */
/*export type EzsignfoldertypeGetObjectV2Response = CommonResponse;*/
export interface EzsignfoldertypeGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignfoldertypeGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignfoldertypeGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignfoldertypeGetObjectV2ResponseMPayload}
     * @memberof EzsignfoldertypeGetObjectV2Response
     */
    mPayload:EzsignfoldertypeGetObjectV2ResponseMPayload 
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
import { DataObjectEzsignfoldertypeGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignfoldertypeGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsignfoldertypeGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfoldertypeGetObjectV2Response
 */
export class DataObjectEzsignfoldertypeGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignfoldertypeGetObjectV2ResponseMPayload = new DataObjectEzsignfoldertypeGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsignfoldertypeGetObjectV2Response Validation Object
 * @class ValidationObjectEzsignfoldertypeGetObjectV2Response
 */
export class ValidationObjectEzsignfoldertypeGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignfoldertypeGetObjectV2ResponseMPayload()
} 


