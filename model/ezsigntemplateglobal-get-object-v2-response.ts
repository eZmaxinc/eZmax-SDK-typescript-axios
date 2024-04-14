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
import { EzsigntemplateglobalGetObjectV2ResponseMPayload } from './ezsigntemplateglobal-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplateglobalGetObjectV2Response
 * Response for GET /2/object/ezsigntemplateglobal/{pkiEzsigntemplateglobalID}
 * @export
 */
/*export type EzsigntemplateglobalGetObjectV2Response = CommonResponse;*/
export interface EzsigntemplateglobalGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplateglobalGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplateglobalGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplateglobalGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplateglobalGetObjectV2Response
     */
    mPayload:EzsigntemplateglobalGetObjectV2ResponseMPayload 
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
import { DataObjectEzsigntemplateglobalGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplateglobalGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplateglobalGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobalGetObjectV2Response
 */
export class DataObjectEzsigntemplateglobalGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplateglobalGetObjectV2ResponseMPayload = new DataObjectEzsigntemplateglobalGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplateglobalGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplateglobalGetObjectV2Response
 */
export class ValidationObjectEzsigntemplateglobalGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplateglobalGetObjectV2ResponseMPayload()
} 


