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
import { EzsigntemplatesignatureGetObjectV2ResponseMPayload } from './ezsigntemplatesignature-get-object-v2-response-mpayload';

/**
 * @type EzsigntemplatesignatureGetObjectV2Response
 * Response for GET /2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 */
/*export type EzsigntemplatesignatureGetObjectV2Response = CommonResponse;*/
export interface EzsigntemplatesignatureGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatesignatureGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatesignatureGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatesignatureGetObjectV2ResponseMPayload}
     * @memberof EzsigntemplatesignatureGetObjectV2Response
     */
    mPayload:EzsigntemplatesignatureGetObjectV2ResponseMPayload 
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
import { DataObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureGetObjectV2Response
 */
export class DataObjectEzsigntemplatesignatureGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatesignatureGetObjectV2ResponseMPayload = new DataObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV2Response Validation Object
 * @class ValidationObjectEzsigntemplatesignatureGetObjectV2Response
 */
export class ValidationObjectEzsigntemplatesignatureGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload()
} 


