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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type EzsigntemplatepackagemembershipDeleteObjectV1Response
 * Response for DELETE /1/object/ezsigntemplatepackagemembership/{pkiEzsigntemplatepackagemembershipID}
 * @export
 */
/*export type EzsigntemplatepackagemembershipDeleteObjectV1Response = CommonResponse;*/
export interface EzsigntemplatepackagemembershipDeleteObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepackagemembershipDeleteObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepackagemembershipDeleteObjectV1Response
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
 * A EzsigntemplatepackagemembershipDeleteObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagemembershipDeleteObjectV1Response
 */
export class DataObjectEzsigntemplatepackagemembershipDeleteObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A EzsigntemplatepackagemembershipDeleteObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagemembershipDeleteObjectV1Response
 */
export class ValidationObjectEzsigntemplatepackagemembershipDeleteObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


