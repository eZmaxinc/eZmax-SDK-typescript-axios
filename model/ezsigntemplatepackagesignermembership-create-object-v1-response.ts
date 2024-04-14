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
import { EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './ezsigntemplatepackagesignermembership-create-object-v1-response-mpayload';

/**
 * @type EzsigntemplatepackagesignermembershipCreateObjectV1Response
 * Response for POST /1/object/ezsigntemplatepackagesignermembership
 * @export
 */
/*export type EzsigntemplatepackagesignermembershipCreateObjectV1Response = CommonResponse;*/
export interface EzsigntemplatepackagesignermembershipCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepackagesignermembershipCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepackagesignermembershipCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipCreateObjectV1Response
     */
    mPayload:EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1Response
 */
export class DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload = new DataObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1Response
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackagesignermembershipCreateObjectV1ResponseMPayload()
} 


