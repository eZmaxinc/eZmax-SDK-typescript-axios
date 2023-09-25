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
import { EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './ezsigntemplatepackagesignermembership-delete-object-v1-response-mpayload';

/**
 * @type EzsigntemplatepackagesignermembershipDeleteObjectV1Response
 * Response for DELETE /1/object/ezsigntemplatepackagesignermembership/{pkiEzsigntemplatepackagesignermembershipID}
 * @export
 */
/** export type EzsigntemplatepackagesignermembershipDeleteObjectV1Response = CommonResponse; */
export interface EzsigntemplatepackagesignermembershipDeleteObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload}
     * @memberof EzsigntemplatepackagesignermembershipDeleteObjectV1Response
     */
    mPayload:EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload 
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
import { DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1Response
 */
export class DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload = new DataObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsigntemplatepackagesignermembershipDeleteObjectV1Response Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1Response
 */
export class ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsigntemplatepackagesignermembershipDeleteObjectV1ResponseMPayload()
} 


