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
import { EzsignsignergroupmembershipCreateObjectV1ResponseMPayload } from './ezsignsignergroupmembership-create-object-v1-response-mpayload';

/**
 * @type EzsignsignergroupmembershipCreateObjectV1Response
 * Response for POST /1/object/ezsignsignergroupmembership
 * @export
 */
/*export type EzsignsignergroupmembershipCreateObjectV1Response = CommonResponse;*/
export interface EzsignsignergroupmembershipCreateObjectV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignergroupmembershipCreateObjectV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignergroupmembershipCreateObjectV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignergroupmembershipCreateObjectV1ResponseMPayload}
     * @memberof EzsignsignergroupmembershipCreateObjectV1Response
     */
    mPayload:EzsignsignergroupmembershipCreateObjectV1ResponseMPayload 
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
import { DataObjectEzsignsignergroupmembershipCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignergroupmembershipCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignergroupmembershipCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupmembershipCreateObjectV1Response
 */
export class DataObjectEzsignsignergroupmembershipCreateObjectV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignergroupmembershipCreateObjectV1ResponseMPayload = new DataObjectEzsignsignergroupmembershipCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignergroupmembershipCreateObjectV1Response Validation Object
 * @class ValidationObjectEzsignsignergroupmembershipCreateObjectV1Response
 */
export class ValidationObjectEzsignsignergroupmembershipCreateObjectV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignergroupmembershipCreateObjectV1ResponseMPayload()
} 


