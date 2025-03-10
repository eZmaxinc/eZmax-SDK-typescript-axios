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
import type { EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload } from './ezsignsignergroup-get-ezsignsignergroupmemberships-v1-response-mpayload';

/**
 * @type EzsignsignergroupGetEzsignsignergroupmembershipsV1Response
 * Response for GET /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/getEzsignsignergroupmemberships
 * @export
 */
/*export type EzsignsignergroupGetEzsignsignergroupmembershipsV1Response = CommonResponse;*/
export interface EzsignsignergroupGetEzsignsignergroupmembershipsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignergroupGetEzsignsignergroupmembershipsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignergroupGetEzsignsignergroupmembershipsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload}
     * @memberof EzsignsignergroupGetEzsignsignergroupmembershipsV1Response
     */
    mPayload:EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload 
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
import { DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignergroupGetEzsignsignergroupmembershipsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1Response
 */
export class DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload = new DataObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignergroupGetEzsignsignergroupmembershipsV1Response Validation Object
 * @class ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1Response
 */
export class ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignergroupGetEzsignsignergroupmembershipsV1ResponseMPayload()
} 


