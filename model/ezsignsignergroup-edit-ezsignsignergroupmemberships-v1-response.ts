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
import { EzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload } from './ezsignsignergroup-edit-ezsignsignergroupmemberships-v1-response-mpayload';

/**
 * @type EzsignsignergroupEditEzsignsignergroupmembershipsV1Response
 * Response for PUT /1/object/ezsignsignergroup/{pkiEzsignsignergroupID}/editEzsignsignergroupmemberships
 * @export
 */
/** export type EzsignsignergroupEditEzsignsignergroupmembershipsV1Response = CommonResponse; */
export interface EzsignsignergroupEditEzsignsignergroupmembershipsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof EzsignsignergroupEditEzsignsignergroupmembershipsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof EzsignsignergroupEditEzsignsignergroupmembershipsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {EzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload}
     * @memberof EzsignsignergroupEditEzsignsignergroupmembershipsV1Response
     */
    mPayload:EzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload 
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
import { DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload } from './'

/**
 * @export 
 * A EzsignsignergroupEditEzsignsignergroupmembershipsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Response
 */
export class DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:EzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload = new DataObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload()
}

/**
 * @export 
 * A EzsignsignergroupEditEzsignsignergroupmembershipsV1Response Validation Object
 * @class ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Response
 */
export class ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectEzsignsignergroupEditEzsignsignergroupmembershipsV1ResponseMPayload()
} 

