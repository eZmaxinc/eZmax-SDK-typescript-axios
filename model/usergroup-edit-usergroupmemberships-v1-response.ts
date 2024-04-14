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
import { UsergroupEditUsergroupmembershipsV1ResponseMPayload } from './usergroup-edit-usergroupmemberships-v1-response-mpayload';

/**
 * @type UsergroupEditUsergroupmembershipsV1Response
 * Response for PUT /1/object/usergroup/{pkiUsergroupID}/editUsergroupmemberships
 * @export
 */
/*export type UsergroupEditUsergroupmembershipsV1Response = CommonResponse;*/
export interface UsergroupEditUsergroupmembershipsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UsergroupEditUsergroupmembershipsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupEditUsergroupmembershipsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupEditUsergroupmembershipsV1ResponseMPayload}
     * @memberof UsergroupEditUsergroupmembershipsV1Response
     */
    mPayload:UsergroupEditUsergroupmembershipsV1ResponseMPayload 
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
import { DataObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupEditUsergroupmembershipsV1Response
 */
export class DataObjectUsergroupEditUsergroupmembershipsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupEditUsergroupmembershipsV1ResponseMPayload = new DataObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload()
}

/**
 * @export 
 * A UsergroupEditUsergroupmembershipsV1Response Validation Object
 * @class ValidationObjectUsergroupEditUsergroupmembershipsV1Response
 */
export class ValidationObjectUsergroupEditUsergroupmembershipsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupEditUsergroupmembershipsV1ResponseMPayload()
} 


