/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
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
import { UsergroupGetUsergroupmembershipsV1ResponseAllOf } from './usergroup-get-usergroupmemberships-v1-response-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { UsergroupGetUsergroupmembershipsV1ResponseMPayload } from './usergroup-get-usergroupmemberships-v1-response-mpayload';

/**
 * @type UsergroupGetUsergroupmembershipsV1Response
 * Response for GET /1/object/usergroup/{pkiUsergroupID}/getUsergroupmemberships
 * @export
 */
export type UsergroupGetUsergroupmembershipsV1Response = CommonResponse & UsergroupGetUsergroupmembershipsV1ResponseAllOf;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'

/**
 * @export 
 * A UsergroupGetUsergroupmembershipsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupGetUsergroupmembershipsV1Response
 */
export class DataObjectUsergroupGetUsergroupmembershipsV1Response {
    mPayload:UsergroupGetUsergroupmembershipsV1ResponseMPayload = new DataObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload()
    objDebugPayload?:CommonResponseObjDebugPayload = undefined
    objDebug?:CommonResponseObjDebug = undefined
}

/**
 * @export 
 * A UsergroupGetUsergroupmembershipsV1Response Validation Object
 * @class ValidationObjectUsergroupGetUsergroupmembershipsV1Response
 */
export class ValidationObjectUsergroupGetUsergroupmembershipsV1Response {
   mPayload = new ValidationObjectUsergroupGetUsergroupmembershipsV1ResponseMPayload()
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
} 


