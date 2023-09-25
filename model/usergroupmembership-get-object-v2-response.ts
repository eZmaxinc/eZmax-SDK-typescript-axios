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
import { UsergroupmembershipGetObjectV2ResponseMPayload } from './usergroupmembership-get-object-v2-response-mpayload';

/**
 * @type UsergroupmembershipGetObjectV2Response
 * Response for GET /2/object/usergroupmembership/{pkiUsergroupmembershipID}
 * @export
 */
/** export type UsergroupmembershipGetObjectV2Response = CommonResponse; */
export interface UsergroupmembershipGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof UsergroupmembershipGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof UsergroupmembershipGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {UsergroupmembershipGetObjectV2ResponseMPayload}
     * @memberof UsergroupmembershipGetObjectV2Response
     */
    mPayload:UsergroupmembershipGetObjectV2ResponseMPayload 
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
import { DataObjectUsergroupmembershipGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupmembershipGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupmembershipGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupmembershipGetObjectV2Response
 */
export class DataObjectUsergroupmembershipGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupmembershipGetObjectV2ResponseMPayload = new DataObjectUsergroupmembershipGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A UsergroupmembershipGetObjectV2Response Validation Object
 * @class ValidationObjectUsergroupmembershipGetObjectV2Response
 */
export class ValidationObjectUsergroupmembershipGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupmembershipGetObjectV2ResponseMPayload()
} 


