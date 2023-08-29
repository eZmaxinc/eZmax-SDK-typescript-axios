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
import { UsergroupdelegationGetObjectV2ResponseMPayload } from './usergroupdelegation-get-object-v2-response-mpayload';

/**
 * @type UsergroupdelegationGetObjectV2Response
 * Response for GET /2/object/usergroupdelegation/{pkiUsergroupdelegationID}
 * @export
 */
export type UsergroupdelegationGetObjectV2Response = CommonResponse;


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { DataObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { DataObjectUsergroupdelegationGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectUsergroupdelegationGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A UsergroupdelegationGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUsergroupdelegationGetObjectV2Response
 */
export class DataObjectUsergroupdelegationGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:UsergroupdelegationGetObjectV2ResponseMPayload = new DataObjectUsergroupdelegationGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A UsergroupdelegationGetObjectV2Response Validation Object
 * @class ValidationObjectUsergroupdelegationGetObjectV2Response
 */
export class ValidationObjectUsergroupdelegationGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectUsergroupdelegationGetObjectV2ResponseMPayload()
} 


