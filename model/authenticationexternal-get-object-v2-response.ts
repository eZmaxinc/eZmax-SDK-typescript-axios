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
import { AuthenticationexternalGetObjectV2ResponseMPayload } from './authenticationexternal-get-object-v2-response-mpayload';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';

/**
 * @type AuthenticationexternalGetObjectV2Response
 * Response for GET /2/object/authenticationexternal/{pkiAuthenticationexternalID}
 * @export
 */
/*export type AuthenticationexternalGetObjectV2Response = CommonResponse;*/
export interface AuthenticationexternalGetObjectV2Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof AuthenticationexternalGetObjectV2Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof AuthenticationexternalGetObjectV2Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {AuthenticationexternalGetObjectV2ResponseMPayload}
     * @memberof AuthenticationexternalGetObjectV2Response
     */
    mPayload:AuthenticationexternalGetObjectV2ResponseMPayload 
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
import { DataObjectAuthenticationexternalGetObjectV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectAuthenticationexternalGetObjectV2ResponseMPayload } from './'

/**
 * @export 
 * A AuthenticationexternalGetObjectV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAuthenticationexternalGetObjectV2Response
 */
export class DataObjectAuthenticationexternalGetObjectV2Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:AuthenticationexternalGetObjectV2ResponseMPayload = new DataObjectAuthenticationexternalGetObjectV2ResponseMPayload()
}

/**
 * @export 
 * A AuthenticationexternalGetObjectV2Response Validation Object
 * @class ValidationObjectAuthenticationexternalGetObjectV2Response
 */
export class ValidationObjectAuthenticationexternalGetObjectV2Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectAuthenticationexternalGetObjectV2ResponseMPayload()
} 


