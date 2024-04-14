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
import { ApikeyGetSubnetsV1ResponseMPayload } from './apikey-get-subnets-v1-response-mpayload';
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
 * @type ApikeyGetSubnetsV1Response
 * Response for GET /1/object/apikey/{pkiApikeyID}/getSubnets
 * @export
 */
/*export type ApikeyGetSubnetsV1Response = CommonResponse;*/
export interface ApikeyGetSubnetsV1Response {
    /**
     * 
     * @type {CommonResponseObjDebugPayload}
     * @memberof ApikeyGetSubnetsV1Response
     */
    objDebugPayload:CommonResponseObjDebugPayload 
    /**
     * 
     * @type {CommonResponseObjDebug}
     * @memberof ApikeyGetSubnetsV1Response
     */
    objDebug?:CommonResponseObjDebug 
    /**
     * 
     * @type {ApikeyGetSubnetsV1ResponseMPayload}
     * @memberof ApikeyGetSubnetsV1Response
     */
    mPayload:ApikeyGetSubnetsV1ResponseMPayload 
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
import { DataObjectApikeyGetSubnetsV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebugPayload } from './'
// @ts-ignore
import { ValidationObjectCommonResponseObjDebug } from './'
// @ts-ignore
import { ValidationObjectApikeyGetSubnetsV1ResponseMPayload } from './'

/**
 * @export 
 * A ApikeyGetSubnetsV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyGetSubnetsV1Response
 */
export class DataObjectApikeyGetSubnetsV1Response {
    objDebugPayload:CommonResponseObjDebugPayload = new DataObjectCommonResponseObjDebugPayload()
    objDebug?:CommonResponseObjDebug = undefined
    mPayload:ApikeyGetSubnetsV1ResponseMPayload = new DataObjectApikeyGetSubnetsV1ResponseMPayload()
}

/**
 * @export 
 * A ApikeyGetSubnetsV1Response Validation Object
 * @class ValidationObjectApikeyGetSubnetsV1Response
 */
export class ValidationObjectApikeyGetSubnetsV1Response {
   objDebugPayload = new ValidationObjectCommonResponseObjDebugPayload()
   objDebug = new ValidationObjectCommonResponseObjDebug()
   mPayload = new ValidationObjectApikeyGetSubnetsV1ResponseMPayload()
} 


