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
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { UserEditColleaguesV2ResponseMPayload } from './user-edit-colleagues-v2-response-mpayload';

/**
 * @type UserEditColleaguesV2Response
 * Response for PUT /2/object/user/{pkiUserID}/editColleagues
 * @export
 */
/*export type UserEditColleaguesV2Response = CommonResponse;*/
export interface UserEditColleaguesV2Response {
    /**
     * 
     * @type {UserEditColleaguesV2ResponseMPayload}
     * @memberof UserEditColleaguesV2Response
     */
    mPayload:UserEditColleaguesV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectUserEditColleaguesV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectUserEditColleaguesV2ResponseMPayload } from './'

/**
 * @export 
 * A UserEditColleaguesV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserEditColleaguesV2Response
 */
export class DataObjectUserEditColleaguesV2Response {
    mPayload:UserEditColleaguesV2ResponseMPayload = new DataObjectUserEditColleaguesV2ResponseMPayload()
}

/**
 * @export 
 * A UserEditColleaguesV2Response Validation Object
 * @class ValidationObjectUserEditColleaguesV2Response
 */
export class ValidationObjectUserEditColleaguesV2Response {
   mPayload = new ValidationObjectUserEditColleaguesV2ResponseMPayload()
} 


