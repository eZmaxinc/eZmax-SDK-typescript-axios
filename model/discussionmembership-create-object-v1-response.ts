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
import type { DiscussionmembershipCreateObjectV1ResponseMPayload } from './discussionmembership-create-object-v1-response-mpayload';

/**
 * @type DiscussionmembershipCreateObjectV1Response
 * Response for POST /1/object/discussionmembership
 * @export
 */
/*export type DiscussionmembershipCreateObjectV1Response = CommonResponse;*/
export interface DiscussionmembershipCreateObjectV1Response {
    /**
     * 
     * @type {DiscussionmembershipCreateObjectV1ResponseMPayload}
     * @memberof DiscussionmembershipCreateObjectV1Response
     */
    mPayload:DiscussionmembershipCreateObjectV1ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDiscussionmembershipCreateObjectV1ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectDiscussionmembershipCreateObjectV1ResponseMPayload } from './'

/**
 * @export 
 * A DiscussionmembershipCreateObjectV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmembershipCreateObjectV1Response
 */
export class DataObjectDiscussionmembershipCreateObjectV1Response {
    mPayload:DiscussionmembershipCreateObjectV1ResponseMPayload = new DataObjectDiscussionmembershipCreateObjectV1ResponseMPayload()
}

/**
 * @export 
 * A DiscussionmembershipCreateObjectV1Response Validation Object
 * @class ValidationObjectDiscussionmembershipCreateObjectV1Response
 */
export class ValidationObjectDiscussionmembershipCreateObjectV1Response {
   mPayload = new ValidationObjectDiscussionmembershipCreateObjectV1ResponseMPayload()
} 


