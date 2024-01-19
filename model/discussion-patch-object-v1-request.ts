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
import { DiscussionRequestPatch } from './discussion-request-patch';

/**
 * Request for PATCH /1/object/discussion/{pkiDiscussionID}
 * @export
 * @interface DiscussionPatchObjectV1Request
 */
export interface DiscussionPatchObjectV1Request {
    /**
     * 
     * @type {DiscussionRequestPatch}
     * @memberof DiscussionPatchObjectV1Request
     */
    'objDiscussion': DiscussionRequestPatch;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDiscussionRequestPatch } from './'
// @ts-ignore
import { ValidationObjectDiscussionRequestPatch } from './'

/**
 * @export 
 * A DiscussionPatchObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionPatchObjectV1Request
 */
export class DataObjectDiscussionPatchObjectV1Request {
   objDiscussion:DiscussionRequestPatch = new DataObjectDiscussionRequestPatch()
}

/**
 * @export 
 * A DiscussionPatchObjectV1Request Validation Object
 * @class ValidationObjectDiscussionPatchObjectV1Request
 */
export class ValidationObjectDiscussionPatchObjectV1Request {
   objDiscussion = new ValidationObjectDiscussionRequestPatch()
} 


